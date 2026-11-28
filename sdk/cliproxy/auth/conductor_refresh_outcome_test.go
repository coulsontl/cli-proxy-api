package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	baseauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

func TestUnknownRefreshOutcomeRequiresRecoveryWithoutDiscardingAccess(t *testing.T) {
	for _, cause := range []error{nil, context.Canceled} {
		ctx := context.Background()
		manager := NewManager(nil, nil, nil)
		executor := &unauthorizedRefreshExecutor{id: "codex", refreshErr: &codex.RefreshOutcomeUnknownError{Stage: "transport", Cause: cause}}
		manager.RegisterExecutor(executor)
		expiry := time.Now().Add(time.Hour).Truncate(time.Second)
		auth := &Auth{ID: "unknown-outcome", Provider: "codex", Status: StatusActive, Metadata: map[string]any{
			"access_token": "valid-access", "refresh_token": "unresolved-grant", "expired": expiry.Format(time.RFC3339),
		}}
		if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
			t.Fatal(errRegister)
		}
		manager.refreshAuth(ctx, auth.ID)
		updated, _ := manager.GetByID(auth.ID)
		if updated == nil || !updated.RequiresSignIn || updated.RefreshError == nil || updated.RefreshError.Code != "refresh_outcome_unknown" {
			t.Fatalf("unknown outcome not retained as recovery-required: %+v", updated)
		}
		if updated.Unavailable || updated.Status != StatusActive {
			t.Fatal("valid access token must remain usable")
		}
		manager.refreshAuth(ctx, auth.ID)
		if executor.RefreshCalls() != 1 {
			t.Fatalf("scheduled refresh replayed: calls=%d", executor.RefreshCalls())
		}
	}
}

func TestRejectedRefreshJobDoesNotImmediatelyReschedule(t *testing.T) {
	lead := time.Minute
	setRefreshLeadFactory(t, "codex", func() *time.Duration { return &lead })
	for _, tc := range []struct {
		name           string
		missingAccess  bool
		diagnostic401  bool
		disabled       bool
		statusDisabled bool
	}{
		{name: "expired"},
		{name: "missing", missingAccess: true},
		{name: "diagnostic-401", diagnostic401: true},
		{name: "disabled-during-job", disabled: true},
		{name: "status-disabled-during-job", statusDisabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			manager := NewManager(nil, nil, nil)
			executor := &unauthorizedRefreshExecutor{id: "codex"}
			manager.RegisterExecutor(executor)
			// The JWT expired in 2020 even though the file metadata claims a future expiry.
			auth := &Auth{
				ID: "expired-rejected-refresh", Provider: "codex", Status: StatusActive,
				RequiresSignIn: true, RejectedRefreshToken: "rejected-grant",
				RefreshError: &Error{Code: "refresh_outcome_unknown", Message: "refresh_outcome_unknown: transport", HTTPStatus: http.StatusServiceUnavailable},
				Metadata: map[string]any{
					"access_token":  "eyJhbGciOiJub25lIn0.eyJleHAiOjE1Nzc4MzY4MDB9.sig",
					"refresh_token": "rejected-grant",
					"expired":       time.Now().Add(time.Hour).Format(time.RFC3339),
				},
			}
			if tc.missingAccess {
				delete(auth.Metadata, "access_token")
			}
			if tc.diagnostic401 {
				auth.RefreshError.HTTPStatus = http.StatusUnauthorized
			}
			if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
				t.Fatal(errRegister)
			}
			loop := newAuthAutoRefreshLoop(manager, refreshCheckInterval, 1)
			manager.refreshLoop = loop
			now := time.Now()
			loop.rebuild(now)
			loop.handleDue(ctx, now)

			var job *authRefreshJob
			select {
			case job = <-loop.jobs:
			default:
				t.Fatal("expected expired credential to settle its unavailable state")
			}
			wantStatus := StatusError
			if tc.disabled || tc.statusDisabled {
				pending, _ := manager.GetByID(auth.ID)
				pending.Disabled = tc.disabled
				if tc.statusDisabled {
					pending.Status = StatusDisabled
				}
				if _, errUpdate := manager.Update(ctx, pending); errUpdate != nil {
					t.Fatal(errUpdate)
				}
				wantStatus = StatusDisabled
			}
			if !manager.beginRefreshJob(ctx, job) {
				t.Fatal("expected refresh job to begin")
			}
			if _, errRefresh := manager.refreshAuthForRequestAtEpoch(ctx, job.id, "", job.registrationEpoch); errRefresh == nil {
				t.Fatal("expected the previously rejected refresh error")
			}
			manager.finishRefreshJob(job, time.Time{}, false)
			current, _ := manager.GetByID(auth.ID)
			if !current.Unavailable || current.Status != wantStatus || !current.RequiresSignIn {
				t.Fatalf("expired credential must remain unavailable and require sign-in with status %s", wantStatus)
			}
			if current.LastError == nil || current.LastError.Code != "refresh_outcome_unknown" || current.LastError.HTTPStatus != http.StatusServiceUnavailable {
				t.Fatalf("unknown refresh outcome must not become an access-token rejection: %#v", current.LastError)
			}
			if executor.RefreshCalls() != 0 {
				t.Fatal("already rejected refresh grant was submitted upstream")
			}

			loop.applyDirty(current.UpdatedAt)
			if next, scheduled := loop.peek(); scheduled {
				if wantStatus == StatusDisabled {
					t.Fatal("disabled credential must not remain scheduled")
				}
				if next.Before(current.UpdatedAt.Add(refreshCheckInterval)) {
					t.Fatalf("completed rejected refresh was immediately requeued at %v; want at least one check interval after %v", next, current.UpdatedAt)
				}
			}
			loop.handleDue(ctx, current.UpdatedAt)
			if len(loop.jobs) != 0 {
				t.Fatal("completed rejected refresh was dispatched again without waiting")
			}
			if wantStatus == StatusDisabled {
				return
			}

			// A replacement grant must bypass the old recovery backoff immediately.
			replacement := current.Clone()
			replacement.Metadata["access_token"] = "replacement-access"
			replacement.Metadata["refresh_token"] = "replacement-grant"
			replacement.Metadata["expired"] = current.UpdatedAt.Add(-time.Hour).Format(time.RFC3339)
			updated, errUpdate := manager.Update(ctx, replacement)
			if errUpdate != nil {
				t.Fatal(errUpdate)
			}
			loop.applyDirty(updated.UpdatedAt)
			loop.handleDue(ctx, updated.UpdatedAt)
			if len(loop.jobs) != 1 {
				t.Fatal("replacement grant did not restore refresh scheduling")
			}
		})
	}
}

func TestAutoRefreshDeferralDoesNotClearPendingBackoffToZero(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, nil, nil)
	deferredErr := fmt.Errorf("Codex renewal deferred until interactive macOS wake: %w", codex.ErrSIWCRefreshDeferred)
	executor := &unauthorizedRefreshExecutor{id: "codex", refreshErr: deferredErr}
	manager.RegisterExecutor(executor)

	now := time.Now()
	auth := &Auth{
		ID:       "wake-deferred-job",
		Provider: "codex",
		Status:   StatusActive,
		Metadata: map[string]any{
			"access_token":  "valid-access",
			"refresh_token": "ordinary-refresh",
			"expired":       now.Add(24 * time.Hour).Format(time.RFC3339),
		},
	}
	registered, errRegister := manager.Register(ctx, auth)
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	loop := newAuthAutoRefreshLoop(manager, refreshCheckInterval, 1)
	job := manager.markRefreshPending(loop, registered.ID, registered.RegistrationEpoch, now)
	if job == nil {
		t.Fatal("expected pending refresh job")
	}
	if !manager.beginRefreshJob(ctx, job) {
		t.Fatal("expected refresh job to start")
	}
	_, errRefresh := manager.refreshAuthForRequestAtEpoch(ctx, job.id, "", job.registrationEpoch)
	if errRefresh == nil {
		t.Fatal("expected deferred refresh error")
	}
	manager.finishRefreshJob(job, time.Time{}, false)

	updated, ok := manager.GetByID(registered.ID)
	if !ok || updated == nil {
		t.Fatal("credential missing after deferred refresh")
	}
	if updated.RequiresSignIn || updated.RejectedRefreshToken != "" {
		t.Fatalf("wake deferral marked credential as requiring sign-in: %+v", updated)
	}
	if updated.NextRefreshAfter.IsZero() || !updated.NextRefreshAfter.After(now) {
		t.Fatalf("NextRefreshAfter = %v, want a positive backoff after %v to avoid a tight loop", updated.NextRefreshAfter, now)
	}
}

func TestClaudeAutoRefreshDeferralDoesNotClearPendingBackoffToZero(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, nil, nil)
	deferredErr := fmt.Errorf("Claude renewal deferred until interactive macOS wake: %w", baseauth.ErrRefreshDeferred)
	executor := &unauthorizedRefreshExecutor{id: "claude", refreshErr: deferredErr}
	manager.RegisterExecutor(executor)

	now := time.Now()
	auth := &Auth{
		ID:       "claude-wake-deferred-job",
		Provider: "claude",
		Status:   StatusActive,
		Metadata: map[string]any{
			"access_token":  "valid-access",
			"refresh_token": "claude-sleep-refresh",
			"expired":       now.Add(4 * time.Hour).Format(time.RFC3339),
		},
	}
	registered, errRegister := manager.Register(ctx, auth)
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	loop := newAuthAutoRefreshLoop(manager, refreshCheckInterval, 1)
	job := manager.markRefreshPending(loop, registered.ID, registered.RegistrationEpoch, now)
	if job == nil {
		t.Fatal("expected pending refresh job")
	}
	if !manager.beginRefreshJob(ctx, job) {
		t.Fatal("expected refresh job to start")
	}
	_, errRefresh := manager.refreshAuthForRequestAtEpoch(ctx, job.id, "", job.registrationEpoch)
	if errRefresh == nil {
		t.Fatal("expected deferred refresh error")
	}
	manager.finishRefreshJob(job, time.Time{}, false)

	updated, ok := manager.GetByID(registered.ID)
	if !ok || updated == nil {
		t.Fatal("credential missing after deferred refresh")
	}
	if updated.RequiresSignIn || updated.RejectedRefreshToken != "" || updated.Unavailable || updated.Status != StatusActive {
		t.Fatalf("wake deferral marked credential unhealthy: %+v", updated)
	}
	if updated.LastError != nil || updated.RefreshError != nil {
		t.Fatalf("wake deferral recorded error state: last=%v refresh=%v", updated.LastError, updated.RefreshError)
	}
	if updated.NextRefreshAfter.IsZero() || !updated.NextRefreshAfter.After(now) {
		t.Fatalf("NextRefreshAfter = %v, want a positive backoff after %v to avoid a tight loop", updated.NextRefreshAfter, now)
	}
}

func TestOnDemandRefreshUnknownOutcomeRemainsScheduled_Issue8582(t *testing.T) {
	t.Run("first_expired_refresh_keeps_recovery_scheduled", func(t *testing.T) {
		ctx := context.Background()
		manager := NewManager(nil, nil, nil)
		executor := &unauthorizedRefreshExecutor{
			id:         "codex",
			refreshErr: codex.WrapSIWCRefreshError(&codex.RefreshOutcomeUnknownError{Stage: "transport"}),
		}
		manager.RegisterExecutor(executor)

		now := time.Now()
		auth := &Auth{
			ID:       "codex-siwc-ondemand-first",
			Provider: "codex",
			Status:   StatusActive,
			Metadata: map[string]any{
				"use_siwc":      true,
				"access_token":  "outer-expired",
				"refresh_token": "outer-refresh",
				"expired":       now.Add(-time.Hour).Format(time.RFC3339),
				"siwc": map[string]any{
					"access_token":  "siwc-expired",
					"refresh_token": "siwc-unresolved-grant",
					"client_id":     "oaiapp_test",
					"expired":       now.Add(-time.Hour).Format(time.RFC3339),
				},
			},
		}
		if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
			t.Fatal(errRegister)
		}
		loop := newAuthAutoRefreshLoop(manager, refreshCheckInterval, 1)
		manager.refreshLoop = loop
		loop.rebuild(now)

		manager.refreshAuth(ctx, auth.ID)
		loop.applyDirty(time.Now())

		current, ok := manager.GetByID(auth.ID)
		if !ok || current == nil {
			t.Fatal("credential missing after refresh")
		}
		if current.LastError == nil || current.LastError.Code != "refresh_outcome_unknown" {
			t.Fatalf("LastError = %#v, want refresh_outcome_unknown", current.LastError)
		}
		if current.NextRefreshAfter.IsZero() || !current.NextRefreshAfter.After(now) {
			t.Fatalf("NextRefreshAfter = %v, want future recovery delay after %v", current.NextRefreshAfter, now)
		}
		next, scheduled := loop.peek()
		if !scheduled {
			t.Fatal("expected credential with refresh_outcome_unknown to remain scheduled in auto-refresh heap")
		}
		if next.Before(current.UpdatedAt.Add(refreshCheckInterval)) {
			t.Fatalf("scheduled next=%v, want at least %v", next, current.UpdatedAt.Add(refreshCheckInterval))
		}
	})

	t.Run("preflight_expired_branch_keeps_recovery_scheduled_on_demand", func(t *testing.T) {
		ctx := context.Background()
		manager := NewManager(nil, nil, nil)
		executor := &unauthorizedRefreshExecutor{id: "codex"}
		manager.RegisterExecutor(executor)

		now := time.Now()
		auth := &Auth{
			ID:                       "codex-siwc-ondemand-preflight",
			Provider:                 "codex",
			Status:                   StatusActive,
			RequiresSignIn:           true,
			RejectedSIWCRefreshToken: "siwc-unresolved-grant",
			RefreshError: &Error{
				Code:       "refresh_outcome_unknown",
				Message:    "refresh_outcome_unknown: transport",
				HTTPStatus: http.StatusServiceUnavailable,
			},
			Metadata: map[string]any{
				"use_siwc":      true,
				"access_token":  "outer-expired",
				"refresh_token": "",
				"expired":       now.Add(-time.Hour).Format(time.RFC3339),
				"siwc": map[string]any{
					"access_token":  "siwc-expired",
					"refresh_token": "siwc-unresolved-grant",
					"client_id":     "oaiapp_test",
					"expired":       now.Add(-time.Hour).Format(time.RFC3339),
				},
			},
		}
		if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
			t.Fatal(errRegister)
		}
		loop := newAuthAutoRefreshLoop(manager, refreshCheckInterval, 1)
		manager.refreshLoop = loop
		loop.rebuild(now)

		// On-demand refresh without finishRefreshJob enters the expired pre-flight branch.
		manager.refreshAuth(ctx, auth.ID)
		loop.applyDirty(time.Now())

		if executor.RefreshCalls() != 0 {
			t.Fatalf("expected pre-flight branch to skip upstream refresh, got %d calls", executor.RefreshCalls())
		}
		current, ok := manager.GetByID(auth.ID)
		if !ok || current == nil {
			t.Fatal("credential missing after pre-flight refresh")
		}
		if current.LastError == nil || current.LastError.Code != "refresh_outcome_unknown" {
			t.Fatalf("LastError = %#v, want refresh_outcome_unknown", current.LastError)
		}
		if current.NextRefreshAfter.IsZero() || !current.NextRefreshAfter.After(now) {
			t.Fatalf("NextRefreshAfter = %v, want future recovery delay after %v", current.NextRefreshAfter, now)
		}
		next, scheduled := loop.peek()
		if !scheduled {
			t.Fatal("pre-flight branch unscheduled recoverable refresh_outcome_unknown credential on demand")
		}
		if next.Before(current.UpdatedAt.Add(refreshCheckInterval)) {
			t.Fatalf("scheduled next=%v, want at least %v", next, current.UpdatedAt.Add(refreshCheckInterval))
		}
	})

	t.Run("disabled_preflight_still_unschedules", func(t *testing.T) {
		ctx := context.Background()
		manager := NewManager(nil, nil, nil)
		executor := &unauthorizedRefreshExecutor{id: "codex"}
		manager.RegisterExecutor(executor)

		now := time.Now()
		auth := &Auth{
			ID:                       "codex-siwc-ondemand-disabled",
			Provider:                 "codex",
			Status:                   StatusDisabled,
			Disabled:                 true,
			RequiresSignIn:           true,
			RejectedSIWCRefreshToken: "siwc-unresolved-grant",
			RefreshError: &Error{
				Code:       "refresh_outcome_unknown",
				Message:    "refresh_outcome_unknown: transport",
				HTTPStatus: http.StatusServiceUnavailable,
			},
			Metadata: map[string]any{
				"use_siwc":      true,
				"access_token":  "outer-expired",
				"refresh_token": "",
				"expired":       now.Add(-time.Hour).Format(time.RFC3339),
				"siwc": map[string]any{
					"access_token":  "siwc-expired",
					"refresh_token": "siwc-unresolved-grant",
					"client_id":     "oaiapp_test",
					"expired":       now.Add(-time.Hour).Format(time.RFC3339),
				},
			},
		}
		if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
			t.Fatal(errRegister)
		}
		loop := newAuthAutoRefreshLoop(manager, refreshCheckInterval, 1)
		manager.refreshLoop = loop
		loop.upsert(auth.ID, now)

		manager.refreshAuth(ctx, auth.ID)
		loop.applyDirty(time.Now())

		if _, scheduled := loop.peek(); scheduled {
			t.Fatal("disabled credential must not remain scheduled")
		}
	})

	t.Run("stale_preflight_snapshot_does_not_unschedule_reregistered_auth", func(t *testing.T) {
		ctx := context.Background()
		now := time.Now()
		authID := "codex-siwc-reregistered-preflight"

		var manager *Manager
		var loop *authAutoRefreshLoop
		replacementScheduledAt := now.Add(5 * time.Minute)
		reregistered := false
		store := &reregisteringJournalStore{
			onResolve: func() {
				if reregistered {
					return
				}
				reregistered = true
				// Replace the same auth ID with a fresh healthy credential before the stale pre-flight locks m.mu.
				fresh := &Auth{
					ID:               authID,
					Provider:         "codex",
					Status:           StatusActive,
					NextRefreshAfter: replacementScheduledAt,
					Metadata: map[string]any{
						"use_siwc":      true,
						"access_token":  "fresh-outer",
						"refresh_token": "fresh-outer-grant",
						"expired":       now.Add(time.Hour).Format(time.RFC3339),
						"siwc": map[string]any{
							"access_token":  "fresh-siwc",
							"refresh_token": "fresh-siwc-grant",
							"client_id":     "oaiapp_test",
							"expired":       now.Add(time.Hour).Format(time.RFC3339),
						},
					},
				}
				if _, errReg := manager.Register(ctx, fresh); errReg != nil {
					t.Errorf("re-register replacement auth: %v", errReg)
				}
				loop.upsert(authID, replacementScheduledAt)
			},
		}
		manager = NewManager(store, nil, nil)
		executor := &unauthorizedRefreshExecutor{id: "codex"}
		manager.RegisterExecutor(executor)

		old := &Auth{
			ID:                       authID,
			Provider:                 "codex",
			Status:                   StatusActive,
			RequiresSignIn:           true,
			RejectedSIWCRefreshToken: "old-rejected-grant",
			RefreshError: &Error{
				Code:       "invalid_grant",
				Message:    "refresh_token_reused",
				HTTPStatus: http.StatusUnauthorized,
			},
			Metadata: map[string]any{
				"use_siwc":      true,
				"access_token":  "old-outer-expired",
				"refresh_token": "",
				"expired":       now.Add(-time.Hour).Format(time.RFC3339),
				"siwc": map[string]any{
					"access_token":  "old-siwc-expired",
					"refresh_token": "old-rejected-grant",
					"client_id":     "oaiapp_test",
					"expired":       now.Add(-time.Hour).Format(time.RFC3339),
				},
			},
		}
		if _, errReg := manager.Register(ctx, old); errReg != nil {
			t.Fatal(errReg)
		}
		loop = newAuthAutoRefreshLoop(manager, refreshCheckInterval, 1)
		manager.refreshLoop = loop
		loop.rebuild(now)

		manager.refreshAuth(ctx, authID)

		if !reregistered {
			t.Fatal("expected RefreshJournalFor hook to trigger re-registration")
		}
		loop.applyDirty(now)
		next, scheduled := loop.peek()
		if !scheduled {
			t.Fatal("stale pre-flight snapshot unscheduled the re-registered replacement credential")
		}
		if !next.Equal(replacementScheduledAt) {
			t.Fatalf("replacement scheduled next=%v, want %v", next, replacementScheduledAt)
		}
	})
}

type reregisteringJournalStore struct {
	onResolve func()
}

func (s *reregisteringJournalStore) List(context.Context) ([]*Auth, error)       { return nil, nil }
func (s *reregisteringJournalStore) Save(context.Context, *Auth) (string, error) { return "", nil }
func (s *reregisteringJournalStore) Delete(context.Context, string) error        { return nil }
func (s *reregisteringJournalStore) RefreshJournalFor(*Auth) (codex.RefreshJournal, error) {
	if s.onResolve != nil {
		s.onResolve()
	}
	return nil, nil
}
