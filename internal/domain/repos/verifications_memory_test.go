package repos_test

import (
	"context"
	"testing"
	"time"

	"github.com/invopop/gobl/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.kyb.sandbox/internal/domain/models"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/repos"
)

// newVerification builds a minimal valid record for store tests.
func newVerification(addr net.Address) *models.Verification {
	v := models.NewVerification(addr, "owner@example.com", nil)
	v.Token = "tok-" + string(addr)
	v.TokenExpiresAt = time.Now().Add(time.Hour)
	return v
}

func TestMemoryStorePutGet(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryVerifications()
	addr := net.Address("alice.example")
	v := newVerification(addr)

	err := s.Put(ctx, v)
	require.NoError(t, err)
	assert.NotEmpty(t, v.Rev)

	got, err := s.Get(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, addr, got.Address)
	assert.Equal(t, models.StatusPending, got.Status)
	assert.Equal(t, "owner@example.com", got.Email)
	assert.NotEmpty(t, got.Rev)
}

func TestMemoryStoreGetMissing(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryVerifications()
	_, err := s.Get(ctx, "nobody.example")
	require.ErrorIs(t, err, repos.ErrNotFound)
}

func TestMemoryStoreGetByToken(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryVerifications()
	v := newVerification("alice.example")
	err := s.Put(ctx, v)
	require.NoError(t, err)

	got, err := s.GetByToken(ctx, v.Token)
	require.NoError(t, err)
	assert.Equal(t, net.Address("alice.example"), got.Address)

	_, err = s.GetByToken(ctx, "unknown-token")
	require.ErrorIs(t, err, repos.ErrNotFound)
}

func TestMemoryStoreUpdateRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryVerifications()
	v := newVerification("alice.example")
	err := s.Put(ctx, v)
	require.NoError(t, err)

	// Re-read to pick up the new _rev, advance status, write back.
	got, err := s.Get(ctx, "alice.example")
	require.NoError(t, err)
	got.Status = models.StatusDelivered
	err = s.Put(ctx, got)
	require.NoError(t, err)

	final, err := s.Get(ctx, "alice.example")
	require.NoError(t, err)
	assert.Equal(t, models.StatusDelivered, final.Status)
}

func TestMemoryStorePutWithoutMatchingRevConflicts(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryVerifications()
	v := newVerification("alice.example")
	err := s.Put(ctx, v)
	require.NoError(t, err)

	// Drop the rev and try to write again — should conflict.
	v.Rev = ""
	err = s.Put(ctx, v)
	require.ErrorIs(t, err, repos.ErrConflict)
}

func TestMemoryStorePutNewRecordRejectsStaleRev(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryVerifications()
	v := newVerification("alice.example")
	// Pretend the caller has a rev for a doc that doesn't exist.
	v.Rev = "1-deadbeef"
	err := s.Put(ctx, v)
	require.ErrorIs(t, err, repos.ErrConflict)
}

func TestVerificationValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(v *models.Verification)
		wantErr string
	}{
		{"no address", func(v *models.Verification) { v.Address = "" }, "address is required"},
		{"no status", func(v *models.Verification) { v.Status = "" }, "status is required"},
		{"no email", func(v *models.Verification) { v.Email = "" }, "email is required"},
		{"no token", func(v *models.Verification) { v.Token = "" }, "token is required"},
		{"mismatched id", func(v *models.Verification) { v.ID = "verification:wrong" }, "does not match address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newVerification("alice.example")
			tc.mutate(v)
			err := v.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestNilVerificationValidateErrors(t *testing.T) {
	var v *models.Verification
	err := v.Validate()
	require.Error(t, err)
}

func TestTokenExpired(t *testing.T) {
	v := newVerification("alice.example")
	now := time.Now()
	assert.False(t, v.TokenExpired(now))
	assert.True(t, v.TokenExpired(now.Add(2*time.Hour)))
	v.TokenExpiresAt = time.Time{}
	assert.False(t, v.TokenExpired(now), "zero expiry never lapses")
}
