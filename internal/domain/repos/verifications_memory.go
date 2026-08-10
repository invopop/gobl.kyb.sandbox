package repos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb.sandbox/internal/domain/models"
)

// MemoryVerifications is a thread-safe in-process verification store
// useful for tests and local dev. It preserves _rev-style optimistic
// concurrency so callers exercising the conflict path behave the same
// as against CouchDB.
type MemoryVerifications struct {
	mu      sync.Mutex
	records map[string]*models.Verification
}

// NewMemoryVerifications returns an empty in-memory verification store.
func NewMemoryVerifications() *MemoryVerifications {
	return &MemoryVerifications{records: make(map[string]*models.Verification)}
}

// Put creates or updates the record.
func (m *MemoryVerifications) Put(_ context.Context, v *models.Verification) error {
	if err := v.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, exists := m.records[v.ID]
	if exists {
		if v.Rev != prev.Rev {
			return ErrConflict
		}
	} else if v.Rev != "" {
		return ErrConflict
	}
	v.UpdateTimestamps() // parity with couch.Store
	v.Rev = newRev()
	clone := *v
	m.records[v.ID] = &clone
	return nil
}

// Get returns the record for an address or ErrNotFound.
func (m *MemoryVerifications) Get(_ context.Context, address net.Address) (*models.Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.records[models.VerificationDocID(address)]
	if !ok {
		return nil, ErrNotFound
	}
	clone := *v
	return &clone, nil
}

// GetByToken returns the record whose confirmation token matches, or
// ErrNotFound.
func (m *MemoryVerifications) GetByToken(_ context.Context, token string) (*models.Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.records {
		if v.Token == token {
			clone := *v
			return &clone, nil
		}
	}
	return nil, ErrNotFound
}

// newRev generates an opaque revision string. Format mirrors
// CouchDB's "1-<hex>" shape just for parity; the leading integer
// is purely informational.
func newRev() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal; surface so tests notice.
		panic("repos: crypto/rand unavailable: " + err.Error())
	}
	return "1-" + hex.EncodeToString(b[:])
}
