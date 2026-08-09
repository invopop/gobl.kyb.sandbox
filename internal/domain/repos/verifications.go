package repos

import (
	"context"
	"errors"
	"fmt"

	kivik "github.com/go-kivik/kivik/v4"
	"github.com/invopop/couch"
	"github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb.sandbox/internal/domain/models"
)

// Verifications is a verification store backed by a CouchDB database
// through the couch library. There is one database (the couch client's
// prefix); document IDs follow verification:<address>, and the by-token
// lookup uses a `verifications` design document whose view emits the
// confirmation token as a secondary key.
type Verifications struct {
	db *kivik.DB
}

const (
	designName  = "verifications"
	designDocID = "_design/verifications"
	viewByToken = "by_token"
)

// NewVerifications opens (creating if needed) the verifications database
// on the provided couch client, syncs the design document, and returns a
// ready-to-use store.
func NewVerifications(ctx context.Context, client *couch.Client) (*Verifications, error) {
	if client == nil {
		return nil, errors.New("repos: couch client is required")
	}
	db := client.DB("") // single database, named by the client's prefix
	if err := client.Create(ctx, db); err != nil {
		return nil, fmt.Errorf("repos: create database: %w", err)
	}
	if err := client.SyncDesigns(ctx, db, []*couch.Design{verificationsDesign()}); err != nil {
		return nil, fmt.Errorf("repos: sync designs: %w", err)
	}
	return &Verifications{db: db}, nil
}

// Close releases the underlying CouchDB connection.
func (r *Verifications) Close() error {
	if r.db == nil {
		return nil
	}
	return r.db.Close()
}

// verificationsDesign builds the design document backing GetByToken:
// it emits (token → null) for every verification record.
func verificationsDesign() *couch.Design {
	d := couch.NewDesign(designName)
	d.SetView(viewByToken, &couch.View{
		Map: `function(doc) {
			if (doc._id.indexOf("verification:") === 0 && doc.token) {
				emit(doc.token, null);
			}
		}`,
	})
	return d
}

// Put creates or updates the record. On a revision conflict it returns
// ErrConflict so the caller can re-Get and retry.
func (r *Verifications) Put(ctx context.Context, v *models.Verification) error {
	if err := v.Validate(); err != nil {
		return err
	}
	if err := couch.Store(ctx, r.db, v); err != nil {
		if errors.Is(err, couch.ErrAlreadyExists) {
			return ErrConflict
		}
		return fmt.Errorf("repos: store verification: %w", err)
	}
	return nil
}

// Get returns the record for an address or ErrNotFound.
func (r *Verifications) Get(ctx context.Context, address net.Address) (*models.Verification, error) {
	v := new(models.Verification)
	v.ID = models.VerificationDocID(address)
	if err := couch.Fetch(ctx, r.db, v); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repos: fetch verification: %w", err)
	}
	return v, nil
}

// GetByToken returns the record whose confirmation token matches, or
// ErrNotFound. Backs the /confirm/<token> endpoints.
func (r *Verifications) GetByToken(ctx context.Context, token string) (*models.Verification, error) {
	rows := r.db.Query(ctx, designDocID, viewByToken, kivik.Params(map[string]any{
		"key":          token,
		"include_docs": true,
		"limit":        1,
	}))
	defer rows.Close() //nolint:errcheck
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("repos: couchdb view: %w", err)
		}
		return nil, ErrNotFound
	}
	v := new(models.Verification)
	if err := rows.ScanDoc(v); err != nil {
		return nil, fmt.Errorf("repos: couchdb view scan: %w", err)
	}
	return v, nil
}
