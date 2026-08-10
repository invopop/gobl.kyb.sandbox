// Package domain handles all the business logic for the sandbox KYB
// verification service: accepting registered party envelopes from the
// registration authority's subjects, emailing the party's published
// address with a confirmation link, and — once the legal attestation
// is accepted — countersigning the envelope and delivering it back to
// the authority's inbox. Setup wires the repositories and domain
// services together and is the single object handed to the transport
// adapters in interfaces/.
package domain

import (
	"context"
	"log/slog"

	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb.sandbox/internal/domain/delivery"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/mailer"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/models"
)

// VerificationStore is the persistence contract the verifications
// service depends on. repos.Verifications (CouchDB) and
// repos.MemoryVerifications (tests) both satisfy it.
type VerificationStore interface {
	// Put creates or updates the record.
	Put(ctx context.Context, v *models.Verification) error
	// Get returns the record for an address or repos.ErrNotFound.
	Get(ctx context.Context, address goblnet.Address) (*models.Verification, error)
	// GetByToken returns the record whose confirmation token matches,
	// or repos.ErrNotFound.
	GetByToken(ctx context.Context, token string) (*models.Verification, error)
}

// Deps bundles the constructed resources handed to New. The transport
// adapters never see these directly — they talk to the domain
// services exposed by Setup.
type Deps struct {
	// Identity is the verifier's loaded GOBL Net identity.
	Identity *models.Identity
	// Verifications persists verification records.
	Verifications VerificationStore
	// Client verifies incoming envelopes and their authority
	// countersignatures (FetchKey + crypto). It must be constructed
	// with the Authority as its only trusted authority.
	Client *goblnet.Client
	// Sender delivers the countersigned envelope to the authority.
	Sender delivery.Sender
	// Mailer sends the confirmation emails.
	Mailer mailer.Mailer
	// Authority is the registration authority this verifier works
	// for: envelopes must carry its countersignature and confirmed
	// verifications are delivered to its inbox.
	Authority goblnet.Address
	// PublicBaseURL is the canonical https URL of this service (e.g.
	// "https://kyb.sandbox.gobl.org"); used to build the /confirm
	// links in verification emails. When empty, New defaults it to
	// https://<domain>.
	PublicBaseURL string
	// Logger receives domain event logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Setup holds all the domain resources together.
type Setup struct {
	identity      *Identity
	verifications *Verifications
	publicBaseURL string
}

// New prepares the domain setup from its constructed dependencies.
func New(d Deps) *Setup {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	s := new(Setup)
	s.identity = newIdentity(d.Identity, d.Client, d.Logger)
	// Resolve the effective public base URL here (defaulting to
	// https://<domain>) so both the domain and callers observe the same
	// value — the empty case is not visible downstream.
	s.publicBaseURL = d.PublicBaseURL
	if s.publicBaseURL == "" {
		s.publicBaseURL = "https://" + string(s.identity.Address())
	}
	s.verifications = newVerifications(d.Verifications, s.identity, d.Client, d.Sender, d.Mailer, d.Authority, s.publicBaseURL, d.Logger)
	return s
}

// Identity returns the identity domain service.
func (s *Setup) Identity() *Identity { return s.identity }

// Verifications returns the verifications domain service.
func (s *Setup) Verifications() *Verifications { return s.verifications }

// PublicBaseURL returns the effective canonical URL used for
// confirmation links — the configured value, or https://<domain> when
// unset.
func (s *Setup) PublicBaseURL() string { return s.publicBaseURL }
