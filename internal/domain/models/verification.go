package models

import (
	"errors"
	"fmt"
	"time"

	"github.com/invopop/couch"
	"github.com/invopop/gobl"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"
)

// Status represents where a verification record is in the
// processing pipeline.
type Status string

// Pipeline states.
const (
	// StatusPending means the registered envelope is persisted and the
	// confirmation email has been (or is being) sent; the subject has
	// not yet completed the attestation.
	StatusPending Status = "pending"
	// StatusConfirmed means the subject completed the attestation;
	// delivery of the countersigned envelope to the registration
	// authority has not yet succeeded.
	StatusConfirmed Status = "confirmed"
	// StatusDelivered means the countersigned envelope was
	// successfully POSTed to the authority's /inbox (202 received).
	StatusDelivered Status = "delivered"
	// StatusFailed means the delivery attempt(s) failed. The record
	// carries the last error; a retry can be triggered with the
	// redeliver command or by repeating the confirmation.
	StatusFailed Status = "failed"
)

// Verification is the per-address verification document persisted in
// CouchDB. The CouchDB document ID is "verification:<address>" so
// re-submissions land as new revisions on the same row — one live
// verification per address. It embeds couch.Model for the _id/_rev +
// created_at/updated_at handling.
type Verification struct {
	couch.Model
	Address net.Address `json:"address"`
	// Email is the party's published email address at receipt — the
	// destination of the confirmation message.
	Email string `json:"email"`
	// Token is the unguessable secret in the emailed confirmation
	// link. Single live token per address: a re-submission replaces it.
	Token string `json:"token"`
	// TokenExpiresAt bounds how long the confirmation link works.
	TokenExpiresAt time.Time `json:"token_expires_at"`
	Status         Status    `json:"status"`
	// Envelope is the registered envelope exactly as received; it is
	// never mutated — every delivery countersigns a fresh copy.
	Envelope       *gobl.Envelope `json:"envelope"`
	EnvelopeUUID   uuid.UUID      `json:"envelope_uuid"`
	EnvelopeDigest string         `json:"envelope_digest"`
	ReceivedAt     time.Time      `json:"received_at"`

	EmailSentAt    *time.Time `json:"email_sent_at,omitempty"`
	LastEmailError string     `json:"last_email_error,omitempty"`

	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`

	DeliveryAttempts  int        `json:"delivery_attempts,omitempty"`
	LastDeliveryAt    *time.Time `json:"last_delivery_at,omitempty"`
	LastDeliveryError string     `json:"last_delivery_error,omitempty"`
}

// VerificationDocID returns the CouchDB document ID for a given address.
func VerificationDocID(addr net.Address) string {
	return "verification:" + string(addr)
}

// NewVerification builds a fresh Verification for a freshly received
// registered envelope. The caller fills in Token / TokenExpiresAt and
// advances Status as the pipeline progresses.
func NewVerification(addr net.Address, email string, env *gobl.Envelope) *Verification {
	v := &Verification{
		Address:    addr,
		Email:      email,
		Status:     StatusPending,
		Envelope:   env,
		ReceivedAt: time.Now().UTC(),
	}
	if env != nil && env.Head != nil {
		v.EnvelopeUUID = env.Head.UUID
		if env.Head.Digest != nil {
			v.EnvelopeDigest = string(env.Head.Digest.Algorithm) + ":" + env.Head.Digest.Value
		}
	}
	v.ID = VerificationDocID(addr) // promoted from couch.Model
	return v
}

// Validate reports whether the record is internally consistent
// before it is written. Used by both the CouchDB store and tests
// to guard against malformed updates.
func (v *Verification) Validate() error {
	if v == nil {
		return errors.New("models: nil verification")
	}
	if v.Address == "" {
		return errors.New("models: verification address is required")
	}
	if v.ID == "" {
		return errors.New("models: verification _id is required")
	}
	if expected := VerificationDocID(v.Address); v.ID != expected {
		return fmt.Errorf("models: verification _id %q does not match address %q", v.ID, expected)
	}
	if v.Status == "" {
		return errors.New("models: verification status is required")
	}
	if v.Email == "" {
		return errors.New("models: verification email is required")
	}
	if v.Token == "" {
		return errors.New("models: verification token is required")
	}
	return nil
}

// TokenExpired reports whether the confirmation link has lapsed.
func (v *Verification) TokenExpired(now time.Time) bool {
	return !v.TokenExpiresAt.IsZero() && !now.Before(v.TokenExpiresAt)
}
