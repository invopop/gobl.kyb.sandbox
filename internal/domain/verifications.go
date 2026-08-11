package domain

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"

	"github.com/invopop/gobl.kyb.sandbox/internal/domain/delivery"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/mailer"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/models"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/repos"
)

// deliveryTimeout bounds a single outbound POST to the authority's
// inbox, and a single confirmation email submission.
const deliveryTimeout = 30 * time.Second

// confirmTokenTTL bounds how long an emailed confirmation link works.
// Re-registering issues a fresh link.
const confirmTokenTTL = 72 * time.Hour

// Verifications manages the business logic for identity verifications:
// accepting a registered envelope, emailing the party's published
// address, recording the attestation, and delivering the verifier
// countersignature back to the registration authority's inbox.
type Verifications struct {
	store         VerificationStore
	identity      *Identity
	client        *goblnet.Client
	sender        delivery.Sender
	mailer        mailer.Mailer
	authority     goblnet.Address
	publicBaseURL string
	log           *slog.Logger
}

// newVerifications instantiates the verifications domain service.
func newVerifications(store VerificationStore, identity *Identity, client *goblnet.Client, sender delivery.Sender, m mailer.Mailer, authority goblnet.Address, publicBaseURL string, log *slog.Logger) *Verifications {
	if canon, err := goblnet.ParseAddress(string(authority)); err == nil {
		authority = canon
	}
	return &Verifications{
		store:         store,
		identity:      identity,
		client:        client,
		sender:        sender,
		mailer:        m,
		authority:     authority,
		publicBaseURL: publicBaseURL,
		log:           log,
	}
}

// Authority returns the registration authority this verifier works for.
func (d *Verifications) Authority() goblnet.Address { return d.authority }

// Receive processes an incoming verification request: a registered
// envelope containing the subject's org.Party, countersigned by the
// registration authority. It verifies the subject's signature and the
// authority's countersignature, requires a published email address,
// persists the record, and sends the confirmation email before
// returning — a request is only acknowledged once its side effect is
// done, so a failure surfaces to the sender for retry instead of
// vanishing into a log line.
func (d *Verifications) Receive(ctx context.Context, env *gobl.Envelope) (*models.Verification, error) {
	if err := env.Validate(); err != nil {
		d.log.Warn("inbox.rejected", "reason", "validation", "error", err.Error())
		return nil, ErrValidation.WithMessage("envelope failed validation: %s", err.Error())
	}

	// Party envelopes are bearer documents (spec §8.3): no audience
	// binding is required — the request token carries delivery intent,
	// and the authority countersignature check below is what gates
	// eligibility.
	subject, err := d.client.VerifyEnvelope(ctx, env, "")
	if err != nil {
		if errors.Is(err, goblnet.ErrUnavailable) {
			d.log.Warn("inbox.rejected", "reason", "verify_unavailable", "error", err.Error())
			return nil, ErrUnavailable.WithMessage("could not reach the subject's key endpoint; retry later")
		}
		d.log.Warn("inbox.rejected", "reason", "verify_failed", "error", err.Error())
		return nil, ErrUnauthorized.WithMessage("signature verification failed")
	}

	// Any signature claiming this verifier's address must actually be
	// ours: renewals return with our earlier countersignature aboard,
	// and a broken or forged copy means the envelope is not the one we
	// attested to.
	if err := d.verifyOwnSignatures(env); err != nil {
		d.log.Warn("inbox.rejected", "reason", "own_signature_invalid", "caller", string(subject), "error", err.Error())
		return nil, ErrUnauthorized.WithMessage("envelope carries an invalid countersignature claiming this verifier")
	}

	// Only registered envelopes are eligible: the authority's
	// countersignature both proves registration and tells us the
	// registry will accept our countersignature for this exact
	// uuid + digest.
	if _, err := d.client.VerifyAuthority(ctx, env); err != nil {
		if errors.Is(err, goblnet.ErrUnavailable) {
			d.log.Warn("inbox.rejected", "reason", "authority_unavailable", "caller", string(subject), "error", err.Error())
			return nil, ErrUnavailable.WithMessage("could not reach the registration authority's key endpoint; retry later")
		}
		d.log.Warn("inbox.rejected", "reason", "authority_missing", "caller", string(subject), "error", err.Error())
		return nil, ErrForbidden.WithMessage("envelope must carry a valid registration countersignature from %s", d.authority)
	}

	party, ok := env.Extract().(*org.Party)
	if !ok {
		d.log.Warn("inbox.rejected", "reason", "not_a_party", "caller", string(subject))
		return nil, ErrValidation.WithMessage("verification envelope must contain an org.Party document")
	}
	email := partyEmail(party)
	if email == "" {
		d.log.Warn("inbox.rejected", "reason", "no_email", "caller", string(subject))
		return nil, ErrValidation.WithMessage("party must publish an email address to be verified")
	}

	rec, resend, err := d.upsert(ctx, subject, email, env)
	if err != nil {
		d.log.Error("inbox.persist_failed", "caller", string(subject), "error", err.Error())
		return nil, ErrInternal.WithCause(err)
	}
	d.log.Info("inbox.accepted",
		"caller", string(subject),
		"envelope", env.Head.UUID.String(),
		"status", string(rec.Status),
		"email_queued", resend,
	)

	if resend {
		if err := d.sendConfirmation(ctx, rec); err != nil {
			return nil, ErrInternal.WithMessage("could not send the confirmation email; retry later")
		}
	} else {
		// Same digest, already attested: no second attestation needed,
		// deliver the countersignature straight away.
		if err := d.deliver(ctx, rec); err != nil {
			return nil, ErrInternal.WithMessage("could not deliver the verification to the registration authority; retry later")
		}
	}

	return rec, nil
}

// Confirmation resolves a confirmation token to its record for the
// confirm page: ErrNotFound for an unknown token, ErrGone for an
// expired one. Records that have already progressed past pending are
// returned as-is so the page can render the idempotent thank-you.
func (d *Verifications) Confirmation(ctx context.Context, token string) (*models.Verification, error) {
	return d.byToken(ctx, token)
}

// Confirm records the subject's legal attestation and delivers the
// verifier countersignature to the registration authority before
// returning, so a failed delivery surfaces to the page instead of
// only reaching the logs. The call is idempotent: a delivered record
// is returned unchanged, and a confirmed or failed one retries the
// delivery — the attestation itself is durable from the first call.
func (d *Verifications) Confirm(ctx context.Context, token string) (*models.Verification, error) {
	rec, err := d.byToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if rec.Status == models.StatusDelivered {
		return rec, nil
	}
	if rec.ConfirmedAt == nil {
		now := time.Now().UTC()
		rec.ConfirmedAt = &now
		rec.Status = models.StatusConfirmed
		if err := d.store.Put(ctx, rec); err != nil {
			if errors.Is(err, repos.ErrConflict) {
				// A concurrent confirmation won the write; re-read and
				// carry on to delivery — the registry's inbox treats a
				// duplicate of the same digest as an idempotent renewal.
				if rec, err = d.byToken(ctx, token); err != nil {
					return nil, err
				}
			} else {
				d.log.Error("confirm.persist_failed", "address", string(rec.Address), "error", err.Error())
				return nil, ErrInternal.WithCause(err)
			}
		}
		d.log.Info("confirm.accepted",
			"address", string(rec.Address),
			"envelope", rec.EnvelopeUUID.String(),
		)
	}
	if rec.Status == models.StatusDelivered {
		return rec, nil
	}
	if err := d.deliver(ctx, rec); err != nil {
		return nil, ErrUnavailable.WithMessage("your confirmation is saved, but the result could not be delivered to the registration authority — try this link again in a few minutes")
	}
	return rec, nil
}

// Redeliver countersigns and delivers an already-confirmed
// verification synchronously — the recovery path when the async
// delivery after confirmation failed.
func (d *Verifications) Redeliver(ctx context.Context, addr goblnet.Address) (*models.Verification, error) {
	rec, err := d.store.Get(ctx, addr)
	if errors.Is(err, repos.ErrNotFound) {
		return nil, ErrNotFound.WithMessage("no verification for %s", addr)
	}
	if err != nil {
		return nil, ErrInternal.WithCause(err)
	}
	if rec.ConfirmedAt == nil {
		return nil, ErrValidation.WithMessage("verification for %s has not been confirmed", addr)
	}
	if err := d.deliver(ctx, rec); err != nil {
		return nil, ErrInternal.WithCause(fmt.Errorf("deliver countersigned envelope: %w", err))
	}
	return rec, nil
}

// byToken maps a token lookup onto domain errors.
func (d *Verifications) byToken(ctx context.Context, token string) (*models.Verification, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	rec, err := d.store.GetByToken(ctx, token)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		return nil, ErrNotFound
	case err != nil:
		return nil, ErrInternal.WithCause(err)
	}
	if rec.TokenExpired(time.Now().UTC()) {
		return nil, ErrGone.WithMessage("confirmation link has expired; re-register to receive a new one")
	}
	return rec, nil
}

// upsert reads any existing record for the subject (preserving the
// store's _rev token for optimistic concurrency), then writes the new
// state. The second return reports whether a confirmation email is
// needed: a re-submission of the exact envelope digest that was
// already attested skips the email — the attestation binds to the
// digest, so only delivery remains.
func (d *Verifications) upsert(ctx context.Context, subject goblnet.Address, email string, env *gobl.Envelope) (*models.Verification, bool, error) {
	fresh := models.NewVerification(subject, email, env)
	token, err := newToken()
	if err != nil {
		return nil, false, err
	}
	fresh.Token = token
	fresh.TokenExpiresAt = fresh.ReceivedAt.Add(confirmTokenTTL)

	prev, err := d.store.Get(ctx, subject)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		if err := d.store.Put(ctx, fresh); err != nil {
			return nil, false, err
		}
		return fresh, true, nil
	case err != nil:
		return nil, false, err
	}

	if prev.ConfirmedAt != nil && prev.EnvelopeDigest == fresh.EnvelopeDigest {
		// Renewal of an attested digest: keep the confirmation, reset
		// the delivery bookkeeping so the fresh countersignature goes
		// out again.
		prev.Envelope = env
		prev.EnvelopeUUID = fresh.EnvelopeUUID
		prev.ReceivedAt = fresh.ReceivedAt
		prev.Email = email
		prev.Status = models.StatusConfirmed
		prev.DeliveryAttempts = 0
		prev.LastDeliveryError = ""
		prev.LastDeliveryAt = nil
		if err := d.store.Put(ctx, prev); err != nil {
			return nil, false, err
		}
		return prev, false, nil
	}

	// Anything else restarts the attestation: new token, new expiry,
	// cleared confirmation and delivery state.
	fresh.Rev = prev.Rev
	if err := d.store.Put(ctx, fresh); err != nil {
		return nil, false, err
	}
	return fresh, true, nil
}

// sendConfirmation sends the confirmation email and records the
// outcome on the record. A failure leaves the record pending with the
// error noted and is returned to the caller — the subject recovers by
// re-registering, which issues a fresh link.
func (d *Verifications) sendConfirmation(ctx context.Context, rec *models.Verification) error {
	sendCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	msg := confirmationMessage(rec, d.identity.Address(), d.authority, d.publicBaseURL)
	now := time.Now().UTC()
	if err := d.mailer.Send(sendCtx, msg); err != nil {
		rec.LastEmailError = err.Error()
		d.log.Warn("email.send_failed",
			"address", string(rec.Address),
			"to", rec.Email,
			"error", err.Error(),
		)
		if perr := d.store.Put(ctx, rec); perr != nil {
			d.log.Error("email.persist_failed", "address", string(rec.Address), "error", perr.Error())
		}
		return err
	}
	rec.EmailSentAt = &now
	rec.LastEmailError = ""
	d.log.Info("email.sent",
		"address", string(rec.Address),
		"to", rec.Email,
	)
	// The email is out: a bookkeeping failure here must not fail the
	// request and trigger a duplicate send.
	if err := d.store.Put(ctx, rec); err != nil {
		d.log.Error("email.persist_failed",
			"address", string(rec.Address),
			"error", err.Error(),
		)
	}
	return nil
}

// deliver countersigns the stored envelope, POSTs it to the
// authority's inbox, and records the outcome. Failures are not
// retried in-process — recovery is the redeliver command, repeating
// the confirmation, or re-sending the registered envelope.
func (d *Verifications) deliver(ctx context.Context, rec *models.Verification) error {
	env, err := d.countersignedCopy(rec)
	if err != nil {
		rec.Status = models.StatusFailed
		rec.LastDeliveryError = err.Error()
		d.log.Error("deliver.countersign_failed",
			"address", string(rec.Address),
			"error", err.Error(),
		)
		if perr := d.store.Put(ctx, rec); perr != nil {
			d.log.Error("deliver.persist_failed", "address", string(rec.Address), "error", perr.Error())
		}
		return err
	}
	rec.DeliveryAttempts++
	now := time.Now().UTC()
	rec.LastDeliveryAt = &now
	sendCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	if err := d.sender.Send(sendCtx, d.authority, env); err != nil {
		rec.Status = models.StatusFailed
		rec.LastDeliveryError = err.Error()
		d.log.Warn("deliver.failed",
			"address", string(rec.Address),
			"envelope", rec.EnvelopeUUID.String(),
			"attempts", rec.DeliveryAttempts,
			"error", err.Error(),
		)
		if perr := d.store.Put(ctx, rec); perr != nil {
			d.log.Error("deliver.persist_failed", "address", string(rec.Address), "error", perr.Error())
		}
		return err
	}
	rec.Status = models.StatusDelivered
	rec.LastDeliveryError = ""
	d.log.Info("deliver.sent",
		"address", string(rec.Address),
		"envelope", rec.EnvelopeUUID.String(),
	)
	if err := d.store.Put(ctx, rec); err != nil {
		d.log.Error("deliver.persist_failed",
			"address", string(rec.Address),
			"error", err.Error(),
		)
	}
	return nil
}

// countersignedCopy countersigns a fresh copy of the stored envelope.
// The stored envelope is never signed directly: Envelope.Sign clears
// every signature when post-sign validation fails, and each delivery
// should carry a freshly-stamped exp anyway.
func (d *Verifications) countersignedCopy(rec *models.Verification) (*gobl.Envelope, error) {
	if rec.Envelope == nil {
		return nil, errors.New("verification has no stored envelope")
	}
	data, err := json.Marshal(rec.Envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal stored envelope: %w", err)
	}
	env := new(gobl.Envelope)
	if err := json.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("decode stored envelope: %w", err)
	}
	if err := d.identity.CounterSign(env, rec.Address); err != nil {
		return nil, fmt.Errorf("countersign envelope: %w", err)
	}
	return env, nil
}

// verifyOwnSignatures checks every signature claiming this verifier's
// address against its own published keys. Returns an error when one
// claims an unknown key or fails verification; envelopes without any
// such signature (a first submission) pass untouched.
func (d *Verifications) verifyOwnSignatures(env *gobl.Envelope) error {
	for _, sig := range env.Signatures {
		p, err := head.SignedPayload(sig)
		if err != nil {
			continue
		}
		iss, err := goblnet.ParseAddress(p.Iss)
		if err != nil || iss != d.identity.Address() {
			continue
		}
		pub := d.identity.FindKey(sig.KeyID())
		if pub == nil {
			return fmt.Errorf("signature claims this verifier with unknown key %q", sig.KeyID())
		}
		if err := env.Head.Verify(sig, pub); err != nil {
			return fmt.Errorf("signature claiming this verifier does not verify: %w", err)
		}
	}
	return nil
}

// partyEmail returns the party's first published email address, or "".
func partyEmail(party *org.Party) string {
	for _, e := range party.Emails {
		if e != nil && e.Address != "" {
			return e.Address
		}
	}
	return ""
}

// newToken mints an unguessable confirmation-link token.
func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
