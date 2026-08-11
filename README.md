# gobl.kyb.sandbox

A **dummy KYB verification provider** for the [GOBL
Net](https://github.com/invopop/gobl/tree/main/net) sandbox
environment, hosted at `kyb.sandbox.gobl.org`.

This service verifies exactly two things and states so plainly:

1. The registrant controls the email address published in its
   `org.Party` document.
2. A human accepted a declaration of being legally entitled to use
   the identity and credentials being registered.

Nothing more. No company-registry checks, no document review, no
payment. It exists so that sandbox identities can exercise the full
verification choreography of spec §5.3 — registration, provider
countersignature, registry auto-verify — without a commercial KYB
process behind it. Its confidence value is its identity: consumers
who see `verifier: kyb.sandbox.gobl.org` on an endorsement know it
means "sandbox-grade" and nothing else.

## How a verification runs

The service is a standard GOBL Net participant: one inbox, published
keys, a `/who` identity. The only non-protocol surface is the
confirmation page behind the emailed link.

1. **Receive.** The subject delivers its *registered* envelope — its
   own signed `org.Party`, countersigned by the registration
   authority (`lookup.sandbox.gobl.org`) — to `POST
   /.well-known/gobl/inbox` with a request token (spec §5.5). The
   inbox rejects envelopes without a valid, unexpired countersignature
   from the configured authority (403) and parties that publish no
   email address (422); party envelopes are bearer documents, so no
   audience-bound signature is needed (spec §8.3).
2. **Email.** The envelope is stored as a pending verification and a
   confirmation link (`https://kyb.sandbox.gobl.org/confirm/<token>`)
   is emailed to the party's published address — before the `202
   Accepted`, so acknowledgement means the email is out. A send
   failure answers `500` instead and the sender simply retries the
   same delivery later. The link lives 72 hours; re-registering
   issues a fresh one.
3. **Attest.** The link serves a single page with a checkbox: *"I
   confirm that I am legally entitled to use the identity and
   credentials being registered for `<address>`, and I understand
   this is a sandbox environment."*
4. **Countersign and return.** On acceptance the service countersigns
   a copy of the stored envelope — `iss=kyb.sandbox.gobl.org`,
   `aud=<subject>`, `exp` one year out, and **no** `verifier` claim
   (that pointer is the registration authority's to set) — and POSTs
   it to the authority's inbox with its own request token.
5. **Registry auto-verify.** The registry recognises the provider's
   countersignature (this address must be on its `VERIFIERS` list),
   re-countersigns naming `verifier: kyb.sandbox.gobl.org`, and
   re-delivers the result to the subject, whose published envelope
   then carries both countersignatures with independent lifetimes.

Delivery failures are retried by re-opening the confirmation link, or
by the operator with `gobl.kyb.sandbox redeliver <address>`.

## Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /.well-known/gobl/inbox` | request token | receive registered envelopes |
| `GET /.well-known/gobl/who` | request token | the service's own signed party |
| `GET /.well-known/gobl/keys/<kid>` | open | published signing keys |
| `GET /.well-known/jwks.json` | open | keys as an RFC 7517 set |
| `GET/POST /confirm/<token>` | link token | attestation page |
| `GET /healthz` | open | readiness/liveness |

## Configuration

Environment variables (flags on `serve` override them):

| Variable | Default | Purpose |
|---|---|---|
| `CONFIG_DIR` | — | identity directory (`private.jwk`, `party.json`, `keys/`) |
| `COUCHDB_URL` or `COUCHDB_{SCHEME,HOST,PORT,USERNAME,PASSWORD}` | — | CouchDB connection (URL wins) |
| `COUCHDB_DATABASE` | `gobl_kyb_sandbox` | database name |
| `AUTHORITY` | `lookup.sandbox.gobl.org` | registration authority: required countersigner of incoming envelopes and destination of confirmed verifications |
| `PUBLIC_BASE_URL` | `https://<domain>` | base of the emailed `/confirm` links |
| `SMTP_HOST` | — | mail submission host; empty logs emails instead of sending (development) |
| `SMTP_PORT` | `587` | submission port (STARTTLS when offered) |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | — | PLAIN auth; empty for an unauthenticated relay |
| `EMAIL_FROM` | — | e.g. `GOBL Sandbox KYB <kyb@sandbox.gobl.org>`; required with `SMTP_HOST` |
| `HTTP_PORT` / `PORT` | `8080` | listen port |
| `LOG_JSON` | `false` | JSON logs |

Email is plain SMTP so any provider works — hosted senders (Resend,
SES, Postmark, ...) all expose an SMTP submission endpoint.

## Running locally

```sh
docker compose up -d            # CouchDB on :5984
go run ./cmd/gobl.kyb.sandbox init kyb.sandbox.gobl.org --name "GOBL Sandbox KYB"
go run ./cmd/gobl.kyb.sandbox serve \
  --config-dir ~/.config/gobl.kyb.sandbox/kyb.sandbox.gobl.org \
  --couchdb http://admin:pass@localhost:5984
```

Without `SMTP_HOST` the confirmation email — including the link — is
written to the log, which is all a local loop needs.

## Deployment notes

- The registration authority must list this service in its
  `VERIFIERS` configuration. Without it the registry still accepts
  the returned envelope (202) but re-registers without the `verifier`
  claim — the flow silently degrades to registered-only.
- The identity is scaffolded once with `init` and mounted as a
  secret; the sandbox identity is its own keypair, never shared with
  any live service.
- The binary terminates HTTP only; run it behind a TLS-terminating
  proxy.

## Known limitations (accepted for a sandbox)

- **Stale-envelope replay.** A confirmation can land up to 72 hours
  after receipt (or later via `redeliver`); delivering the stored
  envelope then is a valid renewal of *that* digest even if the
  subject re-registered different data in between. Receivers prefer
  the registry's latest endorsement, but the window exists.
- **Signature growth.** Each confirmation appends one
  countersignature to whatever was stored; envelopes are capped at 32
  signatures by `gobl`.
- **No rate limiting.** Rapid re-registration re-emails the party's
  own published address — self-spam only, since both the envelope
  signature and the registry countersignature pin the subject.
