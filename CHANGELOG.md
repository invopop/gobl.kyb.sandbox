# Change Log

All notable changes to this service will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

### Changed

- Every submission restarts the attestation and sends a fresh
  confirmation link — the same-digest renewal no longer countersigns
  and delivers in the background. Nothing reaches the registration
  authority without a confirmation through the emailed link.

- The inbox searches the subject's signatures for one bound to the
  configured authority instead of reading the first signature's
  audience, matching gobl/net's new search semantics — publication-
  first signature ordering and accumulated hop signatures all bind.
  Any signature claiming this verifier's own address must verify
  against its published keys, so a renewal carrying a broken or
  forged copy of an earlier countersignature is rejected.

- The confirm POST delivers the countersignature to the registration
  authority before answering: success renders only once the registry
  has accepted (202), and a failed delivery renders an error page
  with a retry button (503) — never a thank-you for a verification
  that did not complete. The attestation itself is durable from the
  first submit; the checkbox gates only that first attestation, and
  later POSTs on the same link retry the delivery. The submit button
  blocks on first tap.

### Changed

- The inbox sends the confirmation email (and, on renewals, delivers
  the countersignature to the registry) before acknowledging: `202`
  now means the side effect is done, and a failure answers `500` so
  the sender retries instead of the outcome vanishing into a log
  line. The `redeliver` command shares the same delivery path.

### Fixed

- SMTP STARTTLS handshake failed with "either ServerName or
  InsecureSkipVerify must be specified": the TLS config now carries
  the submission host as its server name (TLS 1.2 minimum).

## [v0.1.0]

### Added

- Initial implementation: a dummy KYB verification provider for the
  GOBL Net sandbox. Accepts registered envelopes on the standard
  `/inbox` (request-token authenticated, registration authority
  countersignature required, published email required), sends a
  72-hour confirmation link over SMTP, records the legal attestation
  on `/confirm/<token>`, countersigns the envelope
  (`iss=<verifier>`, `aud=<subject>`, one-year `exp`, no `verifier`
  claim) and delivers it to the registration authority's inbox for
  auto-verification. CouchDB persistence, `init` / `serve` /
  `redeliver` / `version` commands, Docker image and CI workflows.
