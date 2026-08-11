# Change Log

All notable changes to this service will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

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
