# Change Log

All notable changes to this service will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

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
