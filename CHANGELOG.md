# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).


## [0.1.1] - 2026-01-19

### Fixed

- `X-On-Behalf-Of` header in `--seed` output now correctly shows `user_id` instead of the internal member record ID
- Bruno API collection impersonation examples now use `{{user_id}}` instead of `{{member_id}}`




## [0.1.0] - 2026-01-18

Initial release of Paycheck — an offline-first licensing system for indie developers.

### Added

- **Offline-first licensing**: Ed25519-signed JWTs verified locally without server contact
- **Email-based activation**: Short-lived codes (30-min TTL) instead of permanent license keys
- **Payment providers**: Stripe and LemonSqueezy integration with webhook support
- **Multi-tenant architecture**: Operators → Organizations → Projects → Products → Licenses
- **Public API**: Buy, redeem, validate, refresh, and device management endpoints
- **Admin APIs**: Operator and organization endpoints with role-based access control
- **Security**: Envelope encryption (AES-256-GCM), rate limiting, API key scopes, audit logging
- **Email delivery**: Resend integration, webhook mode, or DIY via admin API
- **SDKs**: Rust and TypeScript (with React hooks) for client integration
- **Dev tools**: `--seed` for test data, `--ephemeral` mode, master key rotation
