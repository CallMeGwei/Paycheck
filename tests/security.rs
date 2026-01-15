//! Security tests - API key scopes, input validation, attack prevention, rate limiting, audit logging, JWT claims, tenant isolation, CORS, cascade delete, error leakage

#[path = "security/api_keys.rs"]
mod api_keys;

#[path = "security/input_validation.rs"]
mod input_validation;

#[path = "security/rate_limiting.rs"]
mod rate_limiting;

#[path = "security/audit_logging.rs"]
mod audit_logging;

#[path = "security/jwt_claims.rs"]
mod jwt_claims;

#[path = "security/cross_org_isolation.rs"]
mod cross_org_isolation;

#[path = "security/cors_validation.rs"]
mod cors_validation;

#[path = "security/email_recovery.rs"]
mod email_recovery;

#[path = "security/cascade_delete.rs"]
mod cascade_delete;

#[path = "security/error_leakage.rs"]
mod error_leakage;

#[path = "security/email_hash_rainbow_table.rs"]
mod email_hash_rainbow_table;

#[path = "security/webhook_error_handling.rs"]
mod webhook_error_handling;

#[path = "security/api_key_scope_validation.rs"]
mod api_key_scope_validation;

#[path = "security/license_expiration_validation.rs"]
mod license_expiration_validation;

#[path = "security/csrf_protection.rs"]
mod csrf_protection;

#[path = "security/jwks_rsa_parsing.rs"]
mod jwks_rsa_parsing;
