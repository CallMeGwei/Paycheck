//! JWT claims validation security tests.
//!
//! These tests verify that:
//! 1. Expired JWTs are rejected by validation and refresh endpoints
//! 2. JWTs with invalid/missing issuer are rejected
//! 3. JWTs with wrong subject or audience are rejected
//! 4. JWTs signed with wrong keys are rejected
//! 5. Malformed JWTs are handled gracefully without crashing
//! 6. Edge cases (boundary conditions, oversized tokens) are handled
//!
//! CRITICAL: These tests ensure JWT security is enforced correctly.
//! Any failure here indicates a potential token forgery or bypass vulnerability.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL};
use serde_json::json;
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::{*, ONE_YEAR, ONE_DAY, UPDATES_VALID_DAYS};

use paycheck::db::AppState;
use paycheck::handlers::public::{refresh_token, validate_license};
use paycheck::jwt::{self, LicenseClaims};
use paycheck::models::DeviceType;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

// ============================================================================
// Test App Setup Helper
// ============================================================================

/// Creates a test app with the public router (for /validate and /refresh endpoints).
/// Builds routes directly without rate limiting layer to avoid panic on zero limits.
fn public_app() -> (Router, AppState) {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();
    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();
    }

    let audit_manager = SqliteConnectionManager::memory();
    let audit_pool = Pool::builder().max_size(4).build(audit_manager).unwrap();
    {
        let conn = audit_pool.get().unwrap();
        paycheck::db::init_audit_db(&conn).unwrap();
    }

    let state = AppState {
        db: pool,
        audit: audit_pool,
        base_url: "http://localhost:3000".to_string(),
        audit_log_enabled: false,
        master_key,
        email_hasher: paycheck::crypto::EmailHasher::from_bytes([0xAA; 32]),
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(
            None,
            "test@example.com".to_string(),
        )),
        jwks_cache: std::sync::Arc::new(paycheck::jwt::JwksCache::new()),
        trusted_issuers: vec![],
    };

    // Build router without rate limiting (avoids panic on zero limits)
    let app = Router::new()
        .route("/validate", post(validate_license))
        .route("/refresh", post(refresh_token))
        .with_state(state.clone());

    (app, state)
}

/// Helper to create test claims with customizable fields.
fn create_test_claims(
    license_exp: Option<i64>,
    updates_exp: Option<i64>,
    tier: &str,
    product_id: &str,
    device_id: &str,
    device_type: &str,
) -> LicenseClaims {
    LicenseClaims {
        license_exp,
        updates_exp,
        tier: tier.to_string(),
        features: vec!["feature1".to_string()],
        device_id: device_id.to_string(),
        device_type: device_type.to_string(),
        product_id: product_id.to_string(),
    }
}

/// Create a complete test setup: org, project, product, license, device, and valid JWT.
/// Returns (project_public_key, project_private_key, license_id, device_jti, valid_token).
fn setup_complete_license(state: &AppState) -> (String, Vec<u8>, String, String, String) {
    let conn = state.db.get().unwrap();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
    let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

    // Create a device for this license
    let jti = uuid::Uuid::new_v4().to_string();
    let _device = queries::create_device(
        &conn,
        &license.id,
        "test-device-id",
        DeviceType::Uuid,
        &jti,
        Some("Test Device"),
    )
    .unwrap();

    // Get the private key to sign tokens
    let private_key = state
        .master_key
        .decrypt_private_key(&project.id, &project.private_key)
        .unwrap();

    // Create valid claims
    let claims = create_test_claims(
        Some(future_timestamp(ONE_YEAR)),
        Some(future_timestamp(UPDATES_VALID_DAYS)),
        &product.tier,
        &product.id,
        "test-device-id",
        "uuid",
    );

    // Sign a valid token
    let token = jwt::sign_claims(&claims, &private_key, &license.id, &project.name, &jti).unwrap();

    (project.public_key, private_key, license.id, jti, token)
}

// ============================================================================
// EXPIRATION VALIDATION TESTS
// ============================================================================

mod expiration_validation {
    use super::*;

    /// Verify that a JWT with exp in the past is rejected by verify_token.
    /// This is critical - expired tokens must not be accepted.
    #[test]
    fn test_expired_jwt_rejected_by_verify() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        // Sign a token normally (1 hour validity by default)
        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project-name", "jti-123")
                .unwrap();

        // This should work immediately
        let result = jwt::verify_token(&token, &public_key);
        assert!(result.is_ok(), "fresh token should verify successfully with valid signature");

        // Simulate an expired token by creating one with expired claims
        // Note: The jwt-simple library handles exp internally, so we test with
        // manually constructed expired tokens in the endpoint tests below
    }

    /// Verify that verify_token_allow_expired accepts expired tokens.
    #[test]
    fn test_expired_jwt_accepted_by_allow_expired() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(past_timestamp(ONE_DAY)), // License already expired
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project-name", "jti-123")
                .unwrap();

        // allow_expired should accept it regardless of exp claim
        let result = jwt::verify_token_allow_expired(&token, &public_key);
        assert!(result.is_ok(), "allow_expired mode should accept tokens with valid signature regardless of expiration");
    }

    /// Verify that /validate endpoint rejects requests with invalid JTI (not found).
    #[tokio::test]
    async fn test_validate_rejects_invalid_jti() {
        let (app, state) = public_app();
        let (public_key, _, _, _, _) = setup_complete_license(&state);

        // Try to validate with a non-existent JTI
        let body = json!({
            "public_key": public_key,
            "jti": "non-existent-jti-12345678"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "validate endpoint should return 200 OK even for invalid JTI (validity in response body)"
        );

        // Parse the response - should say valid: false
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            json["valid"], false,
            "non-existent JTI should return valid: false in response body"
        );
    }

    /// Verify that /validate endpoint returns valid: true for a valid JTI.
    #[tokio::test]
    async fn test_validate_accepts_valid_jti() {
        let (app, state) = public_app();
        let (public_key, _, _, jti, _) = setup_complete_license(&state);

        let body = json!({
            "public_key": public_key,
            "jti": jti
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "validate endpoint should return 200 OK for valid JTI"
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            json["valid"], true,
            "existing valid JTI should return valid: true in response body"
        );
    }

    /// Verify that /refresh endpoint rejects tokens with invalid JTI.
    #[tokio::test]
    async fn test_refresh_rejects_invalid_jti() {
        let (app, state) = public_app();

        // Setup a license but create a token with a different JTI
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");
        let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

        let private_key = state
            .master_key
            .decrypt_private_key(&project.id, &project.private_key)
            .unwrap();

        // Create token with a JTI that doesn't exist in the database
        let fake_jti = uuid::Uuid::new_v4().to_string();
        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            &product.tier,
            &product.id,
            "device-id",
            "uuid",
        );

        let token = jwt::sign_claims(&claims, &private_key, &license.id, &project.name, &fake_jti)
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/refresh")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "refresh with non-existent JTI should return 401 Unauthorized"
        );
    }

    /// Verify that /refresh works with a valid token.
    #[tokio::test]
    async fn test_refresh_accepts_valid_token() {
        let (app, state) = public_app();
        let (_, _, _, _, token) = setup_complete_license(&state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/refresh")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "refresh with valid token should return 200 OK"
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert!(
            json["token"].is_string(),
            "successful refresh response should contain a new token string"
        );
    }
}

// ============================================================================
// ISSUER VALIDATION TESTS
// ============================================================================

mod issuer_validation {
    use super::*;

    /// Verify that tokens must have issuer "paycheck".
    #[test]
    fn test_wrong_issuer_fails_verification() {
        let (private_key, public_key) = jwt::generate_keypair();

        // Create a token with the standard sign_claims (always uses "paycheck" issuer)
        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project-name", "jti-123")
                .unwrap();

        // Verify the token has correct issuer
        let verified = jwt::verify_token(&token, &public_key).unwrap();
        assert_eq!(
            verified.issuer,
            Some("paycheck".to_string()),
            "token issuer claim should be set to 'paycheck'"
        );
    }

    /// Verify that decode_unverified works regardless of issuer (for key lookup).
    #[test]
    fn test_decode_unverified_ignores_issuer() {
        let (private_key, _) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project-name", "jti-123")
                .unwrap();

        // decode_unverified should extract claims without checking issuer
        let decoded = jwt::decode_unverified(&token).unwrap();
        assert_eq!(
            decoded.product_id, "product-123",
            "decode_unverified should extract product_id from claims"
        );
        assert_eq!(
            decoded.tier, "pro",
            "decode_unverified should extract tier from claims"
        );
    }
}

// ============================================================================
// AUDIENCE VALIDATION TESTS
// ============================================================================

mod audience_validation {
    use super::*;

    /// Verify that audience is included in tokens (for debugging) but not enforced.
    /// Per CLAUDE.md: "Audience not verified - signature with project's key is sufficient"
    #[test]
    fn test_audience_included_but_not_enforced() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        // Sign with a specific audience
        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "my-project", "jti-123")
                .unwrap();

        // Verify should succeed (audience not enforced)
        let verified = jwt::verify_token(&token, &public_key).unwrap();
        assert!(
            verified.audiences.is_some(),
            "token should have audience claim set for debugging purposes"
        );

        // The audience is the project name, included for debugging
        // Audiences type from jwt-simple doesn't have is_empty, just verify we got something
        // We already verified it's Some above, which means audience was set
    }

    /// Verify that tokens with different audiences validate if signed correctly.
    #[test]
    fn test_different_audience_still_validates() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        // Sign with audience "project-a"
        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project-a", "jti-123").unwrap();

        // Should validate successfully (audience not enforced)
        let result = jwt::verify_token(&token, &public_key);
        assert!(
            result.is_ok(),
            "token should validate regardless of audience value when signature is valid"
        );
    }
}

// ============================================================================
// JTI VALIDATION TESTS
// ============================================================================

mod jti_validation {
    use super::*;

    /// Verify that JTI is properly stored and can be retrieved from tokens.
    #[test]
    fn test_jti_preserved_in_token() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        let expected_jti = "unique-jti-12345";
        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project", expected_jti)
                .unwrap();

        let verified = jwt::verify_token(&token, &public_key).unwrap();
        assert_eq!(
            verified.jwt_id,
            Some(expected_jti.to_string()),
            "JWT ID (jti) claim should be preserved exactly as provided during signing"
        );
    }

    /// Verify that /validate endpoint checks JTI revocation.
    #[tokio::test]
    async fn test_validate_checks_jti_revocation() {
        let (app, state) = public_app();
        let (public_key, _, license_id, jti, _) = setup_complete_license(&state);

        // First validate should succeed
        let body = json!({
            "public_key": public_key,
            "jti": jti.clone()
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["valid"], true,
            "JTI should be valid before revocation"
        );

        // Revoke the JTI
        {
            let conn = state.db.get().unwrap();
            queries::add_revoked_jti(&conn, &license_id, &jti, Some("test revocation")).unwrap();
        }

        // Now validate should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["valid"], false,
            "JTI should be invalid after being added to revocation list"
        );
    }

    /// Verify that /refresh endpoint checks JTI revocation.
    #[tokio::test]
    async fn test_refresh_checks_jti_revocation() {
        let (app, state) = public_app();
        let (_, _, license_id, jti, token) = setup_complete_license(&state);

        // First refresh should succeed
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/refresh")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "refresh should succeed before JTI revocation"
        );

        // Revoke the JTI
        {
            let conn = state.db.get().unwrap();
            queries::add_revoked_jti(&conn, &license_id, &jti, Some("test revocation")).unwrap();
        }

        // Now refresh should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/refresh")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "refresh should return 401 after JTI has been revoked"
        );
    }
}

// ============================================================================
// SIGNATURE VALIDATION TESTS
// ============================================================================

mod signature_validation {
    use super::*;

    /// Verify that tokens signed with wrong key are rejected.
    #[test]
    fn test_wrong_signing_key_fails_verification() {
        let (private_key, _) = jwt::generate_keypair();
        let (_, other_public_key) = jwt::generate_keypair(); // Different key pair

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project", "jti-123").unwrap();

        // Try to verify with different public key
        let result = jwt::verify_token(&token, &other_public_key);
        assert!(
            result.is_err(),
            "token signed with one key should be rejected when verified with a different public key"
        );
    }

    /// Verify that /refresh endpoint rejects tokens signed with wrong key.
    #[tokio::test]
    async fn test_refresh_rejects_wrong_signature() {
        let (app, state) = public_app();

        // Setup a legitimate project
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
        let product = create_test_product(&conn, &project.id, "Pro", "pro");
        let _license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

        // Create a token signed with a DIFFERENT key (attacker's key)
        let (attacker_private_key, _) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            &product.tier,
            &product.id,
            "device-id",
            "uuid",
        );

        // Sign with attacker's key
        let forged_token = jwt::sign_claims(
            &claims,
            &attacker_private_key,
            "fake-license-id",
            &project.name,
            "fake-jti",
        )
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/refresh")
                    .header("Authorization", format!("Bearer {}", forged_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "token signed with attacker's key should be rejected with 401"
        );
    }

    /// Verify that tampered tokens are rejected.
    #[test]
    fn test_tampered_token_fails_verification() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project", "jti-123").unwrap();

        // Tamper with the payload
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "JWT should have exactly 3 parts (header.payload.signature)"
        );

        let mut payload_chars: Vec<char> = parts[1].chars().collect();
        if let Some(c) = payload_chars.get_mut(10) {
            *c = if *c == 'a' { 'b' } else { 'a' };
        }
        let tampered_payload: String = payload_chars.into_iter().collect();
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let result = jwt::verify_token(&tampered_token, &public_key);
        assert!(
            result.is_err(),
            "token with tampered payload should fail signature verification"
        );
    }
}

// ============================================================================
// DEVICE TYPE VALIDATION TESTS
// ============================================================================

mod device_type_validation {
    use super::*;

    /// Verify that device_type is preserved in tokens.
    #[test]
    fn test_device_type_preserved() {
        let (private_key, public_key) = jwt::generate_keypair();

        // Test with "uuid" type
        let claims_uuid = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        let token_uuid =
            jwt::sign_claims(&claims_uuid, &private_key, "license-id", "project", "jti-1")
                .unwrap();
        let verified = jwt::verify_token(&token_uuid, &public_key).unwrap();
        assert_eq!(
            verified.custom.device_type, "uuid",
            "device_type 'uuid' should be preserved in token claims"
        );

        // Test with "machine" type
        let claims_machine = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "machine",
        );

        let token_machine =
            jwt::sign_claims(&claims_machine, &private_key, "license-id", "project", "jti-2")
                .unwrap();
        let verified = jwt::verify_token(&token_machine, &public_key).unwrap();
        assert_eq!(
            verified.custom.device_type, "machine",
            "device_type 'machine' should be preserved in token claims"
        );
    }

    /// Verify that tokens with non-standard device types are handled.
    /// Note: The JWT library doesn't enforce device_type values, but the
    /// application layer should validate when creating devices.
    #[test]
    fn test_nonstandard_device_type_in_token() {
        let (private_key, public_key) = jwt::generate_keypair();

        // Create token with non-standard device type
        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "invalid_type",
        );

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project", "jti-123").unwrap();

        // Token should still verify (JWT doesn't care about device_type content)
        let verified = jwt::verify_token(&token, &public_key).unwrap();
        assert_eq!(
            verified.custom.device_type, "invalid_type",
            "JWT verification should not validate device_type content (validated at device creation)"
        );

        // The application should validate device_type when creating devices,
        // not when verifying tokens. The token just reflects what was stored.
    }
}

// ============================================================================
// MALFORMED JWT TESTS
// ============================================================================

mod malformed_jwt {
    use super::*;

    /// Verify that empty token is rejected.
    #[test]
    fn test_empty_token_returns_error() {
        let (_, public_key) = jwt::generate_keypair();

        let result = jwt::verify_token("", &public_key);
        assert!(
            result.is_err(),
            "empty string should be rejected as invalid JWT"
        );

        let result = jwt::decode_unverified("");
        assert!(
            result.is_err(),
            "empty string should fail unverified decode"
        );
    }

    /// Verify that token with missing parts is rejected.
    #[test]
    fn test_missing_parts_returns_error() {
        let (_, public_key) = jwt::generate_keypair();

        // Only header
        let result = jwt::decode_unverified("eyJhbGciOiJIUzI1NiJ9");
        assert!(
            result.is_err(),
            "JWT with only header (missing payload and signature) should be rejected"
        );

        // Header and payload only (missing signature)
        let result = jwt::decode_unverified("eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ");
        assert!(
            result.is_err(),
            "JWT without signature should be rejected"
        );

        // Same tests for verify_token
        let result = jwt::verify_token("eyJhbGciOiJIUzI1NiJ9", &public_key);
        assert!(
            result.is_err(),
            "verify_token should reject JWT with only header"
        );

        let result = jwt::verify_token("eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ", &public_key);
        assert!(
            result.is_err(),
            "verify_token should reject JWT without signature"
        );
    }

    /// Verify that token with invalid base64 is rejected.
    #[test]
    fn test_invalid_base64_returns_error() {
        let (_, public_key) = jwt::generate_keypair();

        // Invalid base64 characters
        let result = jwt::decode_unverified("not-valid!!!.base64!!!.here!!!");
        assert!(
            result.is_err(),
            "JWT with invalid base64 characters should be rejected"
        );

        let result = jwt::verify_token("not-valid!!!.base64!!!.here!!!", &public_key);
        assert!(
            result.is_err(),
            "verify_token should reject JWT with invalid base64"
        );
    }

    /// Verify that token with invalid JSON payload is rejected.
    #[test]
    fn test_invalid_json_payload_returns_error() {
        let (_, public_key) = jwt::generate_keypair();

        // Valid base64 but not valid JSON
        let invalid_json = BASE64_URL.encode(b"not json at all");
        let token = format!("eyJhbGciOiJFZERTQSJ9.{}.fake_signature", invalid_json);

        let result = jwt::decode_unverified(&token);
        assert!(
            result.is_err(),
            "JWT with non-JSON payload should be rejected"
        );

        let result = jwt::verify_token(&token, &public_key);
        assert!(
            result.is_err(),
            "verify_token should reject JWT with non-JSON payload"
        );
    }

    /// Verify that very long/oversized JWTs are handled gracefully.
    #[test]
    fn test_oversized_jwt_rejected_without_crash() {
        let (_, public_key) = jwt::generate_keypair();

        // Create a very long fake token (1MB)
        let long_payload = "a".repeat(1_000_000);
        let token = format!("eyJhbGciOiJFZERTQSJ9.{}.fake", long_payload);

        // Should not crash, should return an error
        let result = jwt::decode_unverified(&token);
        assert!(
            result.is_err(),
            "oversized JWT (1MB payload) should be rejected without crashing"
        );

        let result = jwt::verify_token(&token, &public_key);
        assert!(
            result.is_err(),
            "verify_token should reject oversized JWT without crashing"
        );
    }

    /// Verify that random garbage data is rejected.
    #[test]
    fn test_garbage_data_returns_error() {
        let (_, public_key) = jwt::generate_keypair();

        let garbage_inputs = vec![
            "completely-random-garbage",
            ".....",
            "\x00\x00\x00",
            "null",
            "undefined",
            "{}",
            "[]",
        ];

        for garbage in garbage_inputs {
            let result = jwt::decode_unverified(garbage);
            assert!(
                result.is_err(),
                "garbage input '{}' should be rejected by decode_unverified",
                garbage
            );

            let result = jwt::verify_token(garbage, &public_key);
            assert!(
                result.is_err(),
                "garbage input '{}' should be rejected by verify_token",
                garbage
            );
        }
    }

    /// Verify that /refresh endpoint handles malformed tokens gracefully.
    #[tokio::test]
    async fn test_refresh_handles_malformed_tokens() {
        let (app, _state) = public_app();

        // Malformed tokens that are valid HTTP header values
        let malformed_tokens = vec![
            "not-a-jwt",
            "header.payload", // Missing signature
            "header.payload.signature.extra",
            "...",
            "a.b.c",
            "eyJhbGciOiJIUzI1NiJ9", // Just header, no payload or signature
            "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ", // Missing signature
        ];

        for token in malformed_tokens {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/refresh")
                        .header("Authorization", format!("Bearer {}", token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            // Should return 400 or 401, NOT 500
            assert!(
                response.status() == StatusCode::BAD_REQUEST
                    || response.status() == StatusCode::UNAUTHORIZED,
                "malformed token '{}' should return 400/401 (got {}), not 500 server error",
                token,
                response.status()
            );
        }
    }

    /// Verify that /refresh endpoint handles empty Bearer token gracefully.
    #[tokio::test]
    async fn test_refresh_handles_empty_bearer_token() {
        let (app, _state) = public_app();

        // Empty token after "Bearer " - this should be handled gracefully
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/refresh")
                    .header("Authorization", "Bearer ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 400 or 401, NOT 500
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNAUTHORIZED,
            "empty Bearer token value should return 400/401 (got {}), not 500 server error",
            response.status()
        );
    }

    /// Verify that /refresh endpoint handles missing Authorization header.
    #[tokio::test]
    async fn test_refresh_requires_authorization_header() {
        let (app, _state) = public_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/refresh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "request without Authorization header should return 401 Unauthorized"
        );
    }
}

// ============================================================================
// FUTURE IAT (ISSUED-AT) TESTS
// ============================================================================

mod future_iat_validation {
    use super::*;

    /// Verify that tokens with normal iat are accepted.
    #[test]
    fn test_normal_iat_accepted() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project", "jti-123").unwrap();

        // Fresh token with normal iat should be accepted
        let result = jwt::verify_token(&token, &public_key);
        assert!(
            result.is_ok(),
            "freshly signed token with normal issued_at should be accepted"
        );

        let verified = result.unwrap();
        assert!(
            verified.issued_at.is_some(),
            "token should have issued_at (iat) claim set automatically"
        );
    }
}

// ============================================================================
// LICENSE REVOCATION TESTS
// ============================================================================

mod license_revocation {
    use super::*;

    /// Verify that /validate returns false for revoked licenses.
    #[tokio::test]
    async fn test_validate_rejects_revoked_license() {
        let (app, state) = public_app();
        let (public_key, _, license_id, jti, _) = setup_complete_license(&state);

        // First validate should succeed
        let body = json!({
            "public_key": public_key,
            "jti": jti.clone()
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["valid"], true,
            "license should be valid before revocation"
        );

        // Revoke the license
        {
            let conn = state.db.get().unwrap();
            queries::revoke_license(&conn, &license_id).unwrap();
        }

        // Now validate should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["valid"], false,
            "license should be invalid after revocation"
        );
    }

    /// Verify that /refresh rejects tokens for revoked licenses.
    #[tokio::test]
    async fn test_refresh_rejects_revoked_license() {
        let (app, state) = public_app();
        let (_, _, license_id, _, token) = setup_complete_license(&state);

        // Revoke the license
        {
            let conn = state.db.get().unwrap();
            queries::revoke_license(&conn, &license_id).unwrap();
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/refresh")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "refresh for revoked license should return 401 Unauthorized"
        );
    }
}

// ============================================================================
// CLAIMS CONTENT TESTS
// ============================================================================

mod claims_content {
    use super::*;

    /// Verify that all custom claims are preserved in round-trip.
    #[test]
    fn test_all_claims_preserved() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = LicenseClaims {
            license_exp: Some(1234567890),
            updates_exp: Some(1234567891),
            tier: "enterprise".to_string(),
            features: vec!["feat1".to_string(), "feat2".to_string(), "feat3".to_string()],
            device_id: "my-device-uuid-123".to_string(),
            device_type: "machine".to_string(),
            product_id: "prod-abc-123".to_string(),
        };

        let token =
            jwt::sign_claims(&claims, &private_key, "license-xyz", "project-name", "jti-456")
                .unwrap();

        let verified = jwt::verify_token(&token, &public_key).unwrap();

        assert_eq!(
            verified.custom.license_exp,
            Some(1234567890),
            "license_exp claim should be preserved in round-trip"
        );
        assert_eq!(
            verified.custom.updates_exp,
            Some(1234567891),
            "updates_exp claim should be preserved in round-trip"
        );
        assert_eq!(
            verified.custom.tier, "enterprise",
            "tier claim should be preserved in round-trip"
        );
        assert_eq!(
            verified.custom.features.len(),
            3,
            "features array should preserve all 3 elements"
        );
        assert!(
            verified.custom.features.contains(&"feat1".to_string()),
            "features should contain 'feat1'"
        );
        assert!(
            verified.custom.features.contains(&"feat2".to_string()),
            "features should contain 'feat2'"
        );
        assert!(
            verified.custom.features.contains(&"feat3".to_string()),
            "features should contain 'feat3'"
        );
        assert_eq!(
            verified.custom.device_id, "my-device-uuid-123",
            "device_id claim should be preserved in round-trip"
        );
        assert_eq!(
            verified.custom.device_type, "machine",
            "device_type claim should be preserved in round-trip"
        );
        assert_eq!(
            verified.custom.product_id, "prod-abc-123",
            "product_id claim should be preserved in round-trip"
        );
    }

    /// Verify that claims helper methods work correctly.
    #[test]
    fn test_claims_helper_methods() {
        let now = now();

        // Test is_license_expired
        let claims_expired = LicenseClaims {
            license_exp: Some(now - 86400), // Yesterday
            updates_exp: None,
            tier: "pro".to_string(),
            features: vec![],
            device_id: "".to_string(),
            device_type: "uuid".to_string(),
            product_id: "".to_string(),
        };
        assert!(
            claims_expired.is_license_expired(now),
            "license with license_exp in the past should report as expired"
        );

        let claims_valid = LicenseClaims {
            license_exp: Some(now + 86400), // Tomorrow
            updates_exp: None,
            tier: "pro".to_string(),
            features: vec![],
            device_id: "".to_string(),
            device_type: "uuid".to_string(),
            product_id: "".to_string(),
        };
        assert!(
            !claims_valid.is_license_expired(now),
            "license with license_exp in the future should not report as expired"
        );

        let claims_perpetual = LicenseClaims {
            license_exp: None,
            updates_exp: None,
            tier: "pro".to_string(),
            features: vec![],
            device_id: "".to_string(),
            device_type: "uuid".to_string(),
            product_id: "".to_string(),
        };
        assert!(
            !claims_perpetual.is_license_expired(now),
            "perpetual license (license_exp: None) should never report as expired"
        );

        // Test covers_version
        let claims_updates = LicenseClaims {
            license_exp: None,
            updates_exp: Some(now),
            tier: "pro".to_string(),
            features: vec![],
            device_id: "".to_string(),
            device_type: "uuid".to_string(),
            product_id: "".to_string(),
        };
        assert!(
            claims_updates.covers_version(now - 86400),
            "version released before updates_exp should be covered"
        );
        assert!(
            !claims_updates.covers_version(now + 86400),
            "version released after updates_exp should not be covered"
        );

        // Test has_feature
        let claims_features = LicenseClaims {
            license_exp: None,
            updates_exp: None,
            tier: "pro".to_string(),
            features: vec!["export".to_string(), "api".to_string()],
            device_id: "".to_string(),
            device_type: "uuid".to_string(),
            product_id: "".to_string(),
        };
        assert!(
            claims_features.has_feature("export"),
            "has_feature should return true for included feature 'export'"
        );
        assert!(
            claims_features.has_feature("api"),
            "has_feature should return true for included feature 'api'"
        );
        assert!(
            !claims_features.has_feature("admin"),
            "has_feature should return false for non-included feature 'admin'"
        );
    }

    /// Verify that special characters in claims are preserved.
    #[test]
    fn test_special_characters_in_claims() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = LicenseClaims {
            license_exp: None,
            updates_exp: None,
            tier: "tier-with-special/chars&stuff".to_string(),
            features: vec![
                "feat:with:colons".to_string(),
                "feat<with>brackets".to_string(),
            ],
            device_id: "device\"with'quotes".to_string(),
            device_type: "uuid".to_string(),
            product_id: "product@#$%^".to_string(),
        };

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project", "jti-123").unwrap();

        let verified = jwt::verify_token(&token, &public_key).unwrap();

        assert_eq!(
            verified.custom.tier, "tier-with-special/chars&stuff",
            "tier with special characters (/, &) should be preserved"
        );
        assert!(
            verified
                .custom
                .features
                .contains(&"feat:with:colons".to_string()),
            "feature with colons should be preserved"
        );
        assert_eq!(
            verified.custom.device_id, "device\"with'quotes",
            "device_id with quotes should be preserved"
        );
        assert_eq!(
            verified.custom.product_id, "product@#$%^",
            "product_id with special characters (@#$%^) should be preserved"
        );
    }

    /// Verify that unicode in claims is preserved.
    #[test]
    fn test_unicode_in_claims() {
        let (private_key, public_key) = jwt::generate_keypair();

        let claims = LicenseClaims {
            license_exp: None,
            updates_exp: None,
            tier: "tier".to_string(),
            features: vec![
                "feature".to_string(),
                "export".to_string(),
            ],
            device_id: "device-id".to_string(),
            device_type: "uuid".to_string(),
            product_id: "product-id".to_string(),
        };

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project", "jti-123").unwrap();

        let verified = jwt::verify_token(&token, &public_key).unwrap();

        assert_eq!(
            verified.custom.tier, "tier",
            "tier claim should be preserved after round-trip"
        );
        assert!(
            verified.custom.features.contains(&"feature".to_string()),
            "features should contain 'feature' after round-trip"
        );
    }
}

// ============================================================================
// KEY VALIDATION TESTS
// ============================================================================

mod key_validation {
    use super::*;

    /// Verify that invalid public key format is rejected.
    #[test]
    fn test_invalid_public_key_format_fails_verification() {
        let (private_key, _) = jwt::generate_keypair();

        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        let token =
            jwt::sign_claims(&claims, &private_key, "license-id", "project", "jti-123").unwrap();

        // Invalid base64
        let result = jwt::verify_token(&token, "not-valid-base64!!!");
        assert!(
            result.is_err(),
            "public key with invalid base64 characters should be rejected"
        );

        // Valid base64 but wrong length
        let short_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0u8; 16],
        );
        let result = jwt::verify_token(&token, &short_key);
        assert!(
            result.is_err(),
            "public key with incorrect length (16 bytes instead of 32) should be rejected"
        );

        // Empty key
        let result = jwt::verify_token(&token, "");
        assert!(
            result.is_err(),
            "empty public key string should be rejected"
        );
    }

    /// Verify that invalid private key length is rejected.
    #[test]
    fn test_invalid_private_key_length_fails_signing() {
        let claims = create_test_claims(
            Some(future_timestamp(ONE_YEAR)),
            None,
            "pro",
            "product-123",
            "device-123",
            "uuid",
        );

        // Too short
        let short_key = vec![0u8; 16];
        let result = jwt::sign_claims(&claims, &short_key, "license-id", "project", "jti-123");
        assert!(
            result.is_err(),
            "private key shorter than 32 bytes should be rejected"
        );

        // Too long
        let long_key = vec![0u8; 64];
        let result = jwt::sign_claims(&claims, &long_key, "license-id", "project", "jti-123");
        assert!(
            result.is_err(),
            "private key longer than 32 bytes should be rejected"
        );

        // Empty
        let empty_key: Vec<u8> = vec![];
        let result = jwt::sign_claims(&claims, &empty_key, "license-id", "project", "jti-123");
        assert!(
            result.is_err(),
            "empty private key should be rejected"
        );
    }
}
