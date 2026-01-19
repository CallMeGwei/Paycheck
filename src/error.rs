use axum::{
    Json,
    extract::rejection::{JsonRejection, PathRejection, QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::typed_header::TypedHeaderRejection;
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JSON body error: {0}")]
    JsonBody(#[from] JsonRejection),

    #[error("Query error: {0}")]
    Query(#[from] QueryRejection),

    #[error("Path error: {0}")]
    Path(#[from] PathRejection),

    #[error("Header error: {0}")]
    Header(#[from] TypedHeaderRejection),

    #[error("Internal error: {0}")]
    Internal(String),

    // JWT authentication errors
    #[error("Untrusted issuer")]
    UntrustedIssuer,

    #[error("Missing key ID in JWT header")]
    MissingKeyId,

    #[error("Failed to fetch JWKS: {0}")]
    JwksFetchFailed(String),

    #[error("JWT validation failed: {0}")]
    JwtValidationFailed(String),

    #[error("User not found")]
    UserNotFound,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl From<StatusCode> for AppError {
    fn from(code: StatusCode) -> Self {
        match code {
            StatusCode::UNAUTHORIZED => AppError::Unauthorized,
            StatusCode::FORBIDDEN => AppError::Forbidden("Access denied".into()),
            StatusCode::NOT_FOUND => AppError::NotFound("Resource not found".into()),
            _ => AppError::Internal(format!("Status: {}", code)),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error, details) = match &self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "Not found", Some(msg.clone())),
            AppError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, "Bad request", Some(msg.clone()))
            }
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized", None),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "Forbidden", Some(msg.clone())),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "Conflict", Some(msg.clone())),
            AppError::Database(e) => {
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error",
                    None,
                )
            }
            AppError::Pool(e) => {
                tracing::error!("Pool error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error",
                    None,
                )
            }
            AppError::Json(e) => (StatusCode::BAD_REQUEST, "Invalid JSON", Some(e.to_string())),
            AppError::JsonBody(e) => (
                StatusCode::BAD_REQUEST,
                "Invalid request body",
                Some(e.body_text()),
            ),
            AppError::Query(e) => (
                StatusCode::BAD_REQUEST,
                "Invalid query parameters",
                Some(e.body_text()),
            ),
            AppError::Path(e) => (
                StatusCode::BAD_REQUEST,
                "Invalid path parameters",
                Some(e.body_text()),
            ),
            AppError::Header(e) => {
                let msg = e.to_string();
                if msg.contains("missing") {
                    (
                        StatusCode::UNAUTHORIZED,
                        "Missing authorization header",
                        None,
                    )
                } else {
                    (StatusCode::BAD_REQUEST, "Invalid header", Some(msg))
                }
            }
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error",
                    None,
                )
            }
            AppError::UntrustedIssuer => (StatusCode::UNAUTHORIZED, "Untrusted issuer", None),
            AppError::MissingKeyId => (StatusCode::BAD_REQUEST, "Missing key ID in JWT", None),
            AppError::JwksFetchFailed(msg) => {
                tracing::error!("JWKS fetch failed: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to validate token",
                    None,
                )
            }
            AppError::JwtValidationFailed(msg) => {
                (StatusCode::UNAUTHORIZED, "Invalid token", Some(msg.clone()))
            }
            AppError::UserNotFound => (StatusCode::UNAUTHORIZED, "User not found", None),
        };

        let body = ErrorResponse {
            error: error.to_string(),
            details,
        };

        (status, Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

/// Extension trait for Option to convert to AppError::NotFound
pub trait OptionExt<T> {
    fn or_not_found(self, msg: &str) -> Result<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn or_not_found(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| AppError::NotFound(msg.into()))
    }
}

/// Standard error messages for consistency and future i18n
pub mod msg {
    // Primary resources
    pub const USER_NOT_FOUND: &str = "User not found";
    pub const ORG_NOT_FOUND: &str = "Organization not found";
    pub const PROJECT_NOT_FOUND: &str = "Project not found";
    pub const PRODUCT_NOT_FOUND: &str = "Product not found";
    pub const LICENSE_NOT_FOUND: &str = "License not found";
    pub const DEVICE_NOT_FOUND: &str = "Device not found";
    pub const API_KEY_NOT_FOUND: &str = "API key not found";
    pub const SESSION_NOT_FOUND: &str = "Session not found";
    pub const PAYMENT_CONFIG_NOT_FOUND: &str = "Payment config not found";
    pub const PROVIDER_LINK_NOT_FOUND: &str = "Provider link not found";

    // Membership checks
    pub const NOT_ORG_MEMBER: &str = "User is not a member of this org";
    pub const NOT_PROJECT_MEMBER: &str = "User is not a member of this project";
    pub const NOT_OPERATOR: &str = "User is not an operator";
    pub const ORG_MEMBER_NOT_FOUND: &str = "Org member not found";

    // Soft-deleted resources
    pub const DELETED_USER_NOT_FOUND: &str = "Deleted user not found";
    pub const DELETED_ORG_NOT_FOUND: &str = "Deleted organization not found";
    pub const DELETED_PROJECT_NOT_FOUND: &str = "Deleted project not found";
    pub const DELETED_PRODUCT_NOT_FOUND: &str = "Deleted product not found";
    pub const DELETED_LICENSE_NOT_FOUND: &str = "Deleted license not found";
    pub const DELETED_MEMBER_NOT_FOUND: &str = "Deleted member not found";

    // Device-specific
    pub const DEVICE_NOT_FOUND_OR_DEACTIVATED: &str = "Device not found or already deactivated";

    // Permission errors
    pub const INSUFFICIENT_PERMISSIONS: &str = "Insufficient permissions";
    pub const CANNOT_BE_REDEEMED: &str = "Cannot be redeemed";
    pub const DEVICE_DEACTIVATED: &str = "Device has been deactivated";

    // Self-action restrictions
    pub const CANNOT_DELETE_SELF: &str = "Cannot delete yourself";
    pub const CANNOT_CHANGE_OWN_ROLE: &str = "Cannot change your own role";

    // Validation errors
    pub const EMAIL_ALREADY_EXISTS: &str = "Email already exists";
    pub const TOKEN_MISSING_JTI: &str = "Token missing JTI";
    pub const OWNER_USER_NOT_FOUND: &str = "Owner user not found";

    // Payment config errors
    pub const STRIPE_NOT_CONFIGURED: &str = "Stripe not configured";
    pub const LS_NOT_CONFIGURED: &str = "LemonSqueezy not configured";
    pub const NO_PRICE_CONFIGURED: &str = "Payment config has no price_cents configured.";
    pub const NO_VARIANT_CONFIGURED: &str = "Payment config has no ls_variant_id configured.";

    // Post-operation errors (for consistency in error messages after mutations)
    pub const USER_NOT_FOUND_AFTER_RESTORE: &str = "User not found after restore";
    pub const USER_NOT_FOUND_AFTER_UPDATE: &str = "User not found after update";
    pub const ORG_NOT_FOUND_AFTER_UPDATE: &str = "Organization not found after update";
    pub const MEMBER_NOT_FOUND_AFTER_UPDATE: &str = "Member not found after update";
    pub const ORG_NOT_FOUND_AFTER_RESTORE: &str = "Organization not found after restore";
    pub const PROJECT_NOT_FOUND_AFTER_RESTORE: &str = "Project not found after restore";
    pub const PRODUCT_NOT_FOUND_AFTER_RESTORE: &str = "Product not found after restore";
    pub const LICENSE_NOT_FOUND_AFTER_RESTORE: &str = "License not found after restore";
    pub const MEMBER_NOT_FOUND_AFTER_RESTORE: &str = "Member not found after restore";
    pub const LICENSE_PAYMENT_PROCESSING: &str =
        "License not found - payment may still be processing";

    // User fetch errors
    pub const FAILED_TO_FETCH_USER: &str = "Failed to fetch user";
    pub const FAILED_TO_FETCH_CREATED_USER: &str = "Failed to fetch created user";

    // License state errors
    pub const LICENSE_REVOKED: &str = "License is revoked";
    pub const LICENSE_ALREADY_REVOKED: &str = "License is already revoked";

    // Token validation errors
    pub const INVALID_TOKEN_PRODUCT: &str = "Invalid token: product not found";
    pub const INVALID_TOKEN_MISSING_JTI: &str = "Invalid token: missing jti";

    // Input validation errors
    pub const INVALID_PROVIDER: &str = "Invalid provider";
    pub const INVALID_ORG_PROVIDER: &str = "Invalid payment_provider in organization";
    pub const INVALID_DEVICE_TYPE: &str = "Invalid device_type. Must be 'uuid' or 'machine'";
    pub const DEVICE_ID_EMPTY: &str = "device_id cannot be empty";
    pub const CANNOT_HARD_DELETE_SELF: &str = "Cannot hard delete yourself";

    // Contextual not found
    pub const DELETED_LICENSE_PRODUCT_NOT_FOUND: &str =
        "Deleted license not found (product not found)";

    // Model validation errors
    pub const NAME_EMPTY: &str = "name cannot be empty";
    pub const TIER_EMPTY: &str = "tier cannot be empty";
    pub const EMAIL_EMPTY: &str = "email cannot be empty";
    pub const INVALID_EMAIL_FORMAT: &str = "invalid email format";
    pub const EMAIL_FROM_REQUIRES_ORG_RESEND_KEY: &str =
        "email_from requires the organization to have a resend_api_key configured";

    // JWT/Token errors
    pub const INVALID_TOKEN_FORMAT: &str = "Invalid token format";
    pub const INVALID_TOKEN_ENCODING: &str = "Invalid token encoding";
    pub const INVALID_TOKEN_PAYLOAD: &str = "Invalid token payload";
    pub const INVALID_PRIVATE_KEY_LENGTH: &str = "Invalid private key length";
    pub const INVALID_PUBLIC_KEY_LENGTH: &str = "Invalid public key length";
    pub const FAILED_TO_CONVERT_KEY_BYTES: &str = "Failed to convert key bytes";

    // Payment signature errors
    pub const INVALID_SIGNATURE_FORMAT: &str = "Invalid signature format";
    pub const INVALID_TIMESTAMP_IN_SIGNATURE: &str = "Invalid timestamp in signature";
    pub const INVALID_WEBHOOK_SECRET: &str = "Invalid webhook secret";
}
