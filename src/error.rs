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
