//! Activation code request handler.
//!
//! Allows users to request activation codes sent to their purchase email.
//! This enables activation on new devices without needing a permanent license key.
//! If the user has multiple licenses, all codes are sent in a single email.

use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::email::{EmailSendConfig, EmailTrigger, LicenseCodeInfo, MultiLicenseEmailConfig};
use crate::error::Result;
use crate::extractors::Json;

#[derive(Debug, Deserialize)]
pub struct RequestCodeBody {
    /// The email address used for the original purchase
    pub email: String,
    /// Public key identifying the project
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RequestCodeResponse {
    /// Generic success message (same whether email exists or not)
    pub message: &'static str,
}

/// POST /activation/request-code
///
/// Request activation codes sent to the purchase email.
/// If the user has multiple licenses, all codes are sent in a single email.
/// Always returns 200 with a generic message to prevent email enumeration.
///
/// Rate limited to 3 requests per email per hour.
pub async fn request_activation_code(
    State(state): State<AppState>,
    Json(body): Json<RequestCodeBody>,
) -> Result<Json<RequestCodeResponse>> {
    let conn = state.db.get()?;

    // Compute email hash for rate limiting and lookup
    let email_hash = queries::hash_email(&body.email);

    // Rate limit check (by email hash)
    if let Err(_msg) = state.activation_rate_limiter.check(&email_hash) {
        // Return same generic message to prevent timing attacks
        tracing::warn!(
            "Rate limit exceeded for email hash {}...",
            &email_hash[..8]
        );
        // Still return success to prevent email enumeration via rate limit error timing
        return Ok(Json(RequestCodeResponse {
            message: "If a license exists for this email, an activation code has been sent.",
        }));
    }

    // Look up project by public key
    let project = match queries::get_project_by_public_key(&conn, &body.public_key)? {
        Some(p) => p,
        None => {
            // Don't reveal project doesn't exist - return same response
            tracing::debug!("Project not found for public key");
            return Ok(Json(RequestCodeResponse {
                message: "If a license exists for this email, an activation code has been sent.",
            }));
        }
    };

    // Look up ALL licenses by email hash and project (user may have multiple)
    let licenses = queries::get_licenses_by_email_hash(&conn, &project.id, &email_hash)?;

    // Filter to non-revoked licenses only (query already does this, but be explicit)
    let active_licenses: Vec<_> = licenses.into_iter().filter(|l| !l.revoked).collect();

    if active_licenses.is_empty() {
        tracing::debug!(
            "No active licenses found for email hash {}... in project {}",
            &email_hash[..8],
            project.id
        );
        return Ok(Json(RequestCodeResponse {
            message: "If a license exists for this email, an activation code has been sent.",
        }));
    }

    // Get organization for org-level Resend API key (do this once)
    let org = queries::get_organization_by_id(&conn, &project.org_id)?;
    let org_resend_key = org
        .as_ref()
        .and_then(|o| o.decrypt_resend_api_key(&state.master_key).ok())
        .flatten();

    // Create activation codes for all licenses and gather product info
    let mut license_codes: Vec<LicenseCodeInfo> = Vec::with_capacity(active_licenses.len());

    for license in &active_licenses {
        // Create activation code
        let code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)?;

        // Get product for product name
        let product = queries::get_product_by_id(&conn, &license.product_id)?;
        let product_name = product
            .map(|p| p.name)
            .unwrap_or_else(|| "Your Product".to_string());

        license_codes.push(LicenseCodeInfo {
            product_name,
            code: code.code,
            license_id: license.id.clone(),
            purchased_at: license.created_at,
        });
    }

    // Send email - use single-license format for 1, multi-license for 2+
    let email_result = if license_codes.len() == 1 {
        let info = &license_codes[0];
        let email_config = EmailSendConfig {
            to_email: &body.email,
            code: &info.code,
            expires_in_minutes: 30,
            product_name: &info.product_name,
            project_name: &project.name,
            project: &project,
            license_id: &info.license_id,
            purchased_at: info.purchased_at,
            org_resend_key: org_resend_key.as_deref(),
            trigger: EmailTrigger::RecoveryRequest,
        };
        state.email_service.send_activation_code(email_config).await
    } else {
        let email_config = MultiLicenseEmailConfig {
            to_email: &body.email,
            expires_in_minutes: 30,
            project_name: &project.name,
            project: &project,
            licenses: license_codes,
            org_resend_key: org_resend_key.as_deref(),
            trigger: EmailTrigger::RecoveryRequest,
        };
        state
            .email_service
            .send_multi_license_activation_codes(email_config)
            .await
    };

    match email_result {
        Ok(result) => {
            tracing::info!(
                result = ?result,
                email_hash_prefix = &email_hash[..8],
                project_id = %project.id,
                license_count = active_licenses.len(),
                "Activation code email processed"
            );
        }
        Err(e) => {
            // Log error but don't expose it to user
            tracing::error!(
                error = %e,
                email_hash_prefix = &email_hash[..8],
                project_id = %project.id,
                license_count = active_licenses.len(),
                "Failed to send activation code email"
            );
        }
    }

    // Always return same response (email enumeration protection)
    Ok(Json(RequestCodeResponse {
        message: "If a license exists for this email, an activation code has been sent.",
    }))
}
