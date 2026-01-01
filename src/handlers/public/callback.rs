use axum::{extract::State, response::Redirect};
use chrono::Utc;
use serde::Deserialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::Query;
use crate::jwt::{self, LicenseClaims};
use crate::util::LicenseExpirations;

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub session: String,
}

/// Callback after payment - redirects to configured URL with token
///
/// If session has a redirect_url (validated at /buy time), redirects there.
/// Otherwise, redirects to the operator-configured success page.
///
/// Query params appended to redirect:
/// - token: The JWT for the activated device
/// - code: A short-lived redemption code for future activations
/// - license_key: The permanent license key (only for success page, not third-party redirects)
pub async fn payment_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Redirect> {
    let conn = state.db.get()?;

    // Get payment session
    let session = queries::get_payment_session(&conn, &query.session)?
        .ok_or_else(|| AppError::NotFound("Session not found".into()))?;

    // Determine base redirect URL
    let base_redirect = session.redirect_url.as_ref()
        .unwrap_or(&state.success_page_url);

    // Check if session was completed by webhook
    if !session.completed {
        // Payment might still be processing - redirect to success page with pending flag
        let redirect_url = append_query_params(base_redirect, &[
            ("session", &query.session),
            ("status", "pending"),
        ]);
        return Ok(Redirect::temporary(&redirect_url));
    }

    // Get the product to find project
    let product = queries::get_product_by_id(&conn, &session.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Get license directly via stored ID (set by webhook when license was created)
    let license_id = session.license_key_id
        .ok_or_else(|| AppError::Internal("License not found - payment may still be processing".into()))?;

    let license = queries::get_license_key_by_id(&conn, &license_id, &state.master_key)?
        .ok_or_else(|| AppError::Internal("License not found".into()))?;

    // Get the device to find JTI
    let device = queries::get_device_for_license(&conn, &license.id, &session.device_id)?
        .ok_or_else(|| AppError::Internal("Device not found".into()))?;

    // Get project for signing
    let project = queries::get_project_by_id(&conn, &product.project_id)?
        .ok_or_else(|| AppError::Internal("Project not found".into()))?;

    // Build fresh JWT
    let now = Utc::now().timestamp();
    let exps = LicenseExpirations::from_product(&product, now);

    let claims = LicenseClaims {
        license_exp: exps.license_exp,
        updates_exp: exps.updates_exp,
        tier: product.tier.clone(),
        features: product.features.clone(),
        device_id: session.device_id.clone(),
        device_type: match session.device_type {
            crate::models::DeviceType::Uuid => "uuid".to_string(),
            crate::models::DeviceType::Machine => "machine".to_string(),
        },
        product_id: product.id.clone(),
        license_key: license.key.clone(),
    };

    // Decrypt the private key and sign the JWT
    let private_key = state.master_key.decrypt_private_key(&project.id, &project.private_key)?;
    let token = jwt::sign_claims(
        &claims,
        &private_key,
        &license.id,
        &project.domain,
        &device.jti,
    )?;

    // Create a short-lived redemption code for future activations
    let redemption_code = queries::create_redemption_code(&conn, &license.id)?;

    // Build redirect URL with token and code
    // For third-party redirects, we don't expose the license key in URL
    // For the success page, we include it so it can be displayed
    let redirect_url = if session.redirect_url.is_some() {
        // Third-party redirect: token + redemption code only
        append_query_params(base_redirect, &[
            ("token", &token),
            ("code", &redemption_code.code),
            ("status", "success"),
        ])
    } else {
        // Success page: include license key for display
        append_query_params(base_redirect, &[
            ("token", &token),
            ("code", &redemption_code.code),
            ("license_key", &license.key),
            ("status", "success"),
        ])
    };

    Ok(Redirect::temporary(&redirect_url))
}

/// Append query parameters to a URL
fn append_query_params(base_url: &str, params: &[(&str, &str)]) -> String {
    let query_string: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    if base_url.contains('?') {
        format!("{}&{}", base_url, query_string)
    } else {
        format!("{}?{}", base_url, query_string)
    }
}
