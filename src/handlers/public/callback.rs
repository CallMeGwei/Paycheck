use axum::{extract::State, response::Redirect};
use serde::Deserialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::Query;

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub session: String,
}

/// Callback after payment - redirects with license key for activation.
///
/// This endpoint is called after a successful payment. It returns the license key
/// which the user must then activate via /redeem/key with their device info.
///
/// Query params appended to redirect:
/// - license_key: The permanent license key
/// - code: A short-lived redemption code for URL-safe activation
/// - status: "success" or "pending"
/// - project_id: The project ID (needed for activation)
///
/// Note: No JWT is returned here because the user hasn't activated a device yet.
/// The user must call /redeem/key with device_id and device_type to get a JWT.
pub async fn payment_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Redirect> {
    let conn = state.db.get()?;

    // Get payment session
    let session = queries::get_payment_session(&conn, &query.session)?
        .ok_or_else(|| AppError::NotFound("Session not found".into()))?;

    // Determine base redirect URL
    let base_redirect = session
        .redirect_url
        .as_ref()
        .unwrap_or(&state.success_page_url);

    // Check if session was completed by webhook
    if !session.completed {
        // Payment might still be processing - redirect to success page with pending flag
        let redirect_url = append_query_params(
            base_redirect,
            &[("session", &query.session), ("status", "pending")],
        );
        return Ok(Redirect::temporary(&redirect_url));
    }

    // Get the product to find project
    let product = queries::get_product_by_id(&conn, &session.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Get license directly via stored ID (set by webhook when license was created)
    let license_id = session.license_key_id.ok_or_else(|| {
        AppError::Internal("License not found - payment may still be processing".into())
    })?;

    let license = queries::get_license_key_by_id(&conn, &license_id, &state.master_key)?
        .ok_or_else(|| AppError::Internal("License not found".into()))?;

    // Create a short-lived redemption code for URL-safe activation
    let redemption_code = queries::create_redemption_code(&conn, &license.id)?;

    // Build redirect URL with license key and redemption code
    // No JWT - user must activate via /redeem/key with device info
    let redirect_url = if session.redirect_url.is_some() {
        // Third-party redirect: redemption code only (safer for URLs)
        append_query_params(
            base_redirect,
            &[
                ("code", &redemption_code.code),
                ("project_id", &product.project_id),
                ("status", "success"),
            ],
        )
    } else {
        // Success page: include license key for display
        append_query_params(
            base_redirect,
            &[
                ("license_key", &license.key),
                ("code", &redemption_code.code),
                ("project_id", &product.project_id),
                ("status", "success"),
            ],
        )
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
