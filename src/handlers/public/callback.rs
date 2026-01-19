use axum::{extract::State, response::Redirect};
use serde::Deserialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::Query;

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub session: String,
}

/// Callback after payment - redirects with activation code.
///
/// This endpoint is called after a successful payment. It returns an activation code
/// which the user must then use via /redeem with their device info.
///
/// Query params appended to redirect:
/// - code: A short-lived activation code (PREFIX-XXXX-XXXX format)
/// - status: "success" or "pending"
///
/// Note: No JWT or license key is returned here. The user must call /redeem
/// with the activation code and device info to get a JWT.
pub async fn payment_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Redirect> {
    let conn = state.db.get()?;

    // Get payment session
    let session = queries::get_payment_session(&conn, &query.session)?
        .or_not_found(msg::SESSION_NOT_FOUND)?;

    // Get the product to find project
    let product = queries::get_product_by_id(&conn, &session.product_id)?
        .ok_or_else(|| AppError::Internal(msg::PRODUCT_NOT_FOUND.into()))?;

    // Get project for redirect URL and activation code prefix
    let project = queries::get_project_by_id(&conn, &product.project_id)?
        .ok_or_else(|| AppError::Internal(msg::PROJECT_NOT_FOUND.into()))?;

    // Determine base redirect URL (from project config or fallback to Paycheck success page)
    let base_redirect = project
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

    // Get license directly via stored ID (set by webhook when license was created)
    let license_id = session
        .license_id
        .ok_or_else(|| AppError::Internal(msg::LICENSE_PAYMENT_PROCESSING.into()))?;

    let license = queries::get_license_by_id(&conn, &license_id)?
        .ok_or_else(|| AppError::Internal(msg::LICENSE_NOT_FOUND.into()))?;

    // Create a short-lived activation code (PREFIX-XXXX-XXXX format)
    let activation_code =
        queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)?;

    // Build redirect URL with activation code only - no license key
    // User must activate via /redeem with device info to get JWT
    let redirect_url = append_query_params(
        base_redirect,
        &[("code", &activation_code.code), ("status", "success")],
    );

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
