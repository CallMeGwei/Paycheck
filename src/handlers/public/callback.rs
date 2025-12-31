use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, Json, Redirect},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::jwt::{self, LicenseClaims};
use crate::util::LicenseExpirations;

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub session: String,
    /// Optional: redirect to app with token
    #[serde(default)]
    pub redirect: Option<String>,
    /// Optional: response format ("json" or "html", default based on Accept header)
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CallbackResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Check if client wants JSON response
fn wants_json(headers: &HeaderMap, format: &Option<String>) -> bool {
    // Explicit format param takes precedence
    if let Some(fmt) = format {
        return fmt.eq_ignore_ascii_case("json");
    }
    // Check Accept header
    if let Some(accept) = headers.get("accept").and_then(|v| v.to_str().ok()) {
        return accept.contains("application/json");
    }
    false
}

/// Callback after payment - issues JWT to the customer
pub async fn payment_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<CallbackResult> {
    let conn = state.db.get()?;
    let use_json = wants_json(&headers, &query.format);

    // Get payment session
    let session = queries::get_payment_session(&conn, &query.session)?
        .ok_or_else(|| AppError::NotFound("Session not found".into()))?;

    // Check if session was completed by webhook
    if !session.completed {
        // Payment might still be processing
        if use_json {
            return Ok(CallbackResult::Json(Json(CallbackResponse {
                success: false,
                token: None,
                license_key: None,
                message: Some("Payment is still processing".into()),
            })));
        }
        return Ok(CallbackResult::Html(Html(pending_html(&query.session))));
    }

    // Find the license created by the webhook
    // We need to find a license for this product that was created around the same time
    let licenses = queries::list_license_keys_for_project(&conn, &session.product_id)?;

    // Get the product to find project
    let product = queries::get_product_by_id(&conn, &session.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Find a device with this device_id that was recently created
    let mut found_license = None;
    for license_with_product in &licenses {
        if let Ok(devices) = queries::list_devices_for_license(&conn, &license_with_product.license.id) {
            for device in devices {
                if device.device_id == session.device_id {
                    found_license = Some(&license_with_product.license);
                    break;
                }
            }
        }
        if found_license.is_some() {
            break;
        }
    }

    let license = found_license
        .ok_or_else(|| AppError::Internal("License not found - payment may still be processing".into()))?;

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

    let token = jwt::sign_claims(
        &claims,
        &project.private_key,
        &license.id,
        &project.domain,
        &device.jti,
    )?;

    // If redirect URL provided, redirect with token and short-lived redemption code
    // We use a redemption code instead of the license key to avoid exposing it in URL history
    if let Some(redirect_url) = query.redirect {
        let redemption_code = queries::create_redemption_code(&conn, &license.id)?;
        let redirect_with_token = if redirect_url.contains('?') {
            format!("{}&token={}&code={}", redirect_url, token, redemption_code.code)
        } else {
            format!("{}?token={}&code={}", redirect_url, token, redemption_code.code)
        };
        return Ok(CallbackResult::Redirect(Redirect::temporary(&redirect_with_token)));
    }

    // Return JSON or HTML based on client preference
    if use_json {
        return Ok(CallbackResult::Json(Json(CallbackResponse {
            success: true,
            token: Some(token),
            license_key: Some(license.key.clone()),
            message: None,
        })));
    }

    Ok(CallbackResult::Html(Html(success_html(&token, &license.key))))
}

pub enum CallbackResult {
    Html(Html<String>),
    Json(Json<CallbackResponse>),
    Redirect(Redirect),
}

impl axum::response::IntoResponse for CallbackResult {
    fn into_response(self) -> axum::response::Response {
        match self {
            CallbackResult::Html(html) => html.into_response(),
            CallbackResult::Json(json) => json.into_response(),
            CallbackResult::Redirect(redirect) => redirect.into_response(),
        }
    }
}

fn pending_html(session_id: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Processing Payment</title>
    <meta http-equiv="refresh" content="3">
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }}
        .spinner {{ border: 4px solid #f3f3f3; border-top: 4px solid #7c3aed; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <h1>Processing Payment...</h1>
    <div class="spinner"></div>
    <p>Please wait while we confirm your payment.</p>
    <p style="color: #666; font-size: 14px;">Session: {}</p>
</body>
</html>"#, session_id)
}

fn success_html(token: &str, license_key: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Payment Successful</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .success {{ color: #059669; font-size: 24px; margin-bottom: 20px; }}
        .key {{ background: #f3f4f6; padding: 15px; border-radius: 8px; font-family: monospace; word-break: break-all; margin: 15px 0; }}
        .token {{ background: #f3f4f6; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 12px; word-break: break-all; max-height: 100px; overflow: auto; margin: 15px 0; }}
        button {{ background: #7c3aed; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; margin: 5px; }}
        button:hover {{ background: #6d28d9; }}
        .copied {{ color: #059669; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="success">✓ Payment Successful!</div>

    <h3>Your License Key</h3>
    <div class="key" id="license-key">{license_key}</div>
    <button onclick="copyKey()">Copy License Key</button>
    <span id="key-copied" class="copied" style="display: none;">Copied!</span>

    <h3>Your Activation Token</h3>
    <div class="token" id="token">{token}</div>
    <button onclick="copyToken()">Copy Token</button>
    <span id="token-copied" class="copied" style="display: none;">Copied!</span>

    <p style="margin-top: 30px; color: #666;">
        Save your license key! You can use it to activate on other devices.
    </p>

    <script>
        function copyKey() {{
            navigator.clipboard.writeText(document.getElementById('license-key').textContent);
            document.getElementById('key-copied').style.display = 'inline';
            setTimeout(() => document.getElementById('key-copied').style.display = 'none', 2000);
        }}
        function copyToken() {{
            navigator.clipboard.writeText(document.getElementById('token').textContent);
            document.getElementById('token-copied').style.display = 'inline';
            setTimeout(() => document.getElementById('token-copied').style.display = 'none', 2000);
        }}
    </script>
</body>
</html>"#, license_key = license_key, token = token)
}
