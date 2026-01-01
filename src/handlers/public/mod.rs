mod redeem;
mod validate;
mod devices;
mod license;
mod buy;
mod callback;

pub use redeem::*;
pub use validate::*;
pub use devices::*;
pub use license::*;
pub use buy::*;
pub use callback::*;

use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;

use crate::db::AppState;
use crate::extractors::Json;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/buy", get(initiate_buy))
        .route("/callback", get(payment_callback))
        // GET /redeem accepts short-lived redemption codes (URL-safe)
        .route("/redeem", get(redeem_with_code))
        // POST /redeem/key accepts permanent license keys (never in URL)
        .route("/redeem/key", post(redeem_with_key))
        // POST /redeem/code generates a new short-lived code from a license key
        .route("/redeem/code", post(generate_redemption_code))
        .route("/validate", get(validate_license))
        // GET /license with license key in Authorization header
        .route("/license", get(get_license_info))
        .route("/devices/deactivate", post(deactivate_device))
}
