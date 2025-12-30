mod redeem;
mod validate;
mod devices;
mod buy;
mod callback;

pub use redeem::*;
pub use validate::*;
pub use devices::*;
pub use buy::*;
pub use callback::*;

use axum::{routing::{get, post}, Json, Router};
use serde::Serialize;

use crate::db::DbPool;

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

pub fn router() -> Router<DbPool> {
    Router::new()
        .route("/health", get(health))
        .route("/buy", get(initiate_buy))
        .route("/callback", get(payment_callback))
        .route("/redeem", get(redeem_license))
        .route("/validate", get(validate_license))
        .route("/devices", get(list_devices))
        .route("/devices/deactivate", post(deactivate_device))
}
