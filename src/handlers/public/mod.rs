mod activation;
mod buy;
mod callback;
mod devices;
mod license;
mod redeem;
mod refresh;
mod validate;

pub use activation::*;
pub use buy::*;
pub use callback::*;
pub use devices::*;
pub use license::*;
pub use redeem::*;
pub use refresh::*;
pub use validate::*;

use axum::Router;
use axum::http::{HeaderName, Method};
use axum::routing::{get, post};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};

use crate::config::RateLimitConfig;
use crate::db::AppState;
use crate::extractors::Json;
use crate::rate_limit;

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

pub fn router(rate_limit_config: RateLimitConfig) -> Router<AppState> {
    // Strict tier: external API calls + activation requests
    let strict_routes = Router::new()
        .route("/buy", post(initiate_buy))
        .route("/activation/request-code", post(request_activation_code))
        .layer(rate_limit::strict_layer(rate_limit_config.strict_rpm));

    // Standard tier: crypto + DB operations
    let standard_routes = Router::new()
        .route("/callback", get(payment_callback))
        .route("/redeem", post(redeem_with_code))
        .route("/refresh", post(refresh_token))
        .route("/validate", post(validate_license))
        .route("/license", get(get_license_info))
        .route("/devices/deactivate", post(deactivate_device))
        .layer(rate_limit::standard_layer(rate_limit_config.standard_rpm));

    // Relaxed tier: lightweight operations
    let relaxed_routes = Router::new()
        .route("/health", get(health))
        .layer(rate_limit::relaxed_layer(rate_limit_config.relaxed_rpm));

    // CORS: Allow any origin since public endpoints are called from customer websites
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
        ]);

    Router::new()
        .merge(strict_routes)
        .merge(standard_routes)
        .merge(relaxed_routes)
        .layer(cors)
}
