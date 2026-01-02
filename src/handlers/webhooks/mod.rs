pub mod common;
mod lemonsqueezy;
mod stripe;

pub use lemonsqueezy::handle_lemonsqueezy_webhook;
pub use stripe::handle_stripe_webhook;

use axum::{Router, routing::post};

use crate::db::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/webhook/stripe", post(handle_stripe_webhook))
        .route("/webhook/lemonsqueezy", post(handle_lemonsqueezy_webhook))
}
