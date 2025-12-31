mod common;
mod stripe;
mod lemonsqueezy;

pub use stripe::handle_stripe_webhook;
pub use lemonsqueezy::handle_lemonsqueezy_webhook;

use axum::{routing::post, Router};

use crate::db::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/webhook/stripe", post(handle_stripe_webhook))
        .route("/webhook/lemonsqueezy", post(handle_lemonsqueezy_webhook))
}
