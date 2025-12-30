mod stripe;
mod lemonsqueezy;

pub use stripe::*;
pub use lemonsqueezy::*;

use axum::{routing::post, Router};

use crate::db::DbPool;

pub fn router() -> Router<DbPool> {
    Router::new()
        .route("/webhook/stripe", post(handle_stripe_webhook))
        .route("/webhook/lemonsqueezy", post(handle_lemonsqueezy_webhook))
}
