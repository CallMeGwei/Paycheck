mod audit_logs;
mod management;
mod organizations;
mod support;

pub use audit_logs::*;
pub use management::*;
pub use organizations::*;
pub use support::*;

use axum::{
    Router, middleware,
    routing::{delete, get, post, put},
};

use crate::db::AppState;
use crate::middleware::{operator_auth, require_admin_role, require_owner_role};

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        // Operator management (owner only)
        .route("/operators", post(create_operator))
        .route("/operators", get(list_operators))
        .route("/operators/{id}", get(get_operator))
        .route("/operators/{id}", put(update_operator))
        .route("/operators/{id}", delete(delete_operator))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_owner_role,
        ))
        .merge(
            Router::new()
                // Organization management (admin+)
                .route("/operators/organizations", post(create_organization))
                .route("/operators/organizations", get(list_organizations))
                .route("/operators/organizations/{id}", get(get_organization))
                .route("/operators/organizations/{id}", put(update_organization))
                .route("/operators/organizations/{id}", delete(delete_organization))
                // Support endpoints (admin+)
                .route(
                    "/operators/organizations/{org_id}/payment-config",
                    get(get_org_payment_config),
                )
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    require_admin_role,
                )),
        )
        .merge(
            Router::new()
                // Audit logs (view+)
                .route("/operators/audit-logs", get(query_audit_logs))
                .layer(middleware::from_fn_with_state(state.clone(), operator_auth)),
        )
}
