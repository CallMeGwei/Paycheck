mod api_keys;
mod audit_logs;
mod management;
mod organizations;
mod support;
mod users;

pub use api_keys::*;
pub use audit_logs::*;
pub use management::*;
pub use organizations::*;
pub use support::*;
pub use users::*;

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
        .route("/operators/{operator_id}", get(get_operator))
        .route("/operators/{operator_id}", put(update_operator))
        .route("/operators/{operator_id}", delete(delete_operator))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_owner_role,
        ))
        .merge(
            Router::new()
                // User management (admin+)
                .route("/operators/users", post(users::create_user))
                .route("/operators/users", get(users::list_users))
                .route("/operators/users/{user_id}", get(users::get_user))
                .route("/operators/users/{user_id}", put(users::update_user))
                .route("/operators/users/{user_id}", delete(users::delete_user))
                // Organization management (admin+)
                .route("/operators/organizations", post(create_organization))
                .route("/operators/organizations", get(list_organizations))
                .route("/operators/organizations/{org_id}", get(get_organization))
                .route("/operators/organizations/{org_id}", put(update_organization))
                .route("/operators/organizations/{org_id}", delete(delete_organization))
                // Support endpoints (admin+)
                .route(
                    "/operators/organizations/{org_id}/payment-config",
                    get(get_org_payment_config),
                )
                .route(
                    "/operators/organizations/{org_id}/projects/{project_id}/licenses/lookup",
                    get(lookup_licenses_by_email),
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
                .route("/operators/audit-logs/text", get(query_audit_logs_text))
                // Operator API keys (operators can manage their own, owner can manage all)
                .route(
                    "/operators/{operator_id}/api-keys",
                    post(api_keys::create_api_key),
                )
                .route(
                    "/operators/{operator_id}/api-keys",
                    get(api_keys::list_api_keys),
                )
                .route(
                    "/operators/{operator_id}/api-keys/{key_id}",
                    delete(api_keys::revoke_api_key),
                )
                .layer(middleware::from_fn_with_state(state.clone(), operator_auth)),
        )
}
