mod api_keys;
mod audit_logs;
mod licenses;
mod members;
mod product_payment_config;
mod products;
mod project_members;
mod projects;

pub use api_keys::*;
pub use audit_logs::*;
pub use licenses::*;
pub use members::*;
pub use product_payment_config::*;
pub use products::*;
pub use project_members::*;
pub use projects::*;

use axum::{
    Router, middleware,
    routing::{delete, get, patch, post, put},
};

use crate::config::RateLimitConfig;
use crate::db::AppState;
use crate::middleware::{org_member_auth, org_member_project_auth};
use crate::rate_limit;

pub fn router(state: AppState, rate_limit_config: RateLimitConfig) -> Router<AppState> {
    // Org-level routes (members management, payment config, audit logs, api keys)
    let org_routes = Router::new()
        .route("/orgs/{org_id}/members", post(create_org_member))
        .route("/orgs/{org_id}/members", get(list_org_members))
        .route("/orgs/{org_id}/members/{member_id}", get(get_org_member))
        .route("/orgs/{org_id}/members/{member_id}", put(update_org_member))
        .route("/orgs/{org_id}/members/{member_id}", delete(delete_org_member))
        // Member API keys
        .route(
            "/orgs/{org_id}/members/{member_id}/api-keys",
            post(api_keys::create_api_key),
        )
        .route(
            "/orgs/{org_id}/members/{member_id}/api-keys",
            get(api_keys::list_api_keys),
        )
        .route(
            "/orgs/{org_id}/members/{member_id}/api-keys/{key_id}",
            delete(api_keys::revoke_api_key),
        )
        .route("/orgs/{org_id}/projects", post(create_project))
        .route("/orgs/{org_id}/projects", get(list_projects))
        // Payment config (at org level, masked for customers to verify their settings)
        .route("/orgs/{org_id}/payment-config", get(get_payment_config))
        // Audit logs (org-scoped, any org member can view their org's logs)
        .route("/orgs/{org_id}/audit-logs", get(query_org_audit_logs))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            org_member_auth,
        ));

    // Project-level routes
    let project_routes = Router::new()
        .route("/orgs/{org_id}/projects/{project_id}", get(get_project))
        .route("/orgs/{org_id}/projects/{project_id}", put(update_project))
        .route(
            "/orgs/{org_id}/projects/{project_id}",
            delete(delete_project),
        )
        // Project members
        .route(
            "/orgs/{org_id}/projects/{project_id}/members",
            post(create_project_member),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/members",
            get(list_project_members),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/members/{member_id}",
            get(get_project_member),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/members/{member_id}",
            put(update_project_member),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/members/{member_id}",
            delete(delete_project_member),
        )
        // Products
        .route(
            "/orgs/{org_id}/projects/{project_id}/products",
            post(create_product),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products",
            get(list_products),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}",
            get(get_product),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}",
            put(update_product),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}",
            delete(delete_product),
        )
        // Product payment config
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/payment-config",
            post(create_payment_config),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/payment-config",
            get(list_payment_configs),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/payment-config/{config_id}",
            get(get_payment_config_handler),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/payment-config/{config_id}",
            put(update_payment_config_handler),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/payment-config/{config_id}",
            delete(delete_payment_config_handler),
        )
        // Licenses
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses",
            get(list_licenses),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses",
            post(create_license),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}",
            get(get_license),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}",
            patch(update_license),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}/revoke",
            post(revoke_license),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}/send-code",
            post(send_activation_code),
        )
        // Device management (for remote deactivation of lost devices)
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}/devices/{device_id}",
            delete(deactivate_device_admin),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            org_member_project_auth,
        ));

    let merged = org_routes.merge(project_routes);

    // Apply rate limiting if configured (skip if rpm is 0, useful for tests)
    if rate_limit_config.org_ops_rpm > 0 {
        merged.layer(rate_limit::org_ops_layer(rate_limit_config.org_ops_rpm))
    } else {
        merged
    }
}
