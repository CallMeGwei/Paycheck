mod audit_logs;
mod licenses;
mod members;
mod product_payment_config;
mod products;
mod project_members;
mod projects;

pub use audit_logs::*;
pub use licenses::*;
pub use members::*;
pub use product_payment_config::*;
pub use products::*;
pub use project_members::*;
pub use projects::*;

use axum::{
    Router, middleware,
    routing::{delete, get, post, put},
};

use crate::db::AppState;
use crate::middleware::{org_member_auth, org_member_project_auth};

pub fn router(state: AppState) -> Router<AppState> {
    // Org-level routes (members management, payment config, audit logs)
    let org_routes = Router::new()
        .route("/orgs/{org_id}/members", post(create_org_member))
        .route("/orgs/{org_id}/members", get(list_org_members))
        .route("/orgs/{org_id}/members/{id}", get(get_org_member))
        .route("/orgs/{org_id}/members/{id}", put(update_org_member))
        .route("/orgs/{org_id}/members/{id}", delete(delete_org_member))
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
            "/orgs/{org_id}/projects/{project_id}/members/{id}",
            put(update_project_member),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/members/{id}",
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
            "/orgs/{org_id}/projects/{project_id}/products/{id}",
            get(get_product),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{id}",
            put(update_product),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{id}",
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
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/payment-config/{id}",
            get(get_payment_config_handler),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/payment-config/{id}",
            put(update_payment_config_handler),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/payment-config/{id}",
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

    org_routes.merge(project_routes)
}
