mod members;
mod projects;
mod project_members;
mod products;
mod licenses;

pub use members::*;
pub use projects::*;
pub use project_members::*;
pub use products::*;
pub use licenses::*;

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};

use crate::db::AppState;
use crate::middleware::{org_member_auth, org_member_project_auth};

pub fn router(state: AppState) -> Router<AppState> {
    // Org-level routes (members management)
    let org_routes = Router::new()
        .route("/orgs/{org_id}/members", post(create_org_member))
        .route("/orgs/{org_id}/members", get(list_org_members))
        .route("/orgs/{org_id}/members/{id}", get(get_org_member))
        .route("/orgs/{org_id}/members/{id}", put(update_org_member))
        .route("/orgs/{org_id}/members/{id}", delete(delete_org_member))
        .route("/orgs/{org_id}/projects", post(create_project))
        .route("/orgs/{org_id}/projects", get(list_projects))
        .layer(middleware::from_fn_with_state(state.clone(), org_member_auth));

    // Project-level routes
    let project_routes = Router::new()
        .route("/orgs/{org_id}/projects/{project_id}", get(get_project))
        .route("/orgs/{org_id}/projects/{project_id}", put(update_project))
        .route("/orgs/{org_id}/projects/{project_id}", delete(delete_project))
        // Project members
        .route("/orgs/{org_id}/projects/{project_id}/members", post(create_project_member))
        .route("/orgs/{org_id}/projects/{project_id}/members", get(list_project_members))
        .route("/orgs/{org_id}/projects/{project_id}/members/{id}", put(update_project_member))
        .route("/orgs/{org_id}/projects/{project_id}/members/{id}", delete(delete_project_member))
        // Products
        .route("/orgs/{org_id}/projects/{project_id}/products", post(create_product))
        .route("/orgs/{org_id}/projects/{project_id}/products", get(list_products))
        .route("/orgs/{org_id}/projects/{project_id}/products/{id}", get(get_product))
        .route("/orgs/{org_id}/projects/{project_id}/products/{id}", put(update_product))
        .route("/orgs/{org_id}/projects/{project_id}/products/{id}", delete(delete_product))
        // Licenses
        .route("/orgs/{org_id}/projects/{project_id}/licenses", get(list_licenses))
        .route("/orgs/{org_id}/projects/{project_id}/licenses", post(create_license))
        .route("/orgs/{org_id}/projects/{project_id}/licenses/{key}", get(get_license))
        .route("/orgs/{org_id}/projects/{project_id}/licenses/{key}/revoke", post(revoke_license))
        .route("/orgs/{org_id}/projects/{project_id}/licenses/{key}/replace", post(replace_license))
        // Device management (for remote deactivation of lost devices)
        .route("/orgs/{org_id}/projects/{project_id}/licenses/{key}/devices/{device_id}", delete(deactivate_device_admin))
        // Payment config (masked, for customers to verify their settings)
        .route("/orgs/{org_id}/projects/{project_id}/payment-config", get(get_payment_config))
        .layer(middleware::from_fn_with_state(state.clone(), org_member_project_auth));

    org_routes.merge(project_routes)
}
