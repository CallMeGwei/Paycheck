use axum::{
    extract::{Extension, State},
    http::HeaderMap,
};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, CreateProduct, Product, UpdateProduct};
use crate::util::audit_log;

#[derive(serde::Deserialize)]
pub struct ProductPath {
    pub org_id: String,
    pub project_id: String,
    pub id: String,
}

pub async fn create_product(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
    Json(input): Json<CreateProduct>,
) -> Result<Json<Product>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let product = queries::create_product(&conn, &path.project_id, &input)?;

    audit_log(
        &audit_conn, state.audit_log_enabled, ActorType::OrgMember, Some(&ctx.member.id), &headers,
        "create_product", "product", &product.id,
        Some(&serde_json::json!({ "name": input.name, "tier": input.tier })),
        Some(&path.org_id), Some(&path.project_id),
    )?;

    Ok(Json(product))
}

pub async fn list_products(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
) -> Result<Json<Vec<Product>>> {
    let conn = state.db.get()?;
    let products = queries::list_products_for_project(&conn, &path.project_id)?;
    Ok(Json(products))
}

pub async fn get_product(
    State(state): State<AppState>,
    Path(path): Path<ProductPath>,
) -> Result<Json<Product>> {
    let conn = state.db.get()?;
    let product = queries::get_product_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    Ok(Json(product))
}

pub async fn update_product(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProductPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateProduct>,
) -> Result<Json<Product>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_product_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if existing.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    queries::update_product(&conn, &path.id, &input)?;

    audit_log(
        &audit_conn, state.audit_log_enabled, ActorType::OrgMember, Some(&ctx.member.id), &headers,
        "update_product", "product", &path.id,
        Some(&serde_json::json!({ "name": input.name, "tier": input.tier })),
        Some(&path.org_id), Some(&path.project_id),
    )?;

    let product = queries::get_product_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    Ok(Json(product))
}

pub async fn delete_product(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProductPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_product_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if existing.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    queries::delete_product(&conn, &path.id)?;

    audit_log(
        &audit_conn, state.audit_log_enabled, ActorType::OrgMember, Some(&ctx.member.id), &headers,
        "delete_product", "product", &path.id,
        Some(&serde_json::json!({ "name": existing.name })),
        Some(&path.org_id), Some(&path.project_id),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
