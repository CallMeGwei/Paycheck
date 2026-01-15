use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};

use crate::db::queries::ProductWithPaymentConfig;
use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path, RestoreRequest};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, AuditAction, CreateProduct, UpdateProduct};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::AuditLogBuilder;

#[derive(serde::Deserialize)]
pub struct ProductPath {
    pub org_id: String,
    pub project_id: String,
    pub product_id: String,
}

pub async fn create_product(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
    Json(input): Json<CreateProduct>,
) -> Result<Json<ProductWithPaymentConfig>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }
    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let product = queries::create_product(&conn, &path.project_id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::CreateProduct)
        .resource("product", &product.id)
        .details(&serde_json::json!({ "name": input.name, "tier": input.tier }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().resource(product.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    // Return with empty payment config (none configured yet)
    Ok(Json(ProductWithPaymentConfig {
        product,
        payment_config: vec![],
    }))
}

pub async fn list_products(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<ProductWithPaymentConfig>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();
    let (products, total) =
        queries::list_products_with_config_paginated(&conn, &path.project_id, limit, offset)?;
    Ok(Json(Paginated::new(products, total, limit, offset)))
}

pub async fn get_product(
    State(state): State<AppState>,
    Path(path): Path<ProductPath>,
) -> Result<Json<ProductWithPaymentConfig>> {
    let conn = state.db.get()?;
    let product = queries::get_product_with_config(&conn, &path.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if product.product.project_id != path.project_id {
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
) -> Result<Json<ProductWithPaymentConfig>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }
    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_product_by_id(&conn, &path.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if existing.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    queries::update_product(&conn, &path.product_id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::UpdateProduct)
        .resource("product", &path.product_id)
        .details(&serde_json::json!({ "name": input.name, "tier": input.tier }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    let product = queries::get_product_with_config(&conn, &path.product_id)?
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

    let existing = queries::get_product_by_id(&conn, &path.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if existing.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    queries::soft_delete_product(&conn, &path.product_id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::DeleteProduct)
        .resource("product", &path.product_id)
        .details(&serde_json::json!({ "name": existing.name }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Restore a soft-deleted product and its cascade-deleted licenses
pub async fn restore_product(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProductPath>,
    headers: HeaderMap,
    Json(input): Json<RestoreRequest>,
) -> Result<Json<ProductWithPaymentConfig>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_deleted_product_by_id(&conn, &path.product_id)?
        .ok_or_else(|| AppError::NotFound("Deleted product not found".into()))?;

    if existing.project_id != path.project_id {
        return Err(AppError::NotFound("Deleted product not found".into()));
    }

    queries::restore_product(&conn, &path.product_id, input.force)?;

    let product = queries::get_product_with_config(&conn, &path.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found after restore".into()))?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::RestoreProduct)
        .resource("product", &path.product_id)
        .details(&serde_json::json!({
            "name": existing.name,
            "force": input.force
        }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().resource(product.product.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(product))
}
