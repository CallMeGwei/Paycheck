use axum::{
    extract::{Extension, State},
    http::HeaderMap,
};

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, CreatePaymentConfig, ProductPaymentConfig, UpdatePaymentConfig};
use crate::util::audit_log;

#[derive(serde::Deserialize)]
pub struct PaymentConfigPath {
    pub org_id: String,
    pub project_id: String,
    pub product_id: String,
}

#[derive(serde::Deserialize)]
pub struct PaymentConfigItemPath {
    pub org_id: String,
    pub project_id: String,
    pub product_id: String,
    pub id: String,
}

pub async fn create_payment_config(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<PaymentConfigPath>,
    headers: HeaderMap,
    Json(input): Json<CreatePaymentConfig>,
) -> Result<Json<ProductPaymentConfig>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify product exists and belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    // Check if config already exists for this provider
    if queries::get_payment_config(&conn, &path.product_id, &input.provider)?.is_some() {
        return Err(AppError::BadRequest(format!(
            "Payment config for provider '{}' already exists",
            input.provider
        )));
    }

    let config = queries::create_payment_config(&conn, &path.product_id, &input)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        &headers,
        "create_payment_config",
        "payment_config",
        &config.id,
        Some(&serde_json::json!({ "product_id": path.product_id, "provider": input.provider })),
        Some(&path.org_id),
        Some(&path.project_id),
    )?;

    Ok(Json(config))
}

pub async fn list_payment_configs(
    State(state): State<AppState>,
    Path(path): Path<PaymentConfigPath>,
) -> Result<Json<Vec<ProductPaymentConfig>>> {
    let conn = state.db.get()?;

    // Verify product exists and belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    let configs = queries::get_payment_configs_for_product(&conn, &path.product_id)?;
    Ok(Json(configs))
}

pub async fn get_payment_config_handler(
    State(state): State<AppState>,
    Path(path): Path<PaymentConfigItemPath>,
) -> Result<Json<ProductPaymentConfig>> {
    let conn = state.db.get()?;

    let config = queries::get_payment_config_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Payment config not found".into()))?;

    // Verify it belongs to the specified product
    if config.product_id != path.product_id {
        return Err(AppError::NotFound("Payment config not found".into()));
    }

    // Verify product belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    Ok(Json(config))
}

pub async fn update_payment_config_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<PaymentConfigItemPath>,
    headers: HeaderMap,
    Json(input): Json<UpdatePaymentConfig>,
) -> Result<Json<ProductPaymentConfig>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_payment_config_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Payment config not found".into()))?;

    // Verify it belongs to the specified product
    if existing.product_id != path.product_id {
        return Err(AppError::NotFound("Payment config not found".into()));
    }

    // Verify product belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    queries::update_payment_config(&conn, &path.id, &input)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        &headers,
        "update_payment_config",
        "payment_config",
        &path.id,
        Some(&serde_json::json!({ "product_id": path.product_id, "provider": existing.provider })),
        Some(&path.org_id),
        Some(&path.project_id),
    )?;

    let config = queries::get_payment_config_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Payment config not found".into()))?;

    Ok(Json(config))
}

pub async fn delete_payment_config_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<PaymentConfigItemPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_payment_config_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Payment config not found".into()))?;

    // Verify it belongs to the specified product
    if existing.product_id != path.product_id {
        return Err(AppError::NotFound("Payment config not found".into()));
    }

    // Verify product belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    queries::delete_payment_config(&conn, &path.id)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        &headers,
        "delete_payment_config",
        "payment_config",
        &path.id,
        Some(&serde_json::json!({ "product_id": path.product_id, "provider": existing.provider })),
        Some(&path.org_id),
        Some(&path.project_id),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
