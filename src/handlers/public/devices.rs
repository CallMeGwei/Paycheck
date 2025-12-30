use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::db::{queries, DbPool};
use crate::error::{AppError, Result};

#[derive(Debug, Deserialize)]
pub struct DevicesQuery {
    pub project_id: String,
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_type: String,
    pub name: Option<String>,
    pub activated_at: i64,
    pub last_seen_at: i64,
}

#[derive(Debug, Serialize)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceInfo>,
    pub device_limit: i32,
}

pub async fn list_devices(
    State(pool): State<DbPool>,
    Query(query): Query<DevicesQuery>,
) -> Result<Json<DevicesResponse>> {
    let conn = pool.get()?;

    // Get the license key
    let license = queries::get_license_key_by_key(&conn, &query.key)?
        .ok_or_else(|| AppError::NotFound("License key not found".into()))?;

    // Get the product to verify project and get device limit
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Verify project matches
    if product.project_id != query.project_id {
        return Err(AppError::NotFound("License key not found".into()));
    }

    // Get all devices for this license
    let devices = queries::list_devices_for_license(&conn, &license.id)?;

    let device_infos: Vec<DeviceInfo> = devices
        .into_iter()
        .map(|d| DeviceInfo {
            device_id: d.device_id,
            device_type: match d.device_type {
                crate::models::DeviceType::Uuid => "uuid".to_string(),
                crate::models::DeviceType::Machine => "machine".to_string(),
            },
            name: d.name,
            activated_at: d.activated_at,
            last_seen_at: d.last_seen_at,
        })
        .collect();

    Ok(Json(DevicesResponse {
        devices: device_infos,
        device_limit: product.device_limit,
    }))
}

#[derive(Debug, Deserialize)]
pub struct DeactivateRequest {
    pub project_id: String,
    pub key: String,
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct DeactivateResponse {
    pub deactivated: bool,
    pub remaining_devices: i32,
}

pub async fn deactivate_device(
    State(pool): State<DbPool>,
    Json(request): Json<DeactivateRequest>,
) -> Result<Json<DeactivateResponse>> {
    let conn = pool.get()?;

    // Get the license key
    let license = queries::get_license_key_by_key(&conn, &request.key)?
        .ok_or_else(|| AppError::NotFound("License key not found".into()))?;

    // Get the product to verify project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Verify project matches
    if product.project_id != request.project_id {
        return Err(AppError::NotFound("License key not found".into()));
    }

    // Find and delete the device
    let device = queries::get_device_for_license(&conn, &license.id, &request.device_id)?
        .ok_or_else(|| AppError::NotFound("Device not found".into()))?;

    // Add the device's JTI to revoked list so it can't be used anymore
    queries::add_revoked_jti(&conn, &license.id, &device.jti)?;

    // Delete the device
    queries::delete_device_by_device_id(&conn, &license.id, &request.device_id)?;

    // Get remaining device count
    let remaining = queries::count_devices_for_license(&conn, &license.id)?;

    Ok(Json(DeactivateResponse {
        deactivated: true,
        remaining_devices: remaining,
    }))
}
