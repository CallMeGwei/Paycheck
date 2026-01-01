//! Operator support endpoints for debugging customer issues.

use axum::extract::State;
use serde::Serialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::models::{LemonSqueezyConfig, StripeConfig};

#[derive(Debug, Serialize)]
pub struct FullPaymentConfigResponse {
    pub org_id: String,
    pub org_name: String,
    pub stripe_config: Option<StripeConfig>,
    pub ls_config: Option<LemonSqueezyConfig>,
}

/// Get full (unmasked) payment provider configuration for an organization.
/// This is for operator support staff to debug customer payment issues.
pub async fn get_org_payment_config(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Result<Json<FullPaymentConfigResponse>> {
    let conn = state.db.get()?;

    let org = queries::get_organization_by_id(&conn, &org_id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    let stripe_config = org.decrypt_stripe_config(&state.master_key)?;
    let ls_config = org.decrypt_ls_config(&state.master_key)?;

    tracing::info!(
        "OPERATOR: Retrieved payment config for organization {} ({})",
        org.name,
        org_id
    );

    Ok(Json(FullPaymentConfigResponse {
        org_id,
        org_name: org.name,
        stripe_config,
        ls_config,
    }))
}
