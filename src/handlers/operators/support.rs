//! Operator support endpoints for debugging customer issues.

use axum::extract::State;
use serde::Serialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::models::{LemonSqueezyConfig, StripeConfig};

#[derive(Debug, Serialize)]
pub struct FullPaymentConfigResponse {
    pub project_id: String,
    pub org_id: String,
    pub project_name: String,
    pub stripe_config: Option<StripeConfig>,
    pub ls_config: Option<LemonSqueezyConfig>,
}

/// Get full (unmasked) payment provider configuration for a project.
/// This is for operator support staff to debug customer payment issues.
pub async fn get_project_payment_config(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
) -> Result<Json<FullPaymentConfigResponse>> {
    let conn = state.db.get()?;

    let project = queries::get_project_by_id(&conn, &project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    let stripe_config = project.decrypt_stripe_config(&state.master_key)?;
    let ls_config = project.decrypt_ls_config(&state.master_key)?;

    tracing::info!(
        "OPERATOR: Retrieved payment config for project {} ({})",
        project.name,
        project_id
    );

    Ok(Json(FullPaymentConfigResponse {
        project_id,
        org_id: project.org_id,
        project_name: project.name,
        stripe_config,
        ls_config,
    }))
}
