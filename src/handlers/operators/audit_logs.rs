use axum::extract::State;

use crate::db::{AppState, queries};
use crate::error::Result;
use crate::extractors::{Json, Query};
use crate::models::{AuditLog, AuditLogQuery};

pub async fn query_audit_logs(
    State(state): State<AppState>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<Vec<AuditLog>>> {
    let conn = state.audit.get()?;
    let logs = queries::query_audit_logs(&conn, &query)?;
    Ok(Json(logs))
}
