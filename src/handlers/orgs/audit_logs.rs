use axum::extract::State;

use crate::db::{AppState, queries};
use crate::error::Result;
use crate::extractors::{Json, Path, Query};
use crate::models::{AuditLog, AuditLogQuery};

/// Query audit logs scoped to the authenticated org.
/// The org_id from the path is always enforced - query params cannot override it.
pub async fn query_org_audit_logs(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Query(mut query): Query<AuditLogQuery>,
) -> Result<Json<Vec<AuditLog>>> {
    // Force org_id from path - ignore any org_id in query params
    query.org_id = Some(org_id);

    let conn = state.audit.get()?;
    let logs = queries::query_audit_logs(&conn, &query)?;
    Ok(Json(logs))
}
