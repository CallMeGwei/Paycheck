//! Authorization and permission tests for all protected API endpoints.
//!
//! These tests verify that:
//! 1. Missing/invalid tokens return 401 Unauthorized
//! 2. Role-based access control is enforced (403 Forbidden)
//! 3. Cross-org and cross-project access is blocked
//! 4. Project-level permissions (can_write_project) work correctly

#[path = "auth/helpers.rs"]
mod helpers;

#[path = "auth/operators.rs"]
mod operator_auth;

#[path = "auth/org_members.rs"]
mod org_member_auth;

#[path = "auth/project_permissions.rs"]
mod project_permissions;

#[path = "auth/cross_project.rs"]
mod cross_project_boundaries;

#[path = "auth/license_permissions.rs"]
mod license_permissions;

#[path = "auth/device_permissions.rs"]
mod device_permissions;

#[path = "auth/project_members.rs"]
mod project_member_management;

#[path = "auth/audit_isolation.rs"]
mod org_audit_log_isolation;

#[path = "auth/impersonation.rs"]
mod operator_impersonation;
