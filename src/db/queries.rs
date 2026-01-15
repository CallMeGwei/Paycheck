use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params, types::Value};
use uuid::Uuid;

use crate::crypto::{MasterKey, hash_secret};
use crate::error::{AppError, Result};
use crate::models::*;

use super::from_row::{
    ACTIVATION_CODE_COLS, API_KEY_COLS, API_KEY_SCOPE_COLS, DEVICE_COLS, LICENSE_COLS,
    OPERATOR_COLS, OPERATOR_WITH_USER_COLS, ORG_MEMBER_COLS, ORG_MEMBER_WITH_USER_COLS,
    ORGANIZATION_COLS, PAYMENT_CONFIG_COLS, PAYMENT_SESSION_COLS, PRODUCT_COLS, PROJECT_COLS,
    PROJECT_MEMBER_COLS, USER_COLS, query_all, query_one,
};

fn now() -> i64 {
    Utc::now().timestamp()
}

fn gen_id() -> String {
    Uuid::new_v4().to_string()
}

/// Builder for dynamic UPDATE statements with optional fields.
/// Combines multiple field updates into a single query for efficiency.
struct UpdateBuilder {
    table: &'static str,
    id: String,
    fields: Vec<(&'static str, Value)>,
    track_updated_at: bool,
}

impl UpdateBuilder {
    fn new(table: &'static str, id: &str) -> Self {
        Self {
            table,
            id: id.to_string(),
            fields: Vec::new(),
            track_updated_at: false,
        }
    }

    fn with_updated_at(mut self) -> Self {
        self.track_updated_at = true;
        self
    }

    fn set(mut self, column: &'static str, value: impl Into<Value>) -> Self {
        self.fields.push((column, value.into()));
        self
    }

    fn set_opt<V: Into<Value>>(self, column: &'static str, value: Option<V>) -> Self {
        match value {
            Some(v) => self.set(column, v),
            None => self,
        }
    }

    /// Set a column to an explicit value (including NULL).
    /// Use this for Option<T> where Some(v) = set to v, None = set to NULL.
    fn set_nullable<V: Into<Value>>(mut self, column: &'static str, value: Option<V>) -> Self {
        match value {
            Some(v) => self.fields.push((column, v.into())),
            None => self.fields.push((column, Value::Null)),
        }
        self
    }

    fn execute(mut self, conn: &Connection) -> Result<bool> {
        if self.fields.is_empty() {
            return Ok(false);
        }
        if self.track_updated_at {
            self.fields.push(("updated_at", now().into()));
        }
        let sets: Vec<String> = self
            .fields
            .iter()
            .map(|(col, _)| format!("{} = ?", col))
            .collect();
        let mut values: Vec<Value> = self.fields.into_iter().map(|(_, v)| v).collect();
        values.push(self.id.into());
        let sql = format!("UPDATE {} SET {} WHERE id = ?", self.table, sets.join(", "));
        let affected = conn.execute(&sql, rusqlite::params_from_iter(values))?;
        Ok(affected > 0)
    }
}

// ============ Users ============

/// Create a user.
pub fn create_user(conn: &Connection, input: &CreateUser) -> Result<User> {
    let id = gen_id();
    let now = now();
    let email = input.email.trim().to_lowercase();

    conn.execute(
        "INSERT INTO users (id, email, name, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![&id, &email, &input.name, now, now],
    )?;

    Ok(User {
        id,
        email,
        name: input.name.clone(),
        created_at: now,
        updated_at: now,
        deleted_at: None,
        deleted_cascade_depth: None,
    })
}

pub fn get_user_by_id(conn: &Connection, id: &str) -> Result<Option<User>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM users WHERE id = ?1 AND deleted_at IS NULL",
            USER_COLS
        ),
        &[&id],
    )
}

pub fn get_user_by_email(conn: &Connection, email: &str) -> Result<Option<User>> {
    let email = email.trim().to_lowercase();
    query_one(
        conn,
        &format!(
            "SELECT {} FROM users WHERE email = ?1 AND deleted_at IS NULL",
            USER_COLS
        ),
        &[&email],
    )
}

pub fn list_users(conn: &Connection) -> Result<Vec<User>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC",
            USER_COLS
        ),
        &[],
    )
}

pub fn list_users_paginated(
    conn: &Connection,
    limit: i64,
    offset: i64,
    include_deleted: bool,
) -> Result<(Vec<User>, i64)> {
    let deleted_filter = if include_deleted {
        ""
    } else {
        "WHERE deleted_at IS NULL"
    };
    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM users {}", deleted_filter),
        [],
        |row| row.get(0),
    )?;
    let items = query_all(
        conn,
        &format!(
            "SELECT {} FROM users {} ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
            USER_COLS, deleted_filter
        ),
        params![limit, offset],
    )?;
    Ok((items, total))
}

pub fn update_user(conn: &Connection, id: &str, input: &UpdateUser) -> Result<bool> {
    let email = input.email.as_ref().map(|e| e.trim().to_lowercase());
    UpdateBuilder::new("users", id)
        .with_updated_at()
        .set_opt("email", email)
        .set_opt("name", input.name.clone())
        .execute(conn)
}

pub fn delete_user(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

/// Soft delete a user and cascade to operators and org_members.
/// Returns true if the user was found and soft deleted.
pub fn soft_delete_user(conn: &Connection, id: &str) -> Result<bool> {
    use super::soft_delete::{cascade_delete_direct, soft_delete_entity};

    let result = soft_delete_entity(conn, "users", id)?;
    if !result.deleted {
        return Ok(false);
    }

    // Cascade to operators and org_members (depth 1)
    // Note: project_members will be orphaned but that's OK
    cascade_delete_direct(conn, "operators", "user_id", id, result.deleted_at, 1)?;
    cascade_delete_direct(conn, "org_members", "user_id", id, result.deleted_at, 1)?;

    Ok(true)
}

/// Get a soft-deleted user by ID (for restore operations).
pub fn get_deleted_user_by_id(conn: &Connection, id: &str) -> Result<Option<User>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM users WHERE id = ?1 AND deleted_at IS NOT NULL",
            USER_COLS
        ),
        &[&id],
    )
}

/// Restore a soft-deleted user and optionally cascade to children.
/// Returns Err if depth > 0 and force=false (was cascaded from parent).
/// If force=true or depth=0, restores user and all cascaded children.
pub fn restore_user(conn: &Connection, id: &str, force: bool) -> Result<bool> {
    use super::soft_delete::{check_restore_allowed, restore_cascaded_direct, restore_entity};

    let Some(user) = get_deleted_user_by_id(conn, id)? else {
        return Ok(false);
    };

    check_restore_allowed(user.deleted_cascade_depth, force, "User")?;

    let deleted_at = user.deleted_at.unwrap();

    // Restore cascaded children first (operators, org_members)
    restore_cascaded_direct(conn, "operators", "user_id", id, deleted_at)?;
    restore_cascaded_direct(conn, "org_members", "user_id", id, deleted_at)?;

    // Restore the user
    restore_entity(conn, "users", id)?;

    Ok(true)
}

/// Get a user with their operator role and org memberships.
pub fn get_user_with_roles(conn: &Connection, id: &str) -> Result<Option<UserWithRoles>> {
    // Get the base user
    let user: Option<User> = query_one(
        conn,
        &format!("SELECT {} FROM users WHERE id = ?1", USER_COLS),
        &[&id],
    )?;

    let Some(user) = user else {
        return Ok(None);
    };

    // Get operator role if any
    let operator: Option<Operator> = query_one(
        conn,
        &format!("SELECT {} FROM operators WHERE user_id = ?1", OPERATOR_COLS),
        &[&id],
    )?;

    // Get org memberships with org names
    let memberships: Vec<(String, String, String, OrgMemberRole)> = {
        let mut stmt = conn.prepare(
            "SELECT m.id, m.org_id, o.name, m.role
             FROM org_members m
             JOIN organizations o ON o.id = m.org_id
             WHERE m.user_id = ?1
             ORDER BY o.name",
        )?;
        stmt.query_map([&id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get::<_, String>(3)?.parse().unwrap(),
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };

    Ok(Some(UserWithRoles {
        id: user.id,
        email: user.email,
        name: user.name,
        created_at: user.created_at,
        updated_at: user.updated_at,
        operator: operator.map(|o| UserOperatorRole {
            id: o.id,
            role: o.role,
        }),
        memberships: memberships
            .into_iter()
            .map(|(id, org_id, org_name, role)| UserOrgMembership {
                id,
                org_id,
                org_name,
                role,
            })
            .collect(),
    }))
}

/// List users with their roles, paginated.
pub fn list_users_with_roles_paginated(
    conn: &Connection,
    limit: i64,
    offset: i64,
    include_deleted: bool,
) -> Result<(Vec<UserWithRoles>, i64)> {
    let deleted_filter = if include_deleted {
        ""
    } else {
        "WHERE deleted_at IS NULL"
    };
    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM users {}", deleted_filter),
        [],
        |row| row.get(0),
    )?;

    let users: Vec<User> = query_all(
        conn,
        &format!(
            "SELECT {} FROM users {} ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
            USER_COLS, deleted_filter
        ),
        params![limit, offset],
    )?;

    // For each user, fetch their roles
    let mut results = Vec::with_capacity(users.len());
    for user in users {
        // Get operator role if any
        let operator: Option<Operator> = query_one(
            conn,
            &format!("SELECT {} FROM operators WHERE user_id = ?1", OPERATOR_COLS),
            &[&user.id],
        )?;

        // Get org memberships with org names
        let memberships: Vec<(String, String, String, OrgMemberRole)> = {
            let mut stmt = conn.prepare(
                "SELECT m.id, m.org_id, o.name, m.role
                 FROM org_members m
                 JOIN organizations o ON o.id = m.org_id
                 WHERE m.user_id = ?1
                 ORDER BY o.name",
            )?;
            stmt.query_map([&user.id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get::<_, String>(3)?.parse().unwrap(),
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };

        results.push(UserWithRoles {
            id: user.id,
            email: user.email,
            name: user.name,
            created_at: user.created_at,
            updated_at: user.updated_at,
            operator: operator.map(|o| UserOperatorRole {
                id: o.id,
                role: o.role,
            }),
            memberships: memberships
                .into_iter()
                .map(|(id, org_id, org_name, role)| UserOrgMembership {
                    id,
                    org_id,
                    org_name,
                    role,
                })
                .collect(),
        });
    }

    Ok((results, total))
}

// ============ Operators ============

/// Create an operator (user must already exist).
pub fn create_operator(conn: &Connection, input: &CreateOperator) -> Result<Operator> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO operators (id, user_id, role, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![&id, &input.user_id, input.role.as_ref(), now],
    )?;

    Ok(Operator {
        id,
        user_id: input.user_id.clone(),
        role: input.role,
        created_at: now,
        deleted_at: None,
        deleted_cascade_depth: None,
    })
}

pub fn get_operator_by_id(conn: &Connection, id: &str) -> Result<Option<Operator>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM operators WHERE id = ?1 AND deleted_at IS NULL",
            OPERATOR_COLS
        ),
        &[&id],
    )
}

pub fn get_operator_with_user_by_id(
    conn: &Connection,
    id: &str,
) -> Result<Option<OperatorWithUser>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM operators o JOIN users u ON o.user_id = u.id WHERE o.id = ?1 AND o.deleted_at IS NULL AND u.deleted_at IS NULL",
            OPERATOR_WITH_USER_COLS
        ),
        &[&id],
    )
}

pub fn get_operator_by_user_id(conn: &Connection, user_id: &str) -> Result<Option<Operator>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM operators WHERE user_id = ?1 AND deleted_at IS NULL",
            OPERATOR_COLS
        ),
        &[&user_id],
    )
}

pub fn get_operator_with_user_by_user_id(
    conn: &Connection,
    user_id: &str,
) -> Result<Option<OperatorWithUser>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM operators o JOIN users u ON o.user_id = u.id WHERE o.user_id = ?1 AND o.deleted_at IS NULL AND u.deleted_at IS NULL",
            OPERATOR_WITH_USER_COLS
        ),
        &[&user_id],
    )
}

pub fn list_operators(conn: &Connection) -> Result<Vec<OperatorWithUser>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM operators o JOIN users u ON o.user_id = u.id WHERE o.deleted_at IS NULL AND u.deleted_at IS NULL ORDER BY o.created_at DESC",
            OPERATOR_WITH_USER_COLS
        ),
        &[],
    )
}

pub fn list_operators_paginated(
    conn: &Connection,
    limit: i64,
    offset: i64,
) -> Result<(Vec<OperatorWithUser>, i64)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM operators WHERE deleted_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    let items = query_all(
        conn,
        &format!(
            "SELECT {} FROM operators o JOIN users u ON o.user_id = u.id WHERE o.deleted_at IS NULL AND u.deleted_at IS NULL ORDER BY o.created_at DESC LIMIT ?1 OFFSET ?2",
            OPERATOR_WITH_USER_COLS
        ),
        params![limit, offset],
    )?;
    Ok((items, total))
}

pub fn update_operator(conn: &Connection, id: &str, input: &UpdateOperator) -> Result<()> {
    UpdateBuilder::new("operators", id)
        .set_opt("role", input.role.map(|r| r.as_ref().to_string()))
        .execute(conn)?;
    Ok(())
}

pub fn delete_operator(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM operators WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

/// Soft delete an operator. No cascade needed (leaf entity).
pub fn soft_delete_operator(conn: &Connection, id: &str) -> Result<bool> {
    use super::soft_delete::soft_delete_entity;
    Ok(soft_delete_entity(conn, "operators", id)?.deleted)
}

/// Get a soft-deleted operator by ID (for restore operations).
pub fn get_deleted_operator_by_id(conn: &Connection, id: &str) -> Result<Option<Operator>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM operators WHERE id = ?1 AND deleted_at IS NOT NULL",
            OPERATOR_COLS
        ),
        &[&id],
    )
}

/// Restore a soft-deleted operator.
/// Returns Err if depth > 0 and force=false (was cascaded from user delete).
pub fn restore_operator(conn: &Connection, id: &str, force: bool) -> Result<bool> {
    use super::soft_delete::{check_restore_allowed, restore_entity};

    let Some(operator) = get_deleted_operator_by_id(conn, id)? else {
        return Ok(false);
    };

    check_restore_allowed(operator.deleted_cascade_depth, force, "Operator")?;
    restore_entity(conn, "operators", id)?;

    Ok(true)
}

pub fn count_operators(conn: &Connection) -> Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM operators", [], |row| row.get(0))
        .map_err(Into::into)
}

// ============ API Keys (Unified) ============

/// Generate an API key with pc_ prefix
pub fn generate_api_key() -> String {
    format!("pc_{}", Uuid::new_v4().to_string().replace("-", ""))
}

/// Get user by API key. Returns the user and key info if found and valid.
pub fn get_user_by_api_key(conn: &Connection, api_key: &str) -> Result<Option<(User, ApiKey)>> {
    let hash = hash_secret(api_key);

    let key: Option<ApiKey> = query_one(
        conn,
        &format!(
            "SELECT {} FROM api_keys WHERE key_hash = ?1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > unixepoch())",
            API_KEY_COLS
        ),
        &[&hash],
    )?;

    if let Some(key) = key {
        // Update last_used_at (fire and forget)
        let _ = conn.execute(
            "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
            params![now(), &key.id],
        );

        // Get the user
        if let Some(user) = get_user_by_id(conn, &key.user_id)? {
            return Ok(Some((user, key)));
        }
    }

    Ok(None)
}

/// Create an API key for a user
pub fn create_api_key(
    conn: &Connection,
    user_id: &str,
    name: &str,
    expires_in_days: Option<i64>,
    user_manageable: bool,
    scopes: Option<&[CreateApiKeyScope]>,
) -> Result<(ApiKey, String)> {
    // Validate all scopes BEFORE creating anything
    if let Some(scopes) = scopes {
        for scope in scopes {
            // Validate that org exists
            let org_exists: bool = conn
                .query_row(
                    "SELECT 1 FROM organizations WHERE id = ?1 AND deleted_at IS NULL",
                    params![&scope.org_id],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);

            if !org_exists {
                return Err(AppError::BadRequest(
                    "Invalid scope: organization not found".into(),
                ));
            }

            // Validate that project belongs to org (if project_id is specified)
            if let Some(ref project_id) = scope.project_id {
                let project_org_id: Option<String> = conn
                    .query_row(
                        "SELECT org_id FROM projects WHERE id = ?1 AND deleted_at IS NULL",
                        params![project_id],
                        |row| row.get(0),
                    )
                    .optional()?;

                match project_org_id {
                    None => {
                        return Err(AppError::BadRequest(
                            "Invalid scope: project not found".into(),
                        ));
                    }
                    Some(org_id) if org_id != scope.org_id => {
                        return Err(AppError::BadRequest(
                            "Invalid scope: project does not belong to the specified organization".into(),
                        ));
                    }
                    _ => {} // Valid: project exists and belongs to the org
                }
            }
        }
    }

    let id = gen_id();
    let now = now();
    let key = generate_api_key();
    let prefix = &key[..8];
    let key_hash = hash_secret(&key);
    let expires_at = expires_in_days.map(|days| now + days * 86400);

    conn.execute(
        "INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, user_manageable, created_at, last_used_at, expires_at, revoked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, NULL)",
        params![&id, user_id, name, prefix, &key_hash, user_manageable as i32, now, expires_at],
    )?;

    // Insert scopes (already validated above)
    if let Some(scopes) = scopes {
        for scope in scopes {
            let scope_id = gen_id();
            conn.execute(
                "INSERT INTO api_key_scopes (id, api_key_id, org_id, project_id, access)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &scope_id,
                    &id,
                    &scope.org_id,
                    &scope.project_id,
                    scope.access.as_ref()
                ],
            )?;
        }
    }

    Ok((
        ApiKey {
            id,
            user_id: user_id.to_string(),
            name: name.to_string(),
            prefix: prefix.to_string(),
            key_hash,
            user_manageable,
            created_at: now,
            last_used_at: None,
            expires_at,
            revoked_at: None,
        },
        key,
    ))
}

/// List API keys for a user (active only, excludes revoked)
/// If user_manageable_only is true, only returns user-manageable keys
pub fn list_api_keys(
    conn: &Connection,
    user_id: &str,
    user_manageable_only: bool,
) -> Result<Vec<ApiKey>> {
    if user_manageable_only {
        query_all(
            conn,
            &format!(
                "SELECT {} FROM api_keys WHERE user_id = ?1 AND user_manageable = 1 AND revoked_at IS NULL ORDER BY created_at DESC",
                API_KEY_COLS
            ),
            &[&user_id],
        )
    } else {
        query_all(
            conn,
            &format!(
                "SELECT {} FROM api_keys WHERE user_id = ?1 AND revoked_at IS NULL ORDER BY created_at DESC",
                API_KEY_COLS
            ),
            &[&user_id],
        )
    }
}

pub fn list_api_keys_paginated(
    conn: &Connection,
    user_id: &str,
    user_manageable_only: bool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ApiKey>, i64)> {
    let (count_sql, list_sql) = if user_manageable_only {
        (
            "SELECT COUNT(*) FROM api_keys WHERE user_id = ?1 AND user_manageable = 1 AND revoked_at IS NULL",
            format!(
                "SELECT {} FROM api_keys WHERE user_id = ?1 AND user_manageable = 1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
                API_KEY_COLS
            ),
        )
    } else {
        (
            "SELECT COUNT(*) FROM api_keys WHERE user_id = ?1 AND revoked_at IS NULL",
            format!(
                "SELECT {} FROM api_keys WHERE user_id = ?1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
                API_KEY_COLS
            ),
        )
    };

    let total: i64 = conn.query_row(count_sql, params![user_id], |row| row.get(0))?;
    let keys = query_all(conn, &list_sql, params![user_id, limit, offset])?;
    Ok((keys, total))
}

/// Get an API key by ID
pub fn get_api_key_by_id(conn: &Connection, key_id: &str) -> Result<Option<ApiKey>> {
    query_one(
        conn,
        &format!("SELECT {} FROM api_keys WHERE id = ?1", API_KEY_COLS),
        &[&key_id],
    )
}

/// Get scopes for an API key
pub fn get_api_key_scopes(conn: &Connection, key_id: &str) -> Result<Vec<ApiKeyScope>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM api_key_scopes WHERE api_key_id = ?1",
            API_KEY_SCOPE_COLS
        ),
        &[&key_id],
    )
}

/// Get scopes for multiple API keys in a single query (fixes N+1).
/// Returns a map of key_id -> Vec<ApiKeyScope>.
pub fn get_api_key_scopes_batch(
    conn: &Connection,
    key_ids: &[String],
) -> Result<std::collections::HashMap<String, Vec<ApiKeyScope>>> {
    use std::collections::HashMap;

    if key_ids.is_empty() {
        return Ok(HashMap::new());
    }

    // Build placeholders: ?1, ?2, ?3, ...
    let placeholders: Vec<String> = (1..=key_ids.len()).map(|i| format!("?{}", i)).collect();
    let sql = format!(
        "SELECT {} FROM api_key_scopes WHERE api_key_id IN ({})",
        API_KEY_SCOPE_COLS,
        placeholders.join(", ")
    );

    // Convert to params
    let params: Vec<&dyn rusqlite::ToSql> =
        key_ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    let scopes: Vec<ApiKeyScope> = query_all(conn, &sql, params.as_slice())?;

    // Group by key_id
    let mut result: HashMap<String, Vec<ApiKeyScope>> = HashMap::new();
    for scope in scopes {
        result
            .entry(scope.api_key_id.clone())
            .or_default()
            .push(scope);
    }

    Ok(result)
}

/// Revoke an API key (soft delete)
pub fn revoke_api_key(conn: &Connection, key_id: &str) -> Result<bool> {
    let now = now();
    let affected = conn.execute(
        "UPDATE api_keys SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
        params![now, key_id],
    )?;
    Ok(affected > 0)
}

/// Check if an API key has any scopes defined
pub fn api_key_has_scopes(conn: &Connection, key_id: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM api_key_scopes WHERE api_key_id = ?1",
        params![key_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Get the access level for an API key on a specific org/project.
/// Returns the access level if allowed, None if no matching scope.
pub fn get_api_key_access_level(
    conn: &Connection,
    key_id: &str,
    org_id: &str,
    project_id: Option<&str>,
) -> Result<Option<AccessLevel>> {
    // Check for matching scope
    // First try exact project match, then org-wide match (project_id IS NULL)
    let scope: Option<ApiKeyScope> = if let Some(proj_id) = project_id {
        // Try exact project match first
        let exact: Option<ApiKeyScope> = query_one(
            conn,
            &format!(
                "SELECT {} FROM api_key_scopes WHERE api_key_id = ?1 AND org_id = ?2 AND project_id = ?3",
                API_KEY_SCOPE_COLS
            ),
            params![key_id, org_id, proj_id],
        )?;

        if exact.is_some() {
            exact
        } else {
            // Fall back to org-wide scope
            query_one(
                conn,
                &format!(
                    "SELECT {} FROM api_key_scopes WHERE api_key_id = ?1 AND org_id = ?2 AND project_id IS NULL",
                    API_KEY_SCOPE_COLS
                ),
                params![key_id, org_id],
            )?
        }
    } else {
        // Just check org-level access
        query_one(
            conn,
            &format!(
                "SELECT {} FROM api_key_scopes WHERE api_key_id = ?1 AND org_id = ?2",
                API_KEY_SCOPE_COLS
            ),
            params![key_id, org_id],
        )?
    };

    Ok(scope.map(|s| s.access))
}

/// Check if an API key has at least the required access level for an org/project.
/// Returns true if access is granted, false otherwise.
pub fn check_api_key_scope(
    conn: &Connection,
    key_id: &str,
    org_id: &str,
    project_id: Option<&str>,
    required_access: AccessLevel,
) -> Result<bool> {
    let access_level = get_api_key_access_level(conn, key_id, org_id, project_id)?;

    match access_level {
        Some(AccessLevel::Admin) => Ok(true), // Admin has all access
        Some(AccessLevel::View) => Ok(required_access == AccessLevel::View), // View only has view access
        None => Ok(false),                                                   // No scope = no access
    }
}

/// Check if an API key has org-level access (not just project-level).
/// Returns the access level if the key has an org-wide scope (project_id IS NULL).
/// Returns None if the key only has project-specific scopes.
///
/// This is used for org-level endpoints (e.g., /orgs/{org_id}/members) where
/// a project-scoped key should NOT grant access.
pub fn get_api_key_org_level_access(
    conn: &Connection,
    key_id: &str,
    org_id: &str,
) -> Result<Option<AccessLevel>> {
    // Only check for org-level scopes (project_id IS NULL)
    let scope: Option<ApiKeyScope> = query_one(
        conn,
        &format!(
            "SELECT {} FROM api_key_scopes WHERE api_key_id = ?1 AND org_id = ?2 AND project_id IS NULL",
            API_KEY_SCOPE_COLS
        ),
        params![key_id, org_id],
    )?;

    Ok(scope.map(|s| s.access))
}

// ============ Audit Logs ============

#[allow(clippy::too_many_arguments)]
pub fn create_audit_log(
    conn: &Connection,
    enabled: bool,
    actor_type: ActorType,
    user_id: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    details: Option<&serde_json::Value>,
    org_id: Option<&str>,
    project_id: Option<&str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    names: &AuditLogNames,
    auth_type: Option<&str>,
    auth_credential: Option<&str>,
) -> Result<AuditLog> {
    let id = gen_id();
    let timestamp = now();

    // Skip database insert if audit logging is disabled
    if !enabled {
        return Ok(AuditLog {
            id,
            timestamp,
            actor_type,
            user_id: user_id.map(String::from),
            user_email: names.user_email.clone(),
            user_name: names.user_name.clone(),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
            resource_name: names.resource_name.clone(),
            resource_email: names.resource_email.clone(),
            details: details.cloned(),
            org_id: org_id.map(String::from),
            org_name: names.org_name.clone(),
            project_id: project_id.map(String::from),
            project_name: names.project_name.clone(),
            ip_address: ip_address.map(String::from),
            user_agent: user_agent.map(String::from),
            auth_type: auth_type.map(String::from),
            auth_credential: auth_credential.map(String::from),
        });
    }

    let details_str = details.map(|d| d.to_string());

    conn.execute(
        "INSERT INTO audit_logs (id, timestamp, actor_type, user_id, user_email, user_name, action, resource_type, resource_id, resource_name, resource_email, details, org_id, org_name, project_id, project_name, ip_address, user_agent, auth_type, auth_credential)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            &id,
            timestamp,
            actor_type.as_ref(),
            user_id,
            &names.user_email,
            &names.user_name,
            action,
            resource_type,
            resource_id,
            &names.resource_name,
            &names.resource_email,
            &details_str,
            org_id,
            &names.org_name,
            project_id,
            &names.project_name,
            ip_address,
            user_agent,
            auth_type,
            auth_credential
        ],
    )?;

    Ok(AuditLog {
        id,
        timestamp,
        actor_type,
        user_id: user_id.map(String::from),
        user_email: names.user_email.clone(),
        user_name: names.user_name.clone(),
        action: action.to_string(),
        resource_type: resource_type.to_string(),
        resource_id: resource_id.to_string(),
        resource_name: names.resource_name.clone(),
        resource_email: names.resource_email.clone(),
        details: details.cloned(),
        org_id: org_id.map(String::from),
        org_name: names.org_name.clone(),
        project_id: project_id.map(String::from),
        project_name: names.project_name.clone(),
        ip_address: ip_address.map(String::from),
        user_agent: user_agent.map(String::from),
        auth_type: auth_type.map(String::from),
        auth_credential: auth_credential.map(String::from),
    })
}

pub fn query_audit_logs(conn: &Connection, query: &AuditLogQuery) -> Result<(Vec<AuditLog>, i64)> {
    // Helper to build filter params (avoids duplication between COUNT and SELECT)
    let build_filter_params = || -> Vec<Box<dyn rusqlite::ToSql>> {
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(ref v) = query.actor_type {
            params.push(Box::new(v.as_ref().to_string()));
        }
        if let Some(ref v) = query.user_id {
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = query.action {
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = query.resource_type {
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = query.resource_id {
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = query.org_id {
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = query.project_id {
            params.push(Box::new(v.clone()));
        }
        if let Some(v) = query.from_timestamp {
            params.push(Box::new(v));
        }
        if let Some(v) = query.to_timestamp {
            params.push(Box::new(v));
        }
        if let Some(ref v) = query.auth_type {
            params.push(Box::new(v.clone()));
        }
        if let Some(ref v) = query.auth_credential {
            params.push(Box::new(v.clone()));
        }
        params
    };

    // Build WHERE clause
    let mut where_clause = String::from("WHERE 1=1");
    if query.actor_type.is_some() {
        where_clause.push_str(" AND actor_type = ?");
    }
    if query.user_id.is_some() {
        where_clause.push_str(" AND user_id = ?");
    }
    if query.action.is_some() {
        where_clause.push_str(" AND action = ?");
    }
    if query.resource_type.is_some() {
        where_clause.push_str(" AND resource_type = ?");
    }
    if query.resource_id.is_some() {
        where_clause.push_str(" AND resource_id = ?");
    }
    if query.org_id.is_some() {
        where_clause.push_str(" AND org_id = ?");
    }
    if query.project_id.is_some() {
        where_clause.push_str(" AND project_id = ?");
    }
    if query.from_timestamp.is_some() {
        where_clause.push_str(" AND timestamp >= ?");
    }
    if query.to_timestamp.is_some() {
        where_clause.push_str(" AND timestamp <= ?");
    }
    if query.auth_type.is_some() {
        where_clause.push_str(" AND auth_type = ?");
    }
    if query.auth_credential.is_some() {
        where_clause.push_str(" AND auth_credential = ?");
    }

    // Get total count
    let count_sql = format!("SELECT COUNT(*) FROM audit_logs {}", where_clause);
    let filter_params = build_filter_params();
    let filter_refs: Vec<&dyn rusqlite::ToSql> = filter_params.iter().map(|b| b.as_ref()).collect();
    let total: i64 = conn.query_row(&count_sql, filter_refs.as_slice(), |row| row.get(0))?;

    // Build SELECT query with pagination
    let limit = query.limit();
    let offset = query.offset();
    let select_sql = format!(
        "SELECT id, timestamp, actor_type, user_id, user_email, user_name, action, resource_type, resource_id, resource_name, resource_email, details, org_id, org_name, project_id, project_name, ip_address, user_agent, auth_type, auth_credential
         FROM audit_logs {} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        where_clause
    );

    // Reuse filter params and add pagination
    let mut select_params = build_filter_params();
    select_params.push(Box::new(limit));
    select_params.push(Box::new(offset));

    let mut stmt = conn.prepare(&select_sql)?;
    let select_refs: Vec<&dyn rusqlite::ToSql> = select_params.iter().map(|b| b.as_ref()).collect();

    let logs = stmt
        .query_map(select_refs.as_slice(), |row| {
            let details_str: Option<String> = row.get(11)?;
            Ok(AuditLog {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                actor_type: row.get::<_, String>(2)?.parse::<ActorType>().unwrap(),
                user_id: row.get(3)?,
                user_email: row.get(4)?,
                user_name: row.get(5)?,
                action: row.get(6)?,
                resource_type: row.get(7)?,
                resource_id: row.get(8)?,
                resource_name: row.get(9)?,
                resource_email: row.get(10)?,
                details: details_str.and_then(|s| serde_json::from_str(&s).ok()),
                org_id: row.get(12)?,
                org_name: row.get(13)?,
                project_id: row.get(14)?,
                project_name: row.get(15)?,
                ip_address: row.get(16)?,
                user_agent: row.get(17)?,
                auth_type: row.get(18)?,
                auth_credential: row.get(19)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok((logs, total))
}

// ============ Organizations ============

pub fn create_organization(conn: &Connection, input: &CreateOrganization) -> Result<Organization> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO organizations (id, name, stripe_config, ls_config, resend_api_key, payment_provider, created_at, updated_at)
         VALUES (?1, ?2, NULL, NULL, NULL, NULL, ?3, ?4)",
        params![&id, &input.name, now, now],
    )?;

    Ok(Organization {
        id,
        name: input.name.clone(),
        stripe_config_encrypted: None,
        ls_config_encrypted: None,
        resend_api_key_encrypted: None,
        payment_provider: None,
        created_at: now,
        updated_at: now,
        deleted_at: None,
        deleted_cascade_depth: None,
    })
}

pub fn get_organization_by_id(conn: &Connection, id: &str) -> Result<Option<Organization>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM organizations WHERE id = ?1 AND deleted_at IS NULL",
            ORGANIZATION_COLS
        ),
        &[&id],
    )
}

pub fn list_organizations(conn: &Connection) -> Result<Vec<Organization>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM organizations WHERE deleted_at IS NULL ORDER BY created_at DESC",
            ORGANIZATION_COLS
        ),
        &[],
    )
}

/// List organizations with pagination
pub fn list_organizations_paginated(
    conn: &Connection,
    limit: i64,
    offset: i64,
    include_deleted: bool,
) -> Result<(Vec<Organization>, i64)> {
    let deleted_filter = if include_deleted {
        ""
    } else {
        "WHERE deleted_at IS NULL"
    };
    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM organizations {}", deleted_filter),
        [],
        |row| row.get(0),
    )?;

    let items = query_all(
        conn,
        &format!(
            "SELECT {} FROM organizations {} ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
            ORGANIZATION_COLS, deleted_filter
        ),
        params![limit, offset],
    )?;

    Ok((items, total))
}

pub fn update_organization(
    conn: &Connection,
    id: &str,
    input: &UpdateOrganization,
    master_key: &MasterKey,
) -> Result<bool> {
    let now = now();
    let mut updated = false;

    if let Some(ref name) = input.name {
        conn.execute(
            "UPDATE organizations SET name = ?1, updated_at = ?2 WHERE id = ?3",
            params![name, now, id],
        )?;
        updated = true;
    }
    if let Some(ref stripe_config) = input.stripe_config {
        // Serialize to JSON and encrypt
        let json = serde_json::to_string(stripe_config)?;
        let encrypted = master_key.encrypt_private_key(id, json.as_bytes())?;
        conn.execute(
            "UPDATE organizations SET stripe_config = ?1, updated_at = ?2 WHERE id = ?3",
            params![encrypted, now, id],
        )?;
        updated = true;
    }
    if let Some(ref ls_config) = input.ls_config {
        // Serialize to JSON and encrypt
        let json = serde_json::to_string(ls_config)?;
        let encrypted = master_key.encrypt_private_key(id, json.as_bytes())?;
        conn.execute(
            "UPDATE organizations SET ls_config = ?1, updated_at = ?2 WHERE id = ?3",
            params![encrypted, now, id],
        )?;
        updated = true;
    }
    if let Some(ref resend_api_key) = input.resend_api_key {
        // Some(None) clears the value (fallback to system default), Some(Some(value)) sets it
        let encrypted: Option<Vec<u8>> = resend_api_key
            .as_ref()
            .map(|key| master_key.encrypt_private_key(id, key.as_bytes()))
            .transpose()?;
        conn.execute(
            "UPDATE organizations SET resend_api_key = ?1, updated_at = ?2 WHERE id = ?3",
            params![encrypted, now, id],
        )?;
        updated = true;
    }
    if let Some(ref payment_provider) = input.payment_provider {
        // Some(None) clears the value, Some(Some(value)) sets it
        conn.execute(
            "UPDATE organizations SET payment_provider = ?1, updated_at = ?2 WHERE id = ?3",
            params![payment_provider, now, id],
        )?;
        updated = true;
    }
    Ok(updated)
}

/// Update an organization's encrypted configs (for migration/rotation)
pub fn update_organization_encrypted_configs(
    conn: &Connection,
    id: &str,
    stripe_config: Option<&[u8]>,
    ls_config: Option<&[u8]>,
    resend_api_key: Option<&[u8]>,
) -> Result<()> {
    conn.execute(
        "UPDATE organizations SET stripe_config = ?1, ls_config = ?2, resend_api_key = ?3, updated_at = ?4 WHERE id = ?5",
        params![stripe_config, ls_config, resend_api_key, now(), id],
    )?;
    Ok(())
}

pub fn delete_organization(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM organizations WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

/// Soft delete an organization and cascade to all children.
/// Cascade: org_members (depth 1), projects (depth 1), products (depth 2), licenses (depth 3)
pub fn soft_delete_organization(conn: &Connection, id: &str) -> Result<bool> {
    use super::soft_delete::{
        PROJECTS_IN_ORG_DELETE_SUBQUERY, cascade_delete_direct, cascade_delete_via_subquery,
        soft_delete_entity,
    };

    let result = soft_delete_entity(conn, "organizations", id)?;
    if !result.deleted {
        return Ok(false);
    }

    // Direct children (depth 1)
    cascade_delete_direct(conn, "org_members", "org_id", id, result.deleted_at, 1)?;
    cascade_delete_direct(conn, "projects", "org_id", id, result.deleted_at, 1)?;

    // Transitive children via projects (depth 2, 3)
    cascade_delete_via_subquery(
        conn,
        "products",
        "project_id",
        PROJECTS_IN_ORG_DELETE_SUBQUERY,
        id,
        result.deleted_at,
        2,
    )?;
    cascade_delete_via_subquery(
        conn,
        "licenses",
        "project_id",
        PROJECTS_IN_ORG_DELETE_SUBQUERY,
        id,
        result.deleted_at,
        3,
    )?;

    Ok(true)
}

/// Get a soft-deleted organization by ID (for restore operations).
pub fn get_deleted_organization_by_id(conn: &Connection, id: &str) -> Result<Option<Organization>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM organizations WHERE id = ?1 AND deleted_at IS NOT NULL",
            ORGANIZATION_COLS
        ),
        &[&id],
    )
}

/// Restore a soft-deleted organization and all cascaded children.
/// Organizations are always directly deleted (depth=0), so no cascade check needed.
pub fn restore_organization(conn: &Connection, id: &str) -> Result<bool> {
    use super::soft_delete::{
        PROJECTS_IN_ORG_RESTORE_SUBQUERY, restore_cascaded_direct, restore_cascaded_via_subquery,
        restore_entity,
    };

    let Some(org) = get_deleted_organization_by_id(conn, id)? else {
        return Ok(false);
    };

    let deleted_at = org.deleted_at.unwrap();

    // Restore in reverse order: deepest children first
    restore_cascaded_via_subquery(
        conn,
        "licenses",
        "project_id",
        PROJECTS_IN_ORG_RESTORE_SUBQUERY,
        id,
        deleted_at,
    )?;
    restore_cascaded_via_subquery(
        conn,
        "products",
        "project_id",
        PROJECTS_IN_ORG_RESTORE_SUBQUERY,
        id,
        deleted_at,
    )?;
    restore_cascaded_direct(conn, "projects", "org_id", id, deleted_at)?;
    restore_cascaded_direct(conn, "org_members", "org_id", id, deleted_at)?;

    // Restore the organization itself
    restore_entity(conn, "organizations", id)?;

    Ok(true)
}

// ============ Org Members ============

/// Create an org member (links a user to an org with a role).
pub fn create_org_member(
    conn: &Connection,
    org_id: &str,
    input: &CreateOrgMember,
) -> Result<OrgMember> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO org_members (id, user_id, org_id, role, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![&id, &input.user_id, org_id, input.role.as_ref(), now],
    )?;

    Ok(OrgMember {
        id,
        user_id: input.user_id.clone(),
        org_id: org_id.to_string(),
        role: input.role,
        created_at: now,
        deleted_at: None,
        deleted_cascade_depth: None,
    })
}

pub fn get_org_member_by_id(conn: &Connection, id: &str) -> Result<Option<OrgMember>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM org_members WHERE id = ?1 AND deleted_at IS NULL",
            ORG_MEMBER_COLS
        ),
        &[&id],
    )
}

/// Get org member with user details joined.
pub fn get_org_member_with_user_by_id(
    conn: &Connection,
    id: &str,
) -> Result<Option<OrgMemberWithUser>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM org_members m JOIN users u ON m.user_id = u.id WHERE m.id = ?1 AND m.deleted_at IS NULL AND u.deleted_at IS NULL",
            ORG_MEMBER_WITH_USER_COLS
        ),
        &[&id],
    )
}

/// Get org member by user_id and org_id.
pub fn get_org_member_by_user_and_org(
    conn: &Connection,
    user_id: &str,
    org_id: &str,
) -> Result<Option<OrgMember>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM org_members WHERE user_id = ?1 AND org_id = ?2 AND deleted_at IS NULL",
            ORG_MEMBER_COLS
        ),
        params![user_id, org_id],
    )
}

/// Get org member with user details by user_id and org_id.
pub fn get_org_member_with_user_by_user_and_org(
    conn: &Connection,
    user_id: &str,
    org_id: &str,
) -> Result<Option<OrgMemberWithUser>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM org_members m JOIN users u ON m.user_id = u.id WHERE m.user_id = ?1 AND m.org_id = ?2 AND m.deleted_at IS NULL AND u.deleted_at IS NULL",
            ORG_MEMBER_WITH_USER_COLS
        ),
        params![user_id, org_id],
    )
}

/// List all orgs where a user is a member.
pub fn list_orgs_by_user_id(conn: &Connection, user_id: &str) -> Result<Vec<Organization>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM organizations WHERE deleted_at IS NULL AND id IN (SELECT org_id FROM org_members WHERE user_id = ?1 AND deleted_at IS NULL) ORDER BY created_at DESC",
            ORGANIZATION_COLS
        ),
        &[&user_id],
    )
}

pub fn list_orgs_by_user_id_paginated(
    conn: &Connection,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<Organization>, i64)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM organizations WHERE deleted_at IS NULL AND id IN (SELECT org_id FROM org_members WHERE user_id = ?1 AND deleted_at IS NULL)",
        params![user_id],
        |row| row.get(0),
    )?;

    let orgs = query_all(
        conn,
        &format!(
            "SELECT {} FROM organizations WHERE deleted_at IS NULL AND id IN (SELECT org_id FROM org_members WHERE user_id = ?1 AND deleted_at IS NULL) ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
            ORGANIZATION_COLS
        ),
        params![user_id, limit, offset],
    )?;

    Ok((orgs, total))
}

pub fn list_org_members(conn: &Connection, org_id: &str) -> Result<Vec<OrgMember>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM org_members WHERE org_id = ?1 AND deleted_at IS NULL ORDER BY created_at DESC",
            ORG_MEMBER_COLS
        ),
        &[&org_id],
    )
}

/// List org members with user details joined.
pub fn list_org_members_with_user(
    conn: &Connection,
    org_id: &str,
) -> Result<Vec<OrgMemberWithUser>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM org_members m JOIN users u ON m.user_id = u.id WHERE m.org_id = ?1 AND m.deleted_at IS NULL AND u.deleted_at IS NULL ORDER BY m.created_at DESC",
            ORG_MEMBER_WITH_USER_COLS
        ),
        &[&org_id],
    )
}

/// List org members with pagination
pub fn list_org_members_paginated(
    conn: &Connection,
    org_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<OrgMember>, i64)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM org_members WHERE org_id = ?1 AND deleted_at IS NULL",
        params![org_id],
        |row| row.get(0),
    )?;

    let items = query_all(
        conn,
        &format!(
            "SELECT {} FROM org_members WHERE org_id = ?1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
            ORG_MEMBER_COLS
        ),
        params![org_id, limit, offset],
    )?;

    Ok((items, total))
}

/// List org members with user details and pagination.
pub fn list_org_members_with_user_paginated(
    conn: &Connection,
    org_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<OrgMemberWithUser>, i64)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM org_members WHERE org_id = ?1 AND deleted_at IS NULL",
        params![org_id],
        |row| row.get(0),
    )?;

    let items = query_all(
        conn,
        &format!(
            "SELECT {} FROM org_members m JOIN users u ON m.user_id = u.id WHERE m.org_id = ?1 AND m.deleted_at IS NULL AND u.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT ?2 OFFSET ?3",
            ORG_MEMBER_WITH_USER_COLS
        ),
        params![org_id, limit, offset],
    )?;

    Ok((items, total))
}

pub fn update_org_member(conn: &Connection, id: &str, input: &UpdateOrgMember) -> Result<()> {
    UpdateBuilder::new("org_members", id)
        .set_opt("role", input.role.map(|r| r.as_ref().to_string()))
        .execute(conn)?;
    Ok(())
}

pub fn delete_org_member(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM org_members WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

/// Soft delete an org member. Project_members will become orphaned (OK - they use FK CASCADE).
pub fn soft_delete_org_member(conn: &Connection, id: &str) -> Result<bool> {
    use super::soft_delete::soft_delete_entity;
    Ok(soft_delete_entity(conn, "org_members", id)?.deleted)
}

/// Get a soft-deleted org member by ID (for restore operations).
pub fn get_deleted_org_member_by_id(conn: &Connection, id: &str) -> Result<Option<OrgMember>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM org_members WHERE id = ?1 AND deleted_at IS NOT NULL",
            ORG_MEMBER_COLS
        ),
        &[&id],
    )
}

/// Get a soft-deleted org member by user_id and org_id (for restore operations).
pub fn get_deleted_org_member_by_user_and_org(
    conn: &Connection,
    user_id: &str,
    org_id: &str,
) -> Result<Option<OrgMember>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM org_members WHERE user_id = ?1 AND org_id = ?2 AND deleted_at IS NOT NULL",
            ORG_MEMBER_COLS
        ),
        params![user_id, org_id],
    )
}

/// Restore a soft-deleted org member.
/// Returns Err if depth > 0 and force=false (was cascaded from org/user delete).
pub fn restore_org_member(conn: &Connection, id: &str, force: bool) -> Result<bool> {
    use super::soft_delete::{check_restore_allowed, restore_entity};

    let Some(member) = get_deleted_org_member_by_id(conn, id)? else {
        return Ok(false);
    };

    check_restore_allowed(member.deleted_cascade_depth, force, "Org member")?;
    restore_entity(conn, "org_members", id)?;

    Ok(true)
}

// ============ Org Access Helpers ============

/// Result type for users who can modify an organization.
#[derive(Debug, Clone)]
pub struct OrgModifier {
    pub user_id: String,
    pub email: String,
    pub name: String,
    /// "operator" if admin+ operator, or the org member role ("owner"/"admin")
    pub access_type: String,
}

/// Get all users who can modify an organization.
///
/// Returns a combined list of:
/// - Org members with Owner or Admin role
/// - Operators with Admin or Owner role (they get synthetic owner access)
///
/// This is useful for admin dashboards and notifications.
pub fn get_org_modifiers(conn: &Connection, org_id: &str) -> Result<Vec<OrgModifier>> {
    let mut stmt = conn.prepare(
        "SELECT u.id, u.email, u.name, m.role as access_type
         FROM org_members m
         JOIN users u ON m.user_id = u.id
         WHERE m.org_id = ?1 AND m.role IN ('owner', 'admin')
         AND m.deleted_at IS NULL AND u.deleted_at IS NULL
         UNION
         SELECT u.id, u.email, u.name, 'operator' as access_type
         FROM operators o
         JOIN users u ON o.user_id = u.id
         WHERE o.role IN ('owner', 'admin')
         AND o.deleted_at IS NULL AND u.deleted_at IS NULL
         ORDER BY access_type, email",
    )?;

    let rows = stmt.query_map(params![org_id], |row| {
        Ok(OrgModifier {
            user_id: row.get(0)?,
            email: row.get(1)?,
            name: row.get(2)?,
            access_type: row.get(3)?,
        })
    })?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Check if a user can modify an organization.
///
/// Returns true if the user is:
/// - An org member with Owner or Admin role, OR
/// - An operator with Admin or Owner role
pub fn can_user_modify_org(conn: &Connection, user_id: &str, org_id: &str) -> Result<bool> {
    // Check org membership first (most common case)
    let member_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM org_members
         WHERE user_id = ?1 AND org_id = ?2 AND role IN ('owner', 'admin') AND deleted_at IS NULL",
        params![user_id, org_id],
        |row| row.get(0),
    )?;

    if member_count > 0 {
        return Ok(true);
    }

    // Check if user is an admin+ operator
    let operator_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM operators
         WHERE user_id = ?1 AND role IN ('owner', 'admin') AND deleted_at IS NULL",
        params![user_id],
        |row| row.get(0),
    )?;

    Ok(operator_count > 0)
}

// ============ Projects ============

/// Create a project, encrypting the private key with envelope encryption.
/// The project ID is generated internally and used as the encryption context.
pub fn create_project(
    conn: &Connection,
    org_id: &str,
    input: &CreateProject,
    private_key: &[u8],
    public_key: &str,
    master_key: &MasterKey,
) -> Result<Project> {
    let id = gen_id();
    let now = now();
    let encrypted_private_key = master_key.encrypt_private_key(&id, private_key)?;

    conn.execute(
        "INSERT INTO projects (id, org_id, name, license_key_prefix, private_key, public_key, redirect_url, email_from, email_enabled, email_webhook_url, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![&id, org_id, &input.name, &input.license_key_prefix, &encrypted_private_key, public_key, &input.redirect_url, &input.email_from, input.email_enabled, &input.email_webhook_url, now, now],
    )?;

    Ok(Project {
        id,
        org_id: org_id.to_string(),
        name: input.name.clone(),
        license_key_prefix: input.license_key_prefix.clone(),
        private_key: encrypted_private_key,
        public_key: public_key.to_string(),
        redirect_url: input.redirect_url.clone(),
        email_from: input.email_from.clone(),
        email_enabled: input.email_enabled,
        email_webhook_url: input.email_webhook_url.clone(),
        created_at: now,
        updated_at: now,
        deleted_at: None,
        deleted_cascade_depth: None,
    })
}

pub fn get_project_by_id(conn: &Connection, id: &str) -> Result<Option<Project>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM projects WHERE id = ?1 AND deleted_at IS NULL",
            PROJECT_COLS
        ),
        &[&id],
    )
}

pub fn list_projects_for_org(conn: &Connection, org_id: &str) -> Result<Vec<Project>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM projects WHERE org_id = ?1 AND deleted_at IS NULL ORDER BY created_at DESC",
            PROJECT_COLS
        ),
        &[&org_id],
    )
}

/// List projects for an org with pagination
pub fn list_projects_for_org_paginated(
    conn: &Connection,
    org_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<Project>, i64)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM projects WHERE org_id = ?1 AND deleted_at IS NULL",
        params![org_id],
        |row| row.get(0),
    )?;

    let items = query_all(
        conn,
        &format!(
            "SELECT {} FROM projects WHERE org_id = ?1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
            PROJECT_COLS
        ),
        params![org_id, limit, offset],
    )?;

    Ok((items, total))
}

/// List projects accessible by a specific org member with pagination
/// For "member" role users who only see projects they're explicitly added to
pub fn list_accessible_projects_for_member_paginated(
    conn: &Connection,
    org_id: &str,
    org_member_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<Project>, i64)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM projects
         WHERE org_id = ?1 AND deleted_at IS NULL
         AND id IN (SELECT project_id FROM project_members WHERE org_member_id = ?2)",
        params![org_id, org_member_id],
        |row| row.get(0),
    )?;

    let items = query_all(
        conn,
        &format!(
            "SELECT {} FROM projects
             WHERE org_id = ?1 AND deleted_at IS NULL
             AND id IN (SELECT project_id FROM project_members WHERE org_member_id = ?2)
             ORDER BY created_at DESC LIMIT ?3 OFFSET ?4",
            PROJECT_COLS
        ),
        params![org_id, org_member_id, limit, offset],
    )?;

    Ok((items, total))
}

/// List all projects (for migration purposes - includes soft-deleted)
pub fn list_all_projects(conn: &Connection) -> Result<Vec<Project>> {
    query_all(
        conn,
        &format!("SELECT {} FROM projects ORDER BY created_at", PROJECT_COLS),
        &[],
    )
}

/// Update a project's private key (for key rotation)
pub fn update_project_private_key(conn: &Connection, id: &str, private_key: &[u8]) -> Result<()> {
    conn.execute(
        "UPDATE projects SET private_key = ?1, updated_at = ?2 WHERE id = ?3",
        params![private_key, now(), id],
    )?;
    Ok(())
}

pub fn update_project(conn: &Connection, id: &str, input: &UpdateProject) -> Result<()> {
    // All nullable fields use Option<Option<T>> pattern:
    // None = leave unchanged, Some(None) = clear, Some(Some(v)) = set
    let mut builder = UpdateBuilder::new("projects", id)
        .with_updated_at()
        .set_opt("name", input.name.clone())
        .set_opt("license_key_prefix", input.license_key_prefix.clone());

    // Handle redirect_url: Option<Option<String>>
    if let Some(ref redirect_url) = input.redirect_url {
        builder = builder.set_nullable("redirect_url", redirect_url.clone());
    }

    // Handle email_from: Option<Option<String>>
    if let Some(ref email_from) = input.email_from {
        builder = builder.set_nullable("email_from", email_from.clone());
    }

    // Handle email_enabled: Option<bool>
    if let Some(email_enabled) = input.email_enabled {
        builder = builder.set("email_enabled", email_enabled as i32);
    }

    // Handle email_webhook_url: Option<Option<String>>
    if let Some(ref email_webhook_url) = input.email_webhook_url {
        builder = builder.set_nullable("email_webhook_url", email_webhook_url.clone());
    }

    builder.execute(conn)?;
    Ok(())
}

pub fn delete_project(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM projects WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

/// Soft delete a project and cascade to products and licenses.
pub fn soft_delete_project(conn: &Connection, id: &str) -> Result<bool> {
    use super::soft_delete::{cascade_delete_direct, soft_delete_entity};

    let result = soft_delete_entity(conn, "projects", id)?;
    if !result.deleted {
        return Ok(false);
    }

    // Cascade to products (depth 1) and licenses (depth 2)
    cascade_delete_direct(conn, "products", "project_id", id, result.deleted_at, 1)?;
    cascade_delete_direct(conn, "licenses", "project_id", id, result.deleted_at, 2)?;

    Ok(true)
}

/// Get a soft-deleted project by ID (for restore operations).
pub fn get_deleted_project_by_id(conn: &Connection, id: &str) -> Result<Option<Project>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM projects WHERE id = ?1 AND deleted_at IS NOT NULL",
            PROJECT_COLS
        ),
        &[&id],
    )
}

/// Restore a soft-deleted project and all cascaded children.
/// Returns Err if depth > 0 and force=false (was cascaded from org delete).
pub fn restore_project(conn: &Connection, id: &str, force: bool) -> Result<bool> {
    use super::soft_delete::{check_restore_allowed, restore_cascaded_direct, restore_entity};

    let Some(project) = get_deleted_project_by_id(conn, id)? else {
        return Ok(false);
    };

    check_restore_allowed(project.deleted_cascade_depth, force, "Project")?;

    let deleted_at = project.deleted_at.unwrap();

    // Restore in reverse order: deepest children first
    restore_cascaded_direct(conn, "licenses", "project_id", id, deleted_at)?;
    restore_cascaded_direct(conn, "products", "project_id", id, deleted_at)?;

    // Restore the project itself
    restore_entity(conn, "projects", id)?;

    Ok(true)
}

/// Look up a project by its public key.
/// Used by public endpoints to identify the project without requiring a project_id.
pub fn get_project_by_public_key(conn: &Connection, public_key: &str) -> Result<Option<Project>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM projects WHERE public_key = ?1 AND deleted_at IS NULL",
            PROJECT_COLS
        ),
        &[&public_key],
    )
}

// ============ Project Members ============

pub fn create_project_member(
    conn: &Connection,
    project_id: &str,
    input: &CreateProjectMember,
) -> Result<ProjectMember> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO project_members (id, org_member_id, project_id, role, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &id,
            &input.org_member_id,
            project_id,
            input.role.as_ref(),
            now
        ],
    )?;

    Ok(ProjectMember {
        id,
        org_member_id: input.org_member_id.clone(),
        project_id: project_id.to_string(),
        role: input.role,
        created_at: now,
    })
}

pub fn get_project_member(
    conn: &Connection,
    org_member_id: &str,
    project_id: &str,
) -> Result<Option<ProjectMember>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM project_members WHERE org_member_id = ?1 AND project_id = ?2",
            PROJECT_MEMBER_COLS
        ),
        &[&org_member_id, &project_id],
    )
}

/// Get a project member by ID with org member details
pub fn get_project_member_by_id(
    conn: &Connection,
    id: &str,
) -> Result<Option<ProjectMemberWithDetails>> {
    query_one(
        conn,
        "SELECT pm.id, pm.org_member_id, om.user_id, pm.project_id, pm.role, pm.created_at, u.email, u.name
         FROM project_members pm
         JOIN org_members om ON pm.org_member_id = om.id
         JOIN users u ON om.user_id = u.id
         WHERE pm.id = ?1",
        &[&id],
    )
}

/// Get a project member by user_id and project_id
pub fn get_project_member_by_user_and_project(
    conn: &Connection,
    user_id: &str,
    org_id: &str,
    project_id: &str,
) -> Result<Option<ProjectMemberWithDetails>> {
    query_one(
        conn,
        "SELECT pm.id, pm.org_member_id, om.user_id, pm.project_id, pm.role, pm.created_at, u.email, u.name
         FROM project_members pm
         JOIN org_members om ON pm.org_member_id = om.id
         JOIN users u ON om.user_id = u.id
         WHERE u.id = ?1 AND om.org_id = ?2 AND pm.project_id = ?3 AND om.deleted_at IS NULL",
        params![user_id, org_id, project_id],
    )
}

pub fn list_project_members(
    conn: &Connection,
    project_id: &str,
) -> Result<Vec<ProjectMemberWithDetails>> {
    query_all(
        conn,
        "SELECT pm.id, pm.org_member_id, om.user_id, pm.project_id, pm.role, pm.created_at, u.email, u.name
         FROM project_members pm
         JOIN org_members om ON pm.org_member_id = om.id
         JOIN users u ON om.user_id = u.id
         WHERE pm.project_id = ?1
         ORDER BY pm.created_at DESC",
        &[&project_id],
    )
}

/// List project members with pagination
pub fn list_project_members_paginated(
    conn: &Connection,
    project_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ProjectMemberWithDetails>, i64)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM project_members WHERE project_id = ?1",
        params![project_id],
        |row| row.get(0),
    )?;

    let items = query_all(
        conn,
        "SELECT pm.id, pm.org_member_id, om.user_id, pm.project_id, pm.role, pm.created_at, u.email, u.name
         FROM project_members pm
         JOIN org_members om ON pm.org_member_id = om.id
         JOIN users u ON om.user_id = u.id
         WHERE pm.project_id = ?1
         ORDER BY pm.created_at DESC
         LIMIT ?2 OFFSET ?3",
        params![project_id, limit, offset],
    )?;

    Ok((items, total))
}

pub fn update_project_member(
    conn: &Connection,
    id: &str,
    project_id: &str,
    input: &UpdateProjectMember,
) -> Result<bool> {
    let affected = conn.execute(
        "UPDATE project_members SET role = ?1 WHERE id = ?2 AND project_id = ?3",
        params![input.role.as_ref(), id, project_id],
    )?;
    Ok(affected > 0)
}

pub fn delete_project_member(conn: &Connection, id: &str, project_id: &str) -> Result<bool> {
    let deleted = conn.execute(
        "DELETE FROM project_members WHERE id = ?1 AND project_id = ?2",
        params![id, project_id],
    )?;
    Ok(deleted > 0)
}

// ============ Products ============

pub fn create_product(
    conn: &Connection,
    project_id: &str,
    input: &CreateProduct,
) -> Result<Product> {
    let id = gen_id();
    let now = now();
    let features_json = serde_json::to_string(&input.features)?;

    conn.execute(
        "INSERT INTO products (id, project_id, name, tier, license_exp_days, updates_exp_days, activation_limit, device_limit, features, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            &id,
            project_id,
            &input.name,
            &input.tier,
            input.license_exp_days,
            input.updates_exp_days,
            input.activation_limit,
            input.device_limit,
            &features_json,
            now
        ],
    )?;

    Ok(Product {
        id,
        project_id: project_id.to_string(),
        name: input.name.clone(),
        tier: input.tier.clone(),
        license_exp_days: input.license_exp_days,
        updates_exp_days: input.updates_exp_days,
        activation_limit: input.activation_limit,
        device_limit: input.device_limit,
        features: input.features.clone(),
        created_at: now,
        deleted_at: None,
        deleted_cascade_depth: None,
    })
}

pub fn get_product_by_id(conn: &Connection, id: &str) -> Result<Option<Product>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM products WHERE id = ?1 AND deleted_at IS NULL",
            PRODUCT_COLS
        ),
        &[&id],
    )
}

pub fn list_products_for_project(conn: &Connection, project_id: &str) -> Result<Vec<Product>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM products WHERE project_id = ?1 AND deleted_at IS NULL ORDER BY created_at DESC",
            PRODUCT_COLS
        ),
        &[&project_id],
    )
}

pub fn list_products_for_project_paginated(
    conn: &Connection,
    project_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<Product>, i64)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM products WHERE project_id = ?1 AND deleted_at IS NULL",
        params![project_id],
        |row| row.get(0),
    )?;

    let products = query_all(
        conn,
        &format!(
            "SELECT {} FROM products WHERE project_id = ?1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
            PRODUCT_COLS
        ),
        params![project_id, limit, offset],
    )?;

    Ok((products, total))
}

pub fn update_product(conn: &Connection, id: &str, input: &UpdateProduct) -> Result<()> {
    let features_json = input
        .features
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;

    UpdateBuilder::new("products", id)
        .set_opt("name", input.name.clone())
        .set_opt("tier", input.tier.clone())
        .set_opt("license_exp_days", input.license_exp_days)
        .set_opt("updates_exp_days", input.updates_exp_days)
        .set_opt("activation_limit", input.activation_limit)
        .set_opt("device_limit", input.device_limit)
        .set_opt("features", features_json)
        .execute(conn)?;
    Ok(())
}

pub fn delete_product(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM products WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

/// Soft delete a product and cascade to licenses.
pub fn soft_delete_product(conn: &Connection, id: &str) -> Result<bool> {
    use super::soft_delete::{cascade_delete_direct, soft_delete_entity};

    let result = soft_delete_entity(conn, "products", id)?;
    if !result.deleted {
        return Ok(false);
    }

    // Cascade to licenses (depth 1)
    cascade_delete_direct(conn, "licenses", "product_id", id, result.deleted_at, 1)?;

    Ok(true)
}

/// Get a soft-deleted product by ID (for restore operations).
pub fn get_deleted_product_by_id(conn: &Connection, id: &str) -> Result<Option<Product>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM products WHERE id = ?1 AND deleted_at IS NOT NULL",
            PRODUCT_COLS
        ),
        &[&id],
    )
}

/// Restore a soft-deleted product and all cascaded licenses.
/// Returns Err if depth > 0 and force=false (was cascaded from project/org delete).
pub fn restore_product(conn: &Connection, id: &str, force: bool) -> Result<bool> {
    use super::soft_delete::{check_restore_allowed, restore_cascaded_direct, restore_entity};

    let Some(product) = get_deleted_product_by_id(conn, id)? else {
        return Ok(false);
    };

    check_restore_allowed(product.deleted_cascade_depth, force, "Product")?;

    let deleted_at = product.deleted_at.unwrap();

    // Restore licenses that were cascaded
    restore_cascaded_direct(conn, "licenses", "product_id", id, deleted_at)?;

    // Restore the product itself
    restore_entity(conn, "products", id)?;

    Ok(true)
}

// ============ Product Payment Config ============

pub fn create_payment_config(
    conn: &Connection,
    product_id: &str,
    input: &CreatePaymentConfig,
) -> Result<ProductPaymentConfig> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO product_payment_config (id, product_id, provider, stripe_price_id, price_cents, currency, ls_variant_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &id,
            product_id,
            &input.provider,
            &input.stripe_price_id,
            input.price_cents,
            &input.currency,
            &input.ls_variant_id,
            now,
            now
        ],
    )?;

    Ok(ProductPaymentConfig {
        id,
        product_id: product_id.to_string(),
        provider: input.provider.clone(),
        stripe_price_id: input.stripe_price_id.clone(),
        price_cents: input.price_cents,
        currency: input.currency.clone(),
        ls_variant_id: input.ls_variant_id.clone(),
        created_at: now,
        updated_at: now,
    })
}

pub fn get_payment_config(
    conn: &Connection,
    product_id: &str,
    provider: &str,
) -> Result<Option<ProductPaymentConfig>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM product_payment_config WHERE product_id = ?1 AND provider = ?2",
            PAYMENT_CONFIG_COLS
        ),
        &[&product_id, &provider],
    )
}

pub fn get_payment_config_by_id(
    conn: &Connection,
    id: &str,
) -> Result<Option<ProductPaymentConfig>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM product_payment_config WHERE id = ?1",
            PAYMENT_CONFIG_COLS
        ),
        &[&id],
    )
}

pub fn get_payment_configs_for_product(
    conn: &Connection,
    product_id: &str,
) -> Result<Vec<ProductPaymentConfig>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM product_payment_config WHERE product_id = ?1 ORDER BY created_at",
            PAYMENT_CONFIG_COLS
        ),
        &[&product_id],
    )
}

pub fn update_payment_config(
    conn: &Connection,
    id: &str,
    input: &UpdatePaymentConfig,
) -> Result<()> {
    UpdateBuilder::new("product_payment_config", id)
        .with_updated_at()
        .set_opt("stripe_price_id", input.stripe_price_id.clone())
        .set_opt("price_cents", input.price_cents)
        .set_opt("currency", input.currency.clone())
        .set_opt("ls_variant_id", input.ls_variant_id.clone())
        .execute(conn)?;
    Ok(())
}

pub fn delete_payment_config(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute(
        "DELETE FROM product_payment_config WHERE id = ?1",
        params![id],
    )?;
    Ok(deleted > 0)
}

/// Product with its payment configurations included inline.
/// Used for API responses to avoid N+1 queries.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProductWithPaymentConfig {
    #[serde(flatten)]
    pub product: Product,
    pub payment_config: Vec<ProductPaymentConfig>,
}

pub fn get_product_with_config(
    conn: &Connection,
    id: &str,
) -> Result<Option<ProductWithPaymentConfig>> {
    let product = get_product_by_id(conn, id)?;
    match product {
        Some(product) => {
            let payment_config = get_payment_configs_for_product(conn, &product.id)?;
            Ok(Some(ProductWithPaymentConfig {
                product,
                payment_config,
            }))
        }
        None => Ok(None),
    }
}

pub fn list_products_with_config(
    conn: &Connection,
    project_id: &str,
) -> Result<Vec<ProductWithPaymentConfig>> {
    // Get all products for the project
    let products = list_products_for_project(conn, project_id)?;

    if products.is_empty() {
        return Ok(vec![]);
    }

    // Get all payment configs for these products in one query
    let product_ids: Vec<&str> = products.iter().map(|p| p.id.as_str()).collect();
    let placeholders: Vec<String> = (1..=product_ids.len()).map(|i| format!("?{}", i)).collect();
    let sql = format!(
        "SELECT {} FROM product_payment_config WHERE product_id IN ({}) ORDER BY product_id, created_at",
        PAYMENT_CONFIG_COLS,
        placeholders.join(", ")
    );

    let params: Vec<&dyn rusqlite::ToSql> = product_ids
        .iter()
        .map(|id| id as &dyn rusqlite::ToSql)
        .collect();

    let configs: Vec<ProductPaymentConfig> = query_all(conn, &sql, &params)?;

    // Group configs by product_id
    let mut config_map: std::collections::HashMap<String, Vec<ProductPaymentConfig>> =
        std::collections::HashMap::new();
    for config in configs {
        config_map
            .entry(config.product_id.clone())
            .or_default()
            .push(config);
    }

    // Build result
    let result = products
        .into_iter()
        .map(|product| {
            let payment_config = config_map.remove(&product.id).unwrap_or_default();
            ProductWithPaymentConfig {
                product,
                payment_config,
            }
        })
        .collect();

    Ok(result)
}

pub fn list_products_with_config_paginated(
    conn: &Connection,
    project_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ProductWithPaymentConfig>, i64)> {
    // Get paginated products for the project
    let (products, total) = list_products_for_project_paginated(conn, project_id, limit, offset)?;

    if products.is_empty() {
        return Ok((vec![], total));
    }

    // Get all payment configs for these products in one query
    let product_ids: Vec<&str> = products.iter().map(|p| p.id.as_str()).collect();
    let placeholders: Vec<String> = (1..=product_ids.len()).map(|i| format!("?{}", i)).collect();
    let sql = format!(
        "SELECT {} FROM product_payment_config WHERE product_id IN ({}) ORDER BY product_id, created_at",
        PAYMENT_CONFIG_COLS,
        placeholders.join(", ")
    );

    let params: Vec<&dyn rusqlite::ToSql> = product_ids
        .iter()
        .map(|id| id as &dyn rusqlite::ToSql)
        .collect();

    let configs: Vec<ProductPaymentConfig> = query_all(conn, &sql, &params)?;

    // Group configs by product_id
    let mut config_map: std::collections::HashMap<String, Vec<ProductPaymentConfig>> =
        std::collections::HashMap::new();
    for config in configs {
        config_map
            .entry(config.product_id.clone())
            .or_default()
            .push(config);
    }

    // Build result
    let result = products
        .into_iter()
        .map(|product| {
            let payment_config = config_map.remove(&product.id).unwrap_or_default();
            ProductWithPaymentConfig {
                product,
                payment_config,
            }
        })
        .collect();

    Ok((result, total))
}

// ============ Licenses ============

/// Generate an activation code in the familiar license key format: PREFIX-XXXX-XXXX-XXXX-XXXX
pub fn generate_activation_code(prefix: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();

    let mut part = || -> String {
        (0..4)
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect()
    };

    format!("{}-{}-{}-{}-{}", prefix, part(), part(), part(), part())
}

/// Create a new license (no user-facing key - email hash is the identity)
pub fn create_license(
    conn: &Connection,
    project_id: &str,
    product_id: &str,
    input: &CreateLicense,
) -> Result<License> {
    // Validate that at least one identifier is present for license recovery
    let has_identifier = input.email_hash.is_some()
        || input.customer_id.is_some()
        || input.payment_provider_order_id.is_some();

    if !has_identifier {
        return Err(AppError::BadRequest(
            "License must have at least one identifier: email, customer_id, or payment_provider_order_id".into(),
        ));
    }

    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO licenses (id, email_hash, project_id, product_id, customer_id, activation_count, revoked, created_at, expires_at, updates_expires_at, payment_provider, payment_provider_customer_id, payment_provider_subscription_id, payment_provider_order_id)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![&id, &input.email_hash, project_id, product_id, &input.customer_id, now, input.expires_at, input.updates_expires_at, &input.payment_provider, &input.payment_provider_customer_id, &input.payment_provider_subscription_id, &input.payment_provider_order_id],
    )?;

    Ok(License {
        id,
        email_hash: input.email_hash.clone(),
        project_id: project_id.to_string(),
        product_id: product_id.to_string(),
        customer_id: input.customer_id.clone(),
        activation_count: 0,
        revoked: false,
        created_at: now,
        expires_at: input.expires_at,
        updates_expires_at: input.updates_expires_at,
        payment_provider: input.payment_provider.clone(),
        payment_provider_customer_id: input.payment_provider_customer_id.clone(),
        payment_provider_subscription_id: input.payment_provider_subscription_id.clone(),
        payment_provider_order_id: input.payment_provider_order_id.clone(),
        deleted_at: None,
        deleted_cascade_depth: None,
    })
}

pub fn get_license_by_id(conn: &Connection, id: &str) -> Result<Option<License>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM licenses WHERE id = ?1 AND deleted_at IS NULL",
            LICENSE_COLS
        ),
        &[&id],
    )
}

/// Look up an active (non-revoked, non-expired) license by email hash and project.
pub fn get_license_by_email_hash(
    conn: &Connection,
    project_id: &str,
    email_hash: &str,
) -> Result<Option<License>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM licenses WHERE project_id = ?1 AND email_hash = ?2 AND revoked = 0 AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > unixepoch())",
            LICENSE_COLS
        ),
        &[&project_id, &email_hash],
    )
}

/// Look up all active (non-revoked, non-expired) licenses by email hash and project.
/// Used when a user may have multiple licenses (e.g., bought multiple products).
pub fn get_licenses_by_email_hash(
    conn: &Connection,
    project_id: &str,
    email_hash: &str,
) -> Result<Vec<License>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM licenses WHERE project_id = ?1 AND email_hash = ?2 AND revoked = 0 AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > unixepoch()) ORDER BY created_at DESC",
            LICENSE_COLS
        ),
        &[&project_id, &email_hash],
    )
}

/// Look up ALL licenses by email hash and project (for admin support) with pagination.
/// Includes expired and revoked licenses so support can see full history.
/// Note: Excludes soft-deleted licenses.
pub fn get_all_licenses_by_email_hash_for_admin_paginated(
    conn: &Connection,
    project_id: &str,
    email_hash: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<LicenseWithProduct>, i64)> {
    // Get total count
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM licenses WHERE project_id = ?1 AND email_hash = ?2 AND deleted_at IS NULL",
        params![project_id, email_hash],
        |row| row.get(0),
    )?;

    let mut stmt = conn.prepare(&format!(
        "SELECT l.{}, p.name
         FROM licenses l
         JOIN products p ON l.product_id = p.id
         WHERE l.project_id = ?1 AND l.email_hash = ?2 AND l.deleted_at IS NULL
         ORDER BY l.created_at DESC
         LIMIT ?3 OFFSET ?4",
        LICENSE_COLS.replace(", ", ", l.")
    ))?;

    let rows = stmt
        .query_map(params![project_id, email_hash, limit, offset], |row| {
            Ok(LicenseWithProduct {
                license: License {
                    id: row.get(0)?,
                    email_hash: row.get(1)?,
                    project_id: row.get(2)?,
                    product_id: row.get(3)?,
                    customer_id: row.get(4)?,
                    activation_count: row.get(5)?,
                    revoked: row.get::<_, i32>(6)? != 0,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    updates_expires_at: row.get(9)?,
                    payment_provider: row.get(10)?,
                    payment_provider_customer_id: row.get(11)?,
                    payment_provider_subscription_id: row.get(12)?,
                    payment_provider_order_id: row.get(13)?,
                    deleted_at: row.get(14)?,
                    deleted_cascade_depth: row.get(15)?,
                },
                product_name: row.get(16)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok((rows, total))
}

pub fn list_licenses_for_project_paginated(
    conn: &Connection,
    project_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<LicenseWithProduct>, i64)> {
    // Get total count
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM licenses WHERE project_id = ?1 AND deleted_at IS NULL",
        params![project_id],
        |row| row.get(0),
    )?;

    let mut stmt = conn.prepare(&format!(
        "SELECT l.{}, p.name
         FROM licenses l
         JOIN products p ON l.product_id = p.id
         WHERE l.project_id = ?1 AND l.deleted_at IS NULL
         ORDER BY l.created_at DESC
         LIMIT ?2 OFFSET ?3",
        LICENSE_COLS.replace(", ", ", l.")
    ))?;

    let rows = stmt
        .query_map(params![project_id, limit, offset], |row| {
            Ok(LicenseWithProduct {
                license: License {
                    id: row.get(0)?,
                    email_hash: row.get(1)?,
                    project_id: row.get(2)?,
                    product_id: row.get(3)?,
                    customer_id: row.get(4)?,
                    activation_count: row.get(5)?,
                    revoked: row.get::<_, i32>(6)? != 0,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    updates_expires_at: row.get(9)?,
                    payment_provider: row.get(10)?,
                    payment_provider_customer_id: row.get(11)?,
                    payment_provider_subscription_id: row.get(12)?,
                    payment_provider_order_id: row.get(13)?,
                    deleted_at: row.get(14)?,
                    deleted_cascade_depth: row.get(15)?,
                },
                product_name: row.get(16)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok((rows, total))
}

pub fn list_licenses_for_project(
    conn: &Connection,
    project_id: &str,
) -> Result<Vec<LicenseWithProduct>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT l.{}, p.name
         FROM licenses l
         JOIN products p ON l.product_id = p.id
         WHERE l.project_id = ?1 AND l.deleted_at IS NULL
         ORDER BY l.created_at DESC",
        LICENSE_COLS.replace(", ", ", l.")
    ))?;

    let rows = stmt
        .query_map(params![project_id], |row| {
            Ok(LicenseWithProduct {
                license: License {
                    id: row.get(0)?,
                    email_hash: row.get(1)?,
                    project_id: row.get(2)?,
                    product_id: row.get(3)?,
                    customer_id: row.get(4)?,
                    activation_count: row.get(5)?,
                    revoked: row.get::<_, i32>(6)? != 0,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    updates_expires_at: row.get(9)?,
                    payment_provider: row.get(10)?,
                    payment_provider_customer_id: row.get(11)?,
                    payment_provider_subscription_id: row.get(12)?,
                    payment_provider_order_id: row.get(13)?,
                    deleted_at: row.get(14)?,
                    deleted_cascade_depth: row.get(15)?,
                },
                product_name: row.get(16)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(rows)
}

pub fn increment_activation_count(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE licenses SET activation_count = activation_count + 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

pub fn revoke_license(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("UPDATE licenses SET revoked = 1 WHERE id = ?1", params![id])?;
    Ok(())
}

/// Soft delete a license. No cascade needed (devices/codes use FK CASCADE for hard delete).
pub fn soft_delete_license(conn: &Connection, id: &str) -> Result<bool> {
    use super::soft_delete::soft_delete_entity;
    Ok(soft_delete_entity(conn, "licenses", id)?.deleted)
}

/// Get a soft-deleted license by ID (for restore operations).
pub fn get_deleted_license_by_id(conn: &Connection, id: &str) -> Result<Option<License>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM licenses WHERE id = ?1 AND deleted_at IS NOT NULL",
            LICENSE_COLS
        ),
        &[&id],
    )
}

/// Restore a soft-deleted license.
/// Returns Err if depth > 0 and force=false (was cascaded from product/project/org delete).
pub fn restore_license(conn: &Connection, id: &str, force: bool) -> Result<bool> {
    use super::soft_delete::{check_restore_allowed, restore_entity};

    let Some(license) = get_deleted_license_by_id(conn, id)? else {
        return Ok(false);
    };

    check_restore_allowed(license.deleted_cascade_depth, force, "License")?;
    restore_entity(conn, "licenses", id)?;

    Ok(true)
}

pub fn add_revoked_jti(
    conn: &Connection,
    license_id: &str,
    jti: &str,
    details: Option<&str>,
) -> Result<()> {
    let id = gen_id();
    let now = now();
    conn.execute(
        "INSERT OR IGNORE INTO revoked_jtis (id, license_id, jti, revoked_at, details) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, license_id, jti, now, details],
    )?;
    Ok(())
}

pub fn is_jti_revoked(conn: &Connection, license_id: &str, jti: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM revoked_jtis WHERE license_id = ?1 AND jti = ?2",
        params![license_id, jti],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Look up licenses by payment provider order ID (for admin support via receipt).
/// Includes expired and revoked licenses so support can see full history.
/// Note: Excludes soft-deleted licenses.
pub fn get_licenses_by_payment_order_id_paginated(
    conn: &Connection,
    project_id: &str,
    payment_provider_order_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<LicenseWithProduct>, i64)> {
    // Get total count
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM licenses WHERE project_id = ?1 AND payment_provider_order_id = ?2 AND deleted_at IS NULL",
        params![project_id, payment_provider_order_id],
        |row| row.get(0),
    )?;

    let mut stmt = conn.prepare(&format!(
        "SELECT l.{}, p.name
         FROM licenses l
         JOIN products p ON l.product_id = p.id
         WHERE l.project_id = ?1 AND l.payment_provider_order_id = ?2 AND l.deleted_at IS NULL
         ORDER BY l.created_at DESC
         LIMIT ?3 OFFSET ?4",
        LICENSE_COLS.replace(", ", ", l.")
    ))?;

    let rows = stmt
        .query_map(
            params![project_id, payment_provider_order_id, limit, offset],
            |row| {
                Ok(LicenseWithProduct {
                    license: License {
                        id: row.get(0)?,
                        email_hash: row.get(1)?,
                        project_id: row.get(2)?,
                        product_id: row.get(3)?,
                        customer_id: row.get(4)?,
                        activation_count: row.get(5)?,
                        revoked: row.get::<_, i32>(6)? != 0,
                        created_at: row.get(7)?,
                        expires_at: row.get(8)?,
                        updates_expires_at: row.get(9)?,
                        payment_provider: row.get(10)?,
                        payment_provider_customer_id: row.get(11)?,
                        payment_provider_subscription_id: row.get(12)?,
                        payment_provider_order_id: row.get(13)?,
                        deleted_at: row.get(14)?,
                        deleted_cascade_depth: row.get(15)?,
                    },
                    product_name: row.get(16)?,
                })
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok((rows, total))
}

/// Get licenses by developer-managed customer ID for a project (paginated).
/// Use this to find all licenses linked to a customer in your own system.
pub fn get_licenses_by_customer_id_paginated(
    conn: &Connection,
    project_id: &str,
    customer_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<LicenseWithProduct>, i64)> {
    // Get total count
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM licenses WHERE project_id = ?1 AND customer_id = ?2 AND deleted_at IS NULL",
        params![project_id, customer_id],
        |row| row.get(0),
    )?;

    let mut stmt = conn.prepare(&format!(
        "SELECT l.{}, p.name
         FROM licenses l
         JOIN products p ON l.product_id = p.id
         WHERE l.project_id = ?1 AND l.customer_id = ?2 AND l.deleted_at IS NULL
         ORDER BY l.created_at DESC
         LIMIT ?3 OFFSET ?4",
        LICENSE_COLS.replace(", ", ", l.")
    ))?;

    let rows = stmt
        .query_map(params![project_id, customer_id, limit, offset], |row| {
            Ok(LicenseWithProduct {
                license: License {
                    id: row.get(0)?,
                    email_hash: row.get(1)?,
                    project_id: row.get(2)?,
                    product_id: row.get(3)?,
                    customer_id: row.get(4)?,
                    activation_count: row.get(5)?,
                    revoked: row.get::<_, i32>(6)? != 0,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    updates_expires_at: row.get(9)?,
                    payment_provider: row.get(10)?,
                    payment_provider_customer_id: row.get(11)?,
                    payment_provider_subscription_id: row.get(12)?,
                    payment_provider_order_id: row.get(13)?,
                    deleted_at: row.get(14)?,
                    deleted_cascade_depth: row.get(15)?,
                },
                product_name: row.get(16)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok((rows, total))
}

/// Find a license by payment provider and subscription ID (for subscription renewals)
pub fn get_license_by_subscription(
    conn: &Connection,
    provider: &str,
    subscription_id: &str,
) -> Result<Option<License>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM licenses WHERE payment_provider = ?1 AND payment_provider_subscription_id = ?2 AND deleted_at IS NULL",
            LICENSE_COLS
        ),
        &[&provider, &subscription_id],
    )
}

/// Update a license's email hash (for fixing typo'd purchase emails).
/// This enables self-service recovery with the corrected email address.
pub fn update_license_email_hash(
    conn: &Connection,
    license_id: &str,
    email_hash: &str,
) -> Result<bool> {
    let affected = conn.execute(
        "UPDATE licenses SET email_hash = ?1 WHERE id = ?2",
        params![email_hash, license_id],
    )?;
    Ok(affected > 0)
}

/// Extend license expiration dates (for subscription renewals)
pub fn extend_license_expiration(
    conn: &Connection,
    license_id: &str,
    new_expires_at: Option<i64>,
    new_updates_expires_at: Option<i64>,
) -> Result<()> {
    conn.execute(
        "UPDATE licenses SET expires_at = ?1, updates_expires_at = ?2 WHERE id = ?3",
        params![new_expires_at, new_updates_expires_at, license_id],
    )?;
    Ok(())
}

// ============ Activation Codes ============

const ACTIVATION_CODE_TTL_SECONDS: i64 = 30 * 60; // 30 minutes

/// Create an activation code in PREFIX-XXXX-XXXX-XXXX-XXXX format
pub fn create_activation_code(
    conn: &Connection,
    license_id: &str,
    prefix: &str,
) -> Result<ActivationCode> {
    let id = gen_id();
    let code = generate_activation_code(prefix);
    let code_hash = hash_secret(&code);
    let now = now();
    let expires_at = now + ACTIVATION_CODE_TTL_SECONDS;

    conn.execute(
        "INSERT INTO activation_codes (id, code_hash, license_id, expires_at, used, created_at)
         VALUES (?1, ?2, ?3, ?4, 0, ?5)",
        params![&id, &code_hash, license_id, expires_at, now],
    )?;

    Ok(ActivationCode {
        id,
        code,
        license_id: license_id.to_string(),
        expires_at,
        used: false,
        created_at: now,
    })
}

pub fn get_activation_code_by_code(
    conn: &Connection,
    code: &str,
) -> Result<Option<ActivationCode>> {
    let code_hash = hash_secret(code);
    query_one(
        conn,
        &format!(
            "SELECT {} FROM activation_codes WHERE code_hash = ?1",
            ACTIVATION_CODE_COLS
        ),
        &[&code_hash],
    )
}

/// Atomically claim an activation code for redemption.
///
/// This prevents race conditions where multiple concurrent requests could use
/// the same activation code. The UPDATE only succeeds if:
/// - The code exists
/// - The code is not already used
/// - The code has not expired
///
/// Returns Ok(Some(ActivationCode)) if successfully claimed.
/// Returns Ok(None) if the code doesn't exist, is already used, or is expired.
pub fn try_claim_activation_code(
    conn: &Connection,
    code: &str,
) -> Result<Option<ActivationCode>> {
    let code_hash = hash_secret(code);
    let now = now();

    // Atomically mark as used only if not already used and not expired
    let affected = conn.execute(
        "UPDATE activation_codes SET used = 1 WHERE code_hash = ?1 AND used = 0 AND expires_at > ?2",
        params![&code_hash, now],
    )?;

    if affected == 0 {
        // Code doesn't exist, already used, or expired
        return Ok(None);
    }

    // Successfully claimed - now fetch the full record
    query_one(
        conn,
        &format!(
            "SELECT {} FROM activation_codes WHERE code_hash = ?1",
            ACTIVATION_CODE_COLS
        ),
        &[&code_hash],
    )
}

pub fn mark_activation_code_used(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE activation_codes SET used = 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

pub fn cleanup_expired_activation_codes(conn: &Connection) -> Result<usize> {
    let now = now();
    let deleted = conn.execute(
        "DELETE FROM activation_codes WHERE expires_at < ?1 OR used = 1",
        params![now],
    )?;
    Ok(deleted)
}

// ============ Devices ============

/// Result of attempting to acquire a device for a license
pub enum DeviceAcquisitionResult {
    /// Returned an existing device (already activated on this device_id)
    Existing(Device),
    /// Created a new device successfully
    Created(Device),
}

/// Atomically acquire a device for a license, enforcing device and activation limits.
///
/// This function uses a transaction with IMMEDIATE mode (SQLite) to prevent race conditions
/// where multiple concurrent requests could bypass the device limit.
///
/// # PostgreSQL Migration Note
/// When migrating to PostgreSQL, add `FOR UPDATE` to the license SELECT query to achieve
/// the same row-level locking behavior. SQLite's IMMEDIATE transaction provides this
/// implicitly by serializing all writes.
#[allow(clippy::too_many_arguments)]
pub fn acquire_device_atomic(
    conn: &mut Connection,
    license_id: &str,
    device_id: &str,
    device_type: DeviceType,
    jti: &str,
    name: Option<&str>,
    device_limit: i32,
    activation_limit: i32,
) -> Result<DeviceAcquisitionResult> {
    // Use IMMEDIATE to acquire write lock at transaction start, preventing TOCTOU races
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    // Check if device already exists for this license
    let existing_device: Option<Device> = query_one(
        &tx,
        &format!(
            "SELECT {} FROM devices WHERE license_id = ?1 AND device_id = ?2",
            DEVICE_COLS
        ),
        &[&license_id, &device_id],
    )?;

    if let Some(device) = existing_device {
        // Device exists - update JTI and return
        let now = now();
        tx.execute(
            "UPDATE devices SET jti = ?1, last_seen_at = ?2 WHERE id = ?3",
            params![jti, now, device.id],
        )?;
        tx.commit()?;
        return Ok(DeviceAcquisitionResult::Existing(Device {
            jti: jti.to_string(),
            last_seen_at: now,
            ..device
        }));
    }

    // New device - check limits atomically within the transaction
    let current_device_count: i32 = tx.query_row(
        "SELECT COUNT(*) FROM devices WHERE license_id = ?1",
        params![license_id],
        |row| row.get(0),
    )?;

    if device_limit > 0 && current_device_count >= device_limit {
        // No need to commit - just drop the transaction
        return Err(AppError::Forbidden(format!(
            "Device limit reached ({}/{}). Deactivate a device first.",
            current_device_count, device_limit
        )));
    }

    // Check activation limit
    let current_activation_count: i32 = tx.query_row(
        "SELECT activation_count FROM licenses WHERE id = ?1",
        params![license_id],
        |row| row.get(0),
    )?;

    if activation_limit > 0 && current_activation_count >= activation_limit {
        return Err(AppError::Forbidden(format!(
            "Activation limit reached ({}/{})",
            current_activation_count, activation_limit
        )));
    }

    // All checks passed - create device and increment activation count
    let id = gen_id();
    let now = now();

    tx.execute(
        "INSERT INTO devices (id, license_id, device_id, device_type, name, jti, activated_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![&id, license_id, device_id, device_type.as_ref(), name, jti, now, now],
    )?;

    tx.execute(
        "UPDATE licenses SET activation_count = activation_count + 1 WHERE id = ?1",
        params![license_id],
    )?;

    tx.commit()?;

    Ok(DeviceAcquisitionResult::Created(Device {
        id,
        license_id: license_id.to_string(),
        device_id: device_id.to_string(),
        device_type,
        name: name.map(String::from),
        jti: jti.to_string(),
        activated_at: now,
        last_seen_at: now,
    }))
}

pub fn create_device(
    conn: &Connection,
    license_id: &str,
    device_id: &str,
    device_type: DeviceType,
    jti: &str,
    name: Option<&str>,
) -> Result<Device> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO devices (id, license_id, device_id, device_type, name, jti, activated_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![&id, license_id, device_id, device_type.as_ref(), name, jti, now, now],
    )?;

    Ok(Device {
        id,
        license_id: license_id.to_string(),
        device_id: device_id.to_string(),
        device_type,
        name: name.map(String::from),
        jti: jti.to_string(),
        activated_at: now,
        last_seen_at: now,
    })
}

pub fn get_device_by_jti(conn: &Connection, jti: &str) -> Result<Option<Device>> {
    query_one(
        conn,
        &format!("SELECT {} FROM devices WHERE jti = ?1", DEVICE_COLS),
        &[&jti],
    )
}

pub fn get_device_for_license(
    conn: &Connection,
    license_id: &str,
    device_id: &str,
) -> Result<Option<Device>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM devices WHERE license_id = ?1 AND device_id = ?2",
            DEVICE_COLS
        ),
        &[&license_id, &device_id],
    )
}

pub fn list_devices_for_license(conn: &Connection, license_id: &str) -> Result<Vec<Device>> {
    query_all(
        conn,
        &format!(
            "SELECT {} FROM devices WHERE license_id = ?1 ORDER BY activated_at DESC",
            DEVICE_COLS
        ),
        &[&license_id],
    )
}

pub fn count_devices_for_license(conn: &Connection, license_id: &str) -> Result<i32> {
    conn.query_row(
        "SELECT COUNT(*) FROM devices WHERE license_id = ?1",
        params![license_id],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

pub fn update_device_last_seen(conn: &Connection, id: &str) -> Result<()> {
    let now = now();
    conn.execute(
        "UPDATE devices SET last_seen_at = ?1 WHERE id = ?2",
        params![now, id],
    )?;
    Ok(())
}

pub fn update_device_jti(conn: &Connection, id: &str, jti: &str) -> Result<()> {
    let now = now();
    conn.execute(
        "UPDATE devices SET jti = ?1, last_seen_at = ?2 WHERE id = ?3",
        params![jti, now, id],
    )?;
    Ok(())
}

pub fn delete_device(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM devices WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

// ============ Payment Sessions ============

pub fn create_payment_session(
    conn: &Connection,
    input: &CreatePaymentSession,
) -> Result<PaymentSession> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO payment_sessions (id, product_id, customer_id, created_at, completed)
         VALUES (?1, ?2, ?3, ?4, 0)",
        params![&id, &input.product_id, &input.customer_id, now],
    )?;

    Ok(PaymentSession {
        id,
        product_id: input.product_id.clone(),
        customer_id: input.customer_id.clone(),
        created_at: now,
        completed: false,
        license_id: None,
    })
}

pub fn get_payment_session(conn: &Connection, id: &str) -> Result<Option<PaymentSession>> {
    query_one(
        conn,
        &format!(
            "SELECT {} FROM payment_sessions WHERE id = ?1",
            PAYMENT_SESSION_COLS
        ),
        &[&id],
    )
}

/// Atomically mark a payment session as completed, returning whether the claim was successful.
///
/// Uses compare-and-swap to prevent race conditions where multiple concurrent webhook
/// requests could create multiple licenses from a single payment.
///
/// Returns:
/// - `Ok(true)` if this call successfully claimed the session (was not already completed)
/// - `Ok(false)` if the session was already completed by another request
/// - `Err(_)` if the session doesn't exist or a database error occurred
pub fn try_claim_payment_session(conn: &Connection, id: &str) -> Result<bool> {
    let affected = conn.execute(
        "UPDATE payment_sessions SET completed = 1 WHERE id = ?1 AND completed = 0",
        params![id],
    )?;
    Ok(affected > 0)
}

/// Set the license_id on a payment session after license creation.
/// Called after try_claim_payment_session succeeds and license is created.
pub fn set_payment_session_license(
    conn: &Connection,
    session_id: &str,
    license_id: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE payment_sessions SET license_id = ?1 WHERE id = ?2",
        params![license_id, session_id],
    )?;
    Ok(())
}

/// Purge old incomplete payment sessions beyond the retention period.
/// Only deletes sessions where completed = 0 (abandoned carts).
/// Completed sessions are kept as they link to licenses.
/// Returns the number of deleted records.
pub fn purge_old_payment_sessions(conn: &Connection, retention_days: i64) -> Result<usize> {
    let cutoff = now() - (retention_days * 86400);
    let deleted = conn.execute(
        "DELETE FROM payment_sessions WHERE completed = 0 AND created_at < ?1",
        params![cutoff],
    )?;
    Ok(deleted)
}

// ============ Webhook Event Deduplication ============

/// Atomically record a webhook event, returning true if this is a new event.
/// Returns false if the event was already processed (replay attack prevention).
///
/// Uses INSERT OR IGNORE for atomicity - if the (provider, event_id) pair
/// already exists, the insert is silently ignored and we return false.
pub fn try_record_webhook_event(conn: &Connection, provider: &str, event_id: &str) -> Result<bool> {
    let id = gen_id();
    let affected = conn.execute(
        "INSERT OR IGNORE INTO webhook_events (id, provider, event_id, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![id, provider, event_id, now()],
    )?;
    Ok(affected > 0)
}

/// Purge old webhook events beyond the retention period.
/// These are only used for replay attack prevention (Stripe/LemonSqueezy retry for ~3 days max).
/// Returns the number of deleted records.
pub fn purge_old_webhook_events(conn: &Connection, retention_days: i64) -> Result<usize> {
    let cutoff = now() - (retention_days * 86400);
    let deleted = conn.execute(
        "DELETE FROM webhook_events WHERE created_at < ?1",
        params![cutoff],
    )?;
    Ok(deleted)
}

// ============ Audit Log Maintenance ============

/// Purge old audit logs for public (end-user) actions only.
/// Internal actions (operator, org_member, system) are kept forever for audit trail.
/// Returns the number of deleted records.
/// Called on startup when PUBLIC_AUDIT_LOG_RETENTION_DAYS > 0.
pub fn purge_old_public_audit_logs(conn: &Connection, retention_days: i64) -> Result<usize> {
    let cutoff = now() - (retention_days * 86400);
    let deleted = conn.execute(
        "DELETE FROM audit_logs WHERE timestamp < ?1 AND actor_type = 'public'",
        params![cutoff],
    )?;
    Ok(deleted)
}

// ============ Soft Delete Maintenance ============

/// Result of purging soft-deleted records.
#[derive(Debug, Default)]
pub struct PurgeResult {
    pub users: usize,
    pub operators: usize,
    pub organizations: usize,
    pub org_members: usize,
    pub projects: usize,
    pub products: usize,
    pub licenses: usize,
}

impl PurgeResult {
    pub fn total(&self) -> usize {
        self.users
            + self.operators
            + self.organizations
            + self.org_members
            + self.projects
            + self.products
            + self.licenses
    }
}

/// Permanently delete soft-deleted records older than retention_days.
/// Deletes in order to respect FK constraints (children first).
/// Returns counts of deleted records per table.
/// Called periodically when SOFT_DELETE_RETENTION_DAYS > 0.
pub fn purge_soft_deleted_records(conn: &Connection, retention_days: i64) -> Result<PurgeResult> {
    use super::soft_delete::purge_table;

    let cutoff = now() - (retention_days * 86400);

    // Delete in order: deepest children first to respect FK constraints
    // Note: devices, activation_codes, revoked_jtis use FK CASCADE so they'll be deleted
    // automatically when their parent license is deleted.
    Ok(PurgeResult {
        licenses: purge_table(conn, "licenses", cutoff)?,
        products: purge_table(conn, "products", cutoff)?,
        projects: purge_table(conn, "projects", cutoff)?,
        org_members: purge_table(conn, "org_members", cutoff)?,
        organizations: purge_table(conn, "organizations", cutoff)?,
        operators: purge_table(conn, "operators", cutoff)?,
        users: purge_table(conn, "users", cutoff)?,
    })
}

// ============================================================================
// System Config
// ============================================================================

/// Get a system config value by key.
pub fn get_system_config(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    let result = conn.query_row(
        "SELECT value FROM system_config WHERE key = ?",
        [key],
        |row| row.get::<_, Vec<u8>>(0),
    );

    match result {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Set a system config value (insert or update).
pub fn set_system_config(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
    let now = now();
    conn.execute(
        "INSERT INTO system_config (key, value, created_at, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        rusqlite::params![key, value, now, now],
    )?;
    Ok(())
}
