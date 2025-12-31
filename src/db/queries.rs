use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::*;

fn now() -> i64 {
    Utc::now().timestamp()
}

fn gen_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_api_key() -> String {
    format!("pc_{}", Uuid::new_v4().to_string().replace("-", ""))
}

// ============ Operators ============

pub fn create_operator(
    conn: &Connection,
    input: &CreateOperator,
    api_key: &str,
    created_by: Option<&str>,
) -> Result<Operator> {
    let id = gen_id();
    let now = now();
    let api_key_hash = hash_api_key(api_key);

    conn.execute(
        "INSERT INTO operators (id, email, name, role, api_key_hash, created_at, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &id,
            &input.email,
            &input.name,
            input.role.as_str(),
            &api_key_hash,
            now,
            created_by
        ],
    )?;

    Ok(Operator {
        id,
        email: input.email.clone(),
        name: input.name.clone(),
        role: input.role,
        api_key_hash,
        created_at: now,
        created_by: created_by.map(String::from),
    })
}

pub fn get_operator_by_id(conn: &Connection, id: &str) -> Result<Option<Operator>> {
    conn.query_row(
        "SELECT id, email, name, role, api_key_hash, created_at, created_by
         FROM operators WHERE id = ?1",
        params![id],
        |row| {
            Ok(Operator {
                id: row.get(0)?,
                email: row.get(1)?,
                name: row.get(2)?,
                role: OperatorRole::from_str(&row.get::<_, String>(3)?).unwrap(),
                api_key_hash: row.get(4)?,
                created_at: row.get(5)?,
                created_by: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn get_operator_by_api_key(conn: &Connection, api_key: &str) -> Result<Option<Operator>> {
    let hash = hash_api_key(api_key);
    conn.query_row(
        "SELECT id, email, name, role, api_key_hash, created_at, created_by
         FROM operators WHERE api_key_hash = ?1",
        params![hash],
        |row| {
            Ok(Operator {
                id: row.get(0)?,
                email: row.get(1)?,
                name: row.get(2)?,
                role: OperatorRole::from_str(&row.get::<_, String>(3)?).unwrap(),
                api_key_hash: row.get(4)?,
                created_at: row.get(5)?,
                created_by: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn list_operators(conn: &Connection) -> Result<Vec<Operator>> {
    let mut stmt = conn.prepare(
        "SELECT id, email, name, role, api_key_hash, created_at, created_by
         FROM operators ORDER BY created_at DESC",
    )?;

    let ops = stmt
        .query_map([], |row| {
            Ok(Operator {
                id: row.get(0)?,
                email: row.get(1)?,
                name: row.get(2)?,
                role: OperatorRole::from_str(&row.get::<_, String>(3)?).unwrap(),
                api_key_hash: row.get(4)?,
                created_at: row.get(5)?,
                created_by: row.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(ops)
}

pub fn update_operator(conn: &Connection, id: &str, input: &UpdateOperator) -> Result<()> {
    if let Some(ref name) = input.name {
        conn.execute(
            "UPDATE operators SET name = ?1 WHERE id = ?2",
            params![name, id],
        )?;
    }
    if let Some(role) = input.role {
        conn.execute(
            "UPDATE operators SET role = ?1 WHERE id = ?2",
            params![role.as_str(), id],
        )?;
    }
    Ok(())
}

pub fn delete_operator(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM operators WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

pub fn count_operators(conn: &Connection) -> Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM operators", [], |row| row.get(0))
        .map_err(Into::into)
}

// ============ Audit Logs ============

pub fn create_audit_log(
    conn: &Connection,
    actor_type: ActorType,
    actor_id: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    details: Option<&serde_json::Value>,
    org_id: Option<&str>,
    project_id: Option<&str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<AuditLog> {
    let id = gen_id();
    let timestamp = now();

    // Skip database insert if audit logging is disabled
    if !crate::config::AUDIT_LOG_ENABLED {
        return Ok(AuditLog {
            id,
            timestamp,
            actor_type,
            actor_id: actor_id.map(String::from),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
            details: details.cloned(),
            org_id: org_id.map(String::from),
            project_id: project_id.map(String::from),
            ip_address: ip_address.map(String::from),
            user_agent: user_agent.map(String::from),
        });
    }

    let details_str = details.map(|d| d.to_string());

    conn.execute(
        "INSERT INTO audit_logs (id, timestamp, actor_type, actor_id, action, resource_type, resource_id, details, org_id, project_id, ip_address, user_agent)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            &id,
            timestamp,
            actor_type.as_str(),
            actor_id,
            action,
            resource_type,
            resource_id,
            &details_str,
            org_id,
            project_id,
            ip_address,
            user_agent
        ],
    )?;

    Ok(AuditLog {
        id,
        timestamp,
        actor_type,
        actor_id: actor_id.map(String::from),
        action: action.to_string(),
        resource_type: resource_type.to_string(),
        resource_id: resource_id.to_string(),
        details: details.cloned(),
        org_id: org_id.map(String::from),
        project_id: project_id.map(String::from),
        ip_address: ip_address.map(String::from),
        user_agent: user_agent.map(String::from),
    })
}

pub fn query_audit_logs(conn: &Connection, query: &AuditLogQuery) -> Result<Vec<AuditLog>> {
    let mut sql = String::from(
        "SELECT id, timestamp, actor_type, actor_id, action, resource_type, resource_id, details, org_id, project_id, ip_address, user_agent
         FROM audit_logs WHERE 1=1",
    );
    let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(ref actor_type) = query.actor_type {
        sql.push_str(" AND actor_type = ?");
        params_vec.push(Box::new(actor_type.as_str().to_string()));
    }
    if let Some(ref actor_id) = query.actor_id {
        sql.push_str(" AND actor_id = ?");
        params_vec.push(Box::new(actor_id.clone()));
    }
    if let Some(ref action) = query.action {
        sql.push_str(" AND action = ?");
        params_vec.push(Box::new(action.clone()));
    }
    if let Some(ref resource_type) = query.resource_type {
        sql.push_str(" AND resource_type = ?");
        params_vec.push(Box::new(resource_type.clone()));
    }
    if let Some(ref resource_id) = query.resource_id {
        sql.push_str(" AND resource_id = ?");
        params_vec.push(Box::new(resource_id.clone()));
    }
    if let Some(ref org_id) = query.org_id {
        sql.push_str(" AND org_id = ?");
        params_vec.push(Box::new(org_id.clone()));
    }
    if let Some(ref project_id) = query.project_id {
        sql.push_str(" AND project_id = ?");
        params_vec.push(Box::new(project_id.clone()));
    }
    if let Some(from_ts) = query.from_timestamp {
        sql.push_str(" AND timestamp >= ?");
        params_vec.push(Box::new(from_ts));
    }
    if let Some(to_ts) = query.to_timestamp {
        sql.push_str(" AND timestamp <= ?");
        params_vec.push(Box::new(to_ts));
    }

    sql.push_str(" ORDER BY timestamp DESC");

    if let Some(limit) = query.limit {
        sql.push_str(" LIMIT ?");
        params_vec.push(Box::new(limit));
    }
    if let Some(offset) = query.offset {
        sql.push_str(" OFFSET ?");
        params_vec.push(Box::new(offset));
    }

    let mut stmt = conn.prepare(&sql)?;
    let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();

    let logs = stmt
        .query_map(params_refs.as_slice(), |row| {
            let details_str: Option<String> = row.get(7)?;
            Ok(AuditLog {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                actor_type: ActorType::from_str(&row.get::<_, String>(2)?).unwrap(),
                actor_id: row.get(3)?,
                action: row.get(4)?,
                resource_type: row.get(5)?,
                resource_id: row.get(6)?,
                details: details_str.and_then(|s| serde_json::from_str(&s).ok()),
                org_id: row.get(8)?,
                project_id: row.get(9)?,
                ip_address: row.get(10)?,
                user_agent: row.get(11)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(logs)
}

// ============ Organizations ============

pub fn create_organization(conn: &Connection, input: &CreateOrganization) -> Result<Organization> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO organizations (id, name, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![&id, &input.name, now, now],
    )?;

    Ok(Organization {
        id,
        name: input.name.clone(),
        created_at: now,
        updated_at: now,
    })
}

pub fn get_organization_by_id(conn: &Connection, id: &str) -> Result<Option<Organization>> {
    conn.query_row(
        "SELECT id, name, created_at, updated_at FROM organizations WHERE id = ?1",
        params![id],
        |row| {
            Ok(Organization {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn list_organizations(conn: &Connection) -> Result<Vec<Organization>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, created_at, updated_at FROM organizations ORDER BY created_at DESC",
    )?;

    let orgs = stmt
        .query_map([], |row| {
            Ok(Organization {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(orgs)
}

pub fn update_organization(conn: &Connection, id: &str, input: &UpdateOrganization) -> Result<()> {
    let now = now();
    if let Some(ref name) = input.name {
        conn.execute(
            "UPDATE organizations SET name = ?1, updated_at = ?2 WHERE id = ?3",
            params![name, now, id],
        )?;
    }
    Ok(())
}

pub fn delete_organization(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM organizations WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

// ============ Org Members ============

pub fn create_org_member(
    conn: &Connection,
    org_id: &str,
    input: &CreateOrgMember,
    api_key: &str,
) -> Result<OrgMember> {
    let id = gen_id();
    let now = now();
    let api_key_hash = hash_api_key(api_key);

    conn.execute(
        "INSERT INTO org_members (id, org_id, email, name, role, api_key_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &id,
            org_id,
            &input.email,
            &input.name,
            input.role.as_str(),
            &api_key_hash,
            now
        ],
    )?;

    Ok(OrgMember {
        id,
        org_id: org_id.to_string(),
        email: input.email.clone(),
        name: input.name.clone(),
        role: input.role,
        api_key_hash,
        created_at: now,
    })
}

pub fn get_org_member_by_id(conn: &Connection, id: &str) -> Result<Option<OrgMember>> {
    conn.query_row(
        "SELECT id, org_id, email, name, role, api_key_hash, created_at
         FROM org_members WHERE id = ?1",
        params![id],
        |row| {
            Ok(OrgMember {
                id: row.get(0)?,
                org_id: row.get(1)?,
                email: row.get(2)?,
                name: row.get(3)?,
                role: OrgMemberRole::from_str(&row.get::<_, String>(4)?).unwrap(),
                api_key_hash: row.get(5)?,
                created_at: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn get_org_member_by_api_key(conn: &Connection, api_key: &str) -> Result<Option<OrgMember>> {
    let hash = hash_api_key(api_key);
    conn.query_row(
        "SELECT id, org_id, email, name, role, api_key_hash, created_at
         FROM org_members WHERE api_key_hash = ?1",
        params![hash],
        |row| {
            Ok(OrgMember {
                id: row.get(0)?,
                org_id: row.get(1)?,
                email: row.get(2)?,
                name: row.get(3)?,
                role: OrgMemberRole::from_str(&row.get::<_, String>(4)?).unwrap(),
                api_key_hash: row.get(5)?,
                created_at: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn list_org_members(conn: &Connection, org_id: &str) -> Result<Vec<OrgMember>> {
    let mut stmt = conn.prepare(
        "SELECT id, org_id, email, name, role, api_key_hash, created_at
         FROM org_members WHERE org_id = ?1 ORDER BY created_at DESC",
    )?;

    let members = stmt
        .query_map(params![org_id], |row| {
            Ok(OrgMember {
                id: row.get(0)?,
                org_id: row.get(1)?,
                email: row.get(2)?,
                name: row.get(3)?,
                role: OrgMemberRole::from_str(&row.get::<_, String>(4)?).unwrap(),
                api_key_hash: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(members)
}

pub fn update_org_member(conn: &Connection, id: &str, input: &UpdateOrgMember) -> Result<()> {
    if let Some(ref name) = input.name {
        conn.execute(
            "UPDATE org_members SET name = ?1 WHERE id = ?2",
            params![name, id],
        )?;
    }
    if let Some(role) = input.role {
        conn.execute(
            "UPDATE org_members SET role = ?1 WHERE id = ?2",
            params![role.as_str(), id],
        )?;
    }
    Ok(())
}

pub fn delete_org_member(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM org_members WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

// ============ Projects ============

pub fn create_project(
    conn: &Connection,
    org_id: &str,
    input: &CreateProject,
    private_key: &[u8],
    public_key: &str,
) -> Result<Project> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO projects (id, org_id, name, domain, license_key_prefix, private_key, public_key, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![&id, org_id, &input.name, &input.domain, &input.license_key_prefix, private_key, public_key, now, now],
    )?;

    Ok(Project {
        id,
        org_id: org_id.to_string(),
        name: input.name.clone(),
        domain: input.domain.clone(),
        license_key_prefix: input.license_key_prefix.clone(),
        private_key: private_key.to_vec(),
        public_key: public_key.to_string(),
        stripe_config: None,
        ls_config: None,
        default_provider: None,
        created_at: now,
        updated_at: now,
    })
}

pub fn get_project_by_id(conn: &Connection, id: &str) -> Result<Option<Project>> {
    conn.query_row(
        "SELECT id, org_id, name, domain, license_key_prefix, private_key, public_key, stripe_config, ls_config, default_provider, created_at, updated_at
         FROM projects WHERE id = ?1",
        params![id],
        |row| {
            let stripe_str: Option<String> = row.get(7)?;
            let ls_str: Option<String> = row.get(8)?;
            Ok(Project {
                id: row.get(0)?,
                org_id: row.get(1)?,
                name: row.get(2)?,
                domain: row.get(3)?,
                license_key_prefix: row.get(4)?,
                private_key: row.get(5)?,
                public_key: row.get(6)?,
                stripe_config: stripe_str.and_then(|s| serde_json::from_str(&s).ok()),
                ls_config: ls_str.and_then(|s| serde_json::from_str(&s).ok()),
                default_provider: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn list_projects_for_org(conn: &Connection, org_id: &str) -> Result<Vec<Project>> {
    let mut stmt = conn.prepare(
        "SELECT id, org_id, name, domain, license_key_prefix, private_key, public_key, stripe_config, ls_config, default_provider, created_at, updated_at
         FROM projects WHERE org_id = ?1 ORDER BY created_at DESC",
    )?;

    let projects = stmt
        .query_map(params![org_id], |row| {
            let stripe_str: Option<String> = row.get(7)?;
            let ls_str: Option<String> = row.get(8)?;
            Ok(Project {
                id: row.get(0)?,
                org_id: row.get(1)?,
                name: row.get(2)?,
                domain: row.get(3)?,
                license_key_prefix: row.get(4)?,
                private_key: row.get(5)?,
                public_key: row.get(6)?,
                stripe_config: stripe_str.and_then(|s| serde_json::from_str(&s).ok()),
                ls_config: ls_str.and_then(|s| serde_json::from_str(&s).ok()),
                default_provider: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(projects)
}

pub fn update_project(conn: &Connection, id: &str, input: &UpdateProject) -> Result<()> {
    let now = now();

    if let Some(ref name) = input.name {
        conn.execute(
            "UPDATE projects SET name = ?1, updated_at = ?2 WHERE id = ?3",
            params![name, now, id],
        )?;
    }
    if let Some(ref domain) = input.domain {
        conn.execute(
            "UPDATE projects SET domain = ?1, updated_at = ?2 WHERE id = ?3",
            params![domain, now, id],
        )?;
    }
    if let Some(ref license_key_prefix) = input.license_key_prefix {
        conn.execute(
            "UPDATE projects SET license_key_prefix = ?1, updated_at = ?2 WHERE id = ?3",
            params![license_key_prefix, now, id],
        )?;
    }
    if let Some(ref stripe_config) = input.stripe_config {
        let json = serde_json::to_string(stripe_config)?;
        conn.execute(
            "UPDATE projects SET stripe_config = ?1, updated_at = ?2 WHERE id = ?3",
            params![json, now, id],
        )?;
    }
    if let Some(ref ls_config) = input.ls_config {
        let json = serde_json::to_string(ls_config)?;
        conn.execute(
            "UPDATE projects SET ls_config = ?1, updated_at = ?2 WHERE id = ?3",
            params![json, now, id],
        )?;
    }
    if let Some(ref default_provider) = input.default_provider {
        // Some(None) clears the value, Some(Some(value)) sets it
        conn.execute(
            "UPDATE projects SET default_provider = ?1, updated_at = ?2 WHERE id = ?3",
            params![default_provider, now, id],
        )?;
    }
    Ok(())
}

pub fn delete_project(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM projects WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
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
        params![&id, &input.org_member_id, project_id, input.role.as_str(), now],
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
    conn.query_row(
        "SELECT id, org_member_id, project_id, role, created_at
         FROM project_members WHERE org_member_id = ?1 AND project_id = ?2",
        params![org_member_id, project_id],
        |row| {
            Ok(ProjectMember {
                id: row.get(0)?,
                org_member_id: row.get(1)?,
                project_id: row.get(2)?,
                role: ProjectMemberRole::from_str(&row.get::<_, String>(3)?).unwrap(),
                created_at: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn list_project_members(conn: &Connection, project_id: &str) -> Result<Vec<ProjectMemberWithDetails>> {
    let mut stmt = conn.prepare(
        "SELECT pm.id, pm.org_member_id, pm.project_id, pm.role, pm.created_at, om.email, om.name
         FROM project_members pm
         JOIN org_members om ON pm.org_member_id = om.id
         WHERE pm.project_id = ?1
         ORDER BY pm.created_at DESC",
    )?;

    let members = stmt
        .query_map(params![project_id], |row| {
            Ok(ProjectMemberWithDetails {
                id: row.get(0)?,
                org_member_id: row.get(1)?,
                project_id: row.get(2)?,
                role: ProjectMemberRole::from_str(&row.get::<_, String>(3)?).unwrap(),
                created_at: row.get(4)?,
                email: row.get(5)?,
                name: row.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(members)
}

pub fn update_project_member(conn: &Connection, id: &str, input: &UpdateProjectMember) -> Result<()> {
    conn.execute(
        "UPDATE project_members SET role = ?1 WHERE id = ?2",
        params![input.role.as_str(), id],
    )?;
    Ok(())
}

pub fn delete_project_member(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM project_members WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

// ============ Products ============

pub fn create_product(conn: &Connection, project_id: &str, input: &CreateProduct) -> Result<Product> {
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
    })
}

pub fn get_product_by_id(conn: &Connection, id: &str) -> Result<Option<Product>> {
    conn.query_row(
        "SELECT id, project_id, name, tier, license_exp_days, updates_exp_days, activation_limit, device_limit, features, created_at
         FROM products WHERE id = ?1",
        params![id],
        |row| {
            let features_str: String = row.get(8)?;
            Ok(Product {
                id: row.get(0)?,
                project_id: row.get(1)?,
                name: row.get(2)?,
                tier: row.get(3)?,
                license_exp_days: row.get(4)?,
                updates_exp_days: row.get(5)?,
                activation_limit: row.get(6)?,
                device_limit: row.get(7)?,
                features: serde_json::from_str(&features_str).unwrap_or_default(),
                created_at: row.get(9)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn list_products_for_project(conn: &Connection, project_id: &str) -> Result<Vec<Product>> {
    let mut stmt = conn.prepare(
        "SELECT id, project_id, name, tier, license_exp_days, updates_exp_days, activation_limit, device_limit, features, created_at
         FROM products WHERE project_id = ?1 ORDER BY created_at DESC",
    )?;

    let products = stmt
        .query_map(params![project_id], |row| {
            let features_str: String = row.get(8)?;
            Ok(Product {
                id: row.get(0)?,
                project_id: row.get(1)?,
                name: row.get(2)?,
                tier: row.get(3)?,
                license_exp_days: row.get(4)?,
                updates_exp_days: row.get(5)?,
                activation_limit: row.get(6)?,
                device_limit: row.get(7)?,
                features: serde_json::from_str(&features_str).unwrap_or_default(),
                created_at: row.get(9)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(products)
}

pub fn update_product(conn: &Connection, id: &str, input: &UpdateProduct) -> Result<()> {
    if let Some(ref name) = input.name {
        conn.execute("UPDATE products SET name = ?1 WHERE id = ?2", params![name, id])?;
    }
    if let Some(ref tier) = input.tier {
        conn.execute("UPDATE products SET tier = ?1 WHERE id = ?2", params![tier, id])?;
    }
    if let Some(ref exp) = input.license_exp_days {
        conn.execute("UPDATE products SET license_exp_days = ?1 WHERE id = ?2", params![exp, id])?;
    }
    if let Some(ref exp) = input.updates_exp_days {
        conn.execute("UPDATE products SET updates_exp_days = ?1 WHERE id = ?2", params![exp, id])?;
    }
    if let Some(limit) = input.activation_limit {
        conn.execute("UPDATE products SET activation_limit = ?1 WHERE id = ?2", params![limit, id])?;
    }
    if let Some(limit) = input.device_limit {
        conn.execute("UPDATE products SET device_limit = ?1 WHERE id = ?2", params![limit, id])?;
    }
    if let Some(ref features) = input.features {
        let json = serde_json::to_string(features)?;
        conn.execute("UPDATE products SET features = ?1 WHERE id = ?2", params![json, id])?;
    }
    Ok(())
}

pub fn delete_product(conn: &Connection, id: &str) -> Result<bool> {
    let deleted = conn.execute("DELETE FROM products WHERE id = ?1", params![id])?;
    Ok(deleted > 0)
}

// ============ License Keys ============

pub fn generate_license_key_string(prefix: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();

    let mut part = || -> String {
        (0..4).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
    };

    format!("{}-{}-{}-{}-{}", prefix, part(), part(), part(), part())
}

pub fn create_license_key(
    conn: &Connection,
    product_id: &str,
    prefix: &str,
    input: &CreateLicenseKey,
) -> Result<LicenseKey> {
    let id = gen_id();
    let key = generate_license_key_string(prefix);
    let now = now();

    conn.execute(
        "INSERT INTO license_keys (id, key, product_id, customer_id, activation_count, revoked, revoked_jtis, created_at, expires_at, updates_expires_at, payment_provider, payment_provider_customer_id, payment_provider_subscription_id)
         VALUES (?1, ?2, ?3, ?4, 0, 0, '[]', ?5, ?6, ?7, ?8, ?9, ?10)",
        params![&id, &key, product_id, &input.customer_id, now, input.expires_at, input.updates_expires_at, &input.payment_provider, &input.payment_provider_customer_id, &input.payment_provider_subscription_id],
    )?;

    Ok(LicenseKey {
        id,
        key,
        product_id: product_id.to_string(),
        customer_id: input.customer_id.clone(),
        activation_count: 0,
        revoked: false,
        revoked_jtis: vec![],
        created_at: now,
        expires_at: input.expires_at,
        updates_expires_at: input.updates_expires_at,
        payment_provider: input.payment_provider.clone(),
        payment_provider_customer_id: input.payment_provider_customer_id.clone(),
        payment_provider_subscription_id: input.payment_provider_subscription_id.clone(),
    })
}

pub fn get_license_key_by_id(conn: &Connection, id: &str) -> Result<Option<LicenseKey>> {
    conn.query_row(
        "SELECT id, key, product_id, customer_id, activation_count, revoked, revoked_jtis, created_at, expires_at, updates_expires_at, payment_provider, payment_provider_customer_id, payment_provider_subscription_id
         FROM license_keys WHERE id = ?1",
        params![id],
        |row| {
            let jtis_str: String = row.get(6)?;
            Ok(LicenseKey {
                id: row.get(0)?,
                key: row.get(1)?,
                product_id: row.get(2)?,
                customer_id: row.get(3)?,
                activation_count: row.get(4)?,
                revoked: row.get::<_, i32>(5)? != 0,
                revoked_jtis: serde_json::from_str(&jtis_str).unwrap_or_default(),
                created_at: row.get(7)?,
                expires_at: row.get(8)?,
                updates_expires_at: row.get(9)?,
                payment_provider: row.get(10)?,
                payment_provider_customer_id: row.get(11)?,
                payment_provider_subscription_id: row.get(12)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn get_license_key_by_key(conn: &Connection, key: &str) -> Result<Option<LicenseKey>> {
    conn.query_row(
        "SELECT id, key, product_id, customer_id, activation_count, revoked, revoked_jtis, created_at, expires_at, updates_expires_at, payment_provider, payment_provider_customer_id, payment_provider_subscription_id
         FROM license_keys WHERE key = ?1",
        params![key],
        |row| {
            let jtis_str: String = row.get(6)?;
            Ok(LicenseKey {
                id: row.get(0)?,
                key: row.get(1)?,
                product_id: row.get(2)?,
                customer_id: row.get(3)?,
                activation_count: row.get(4)?,
                revoked: row.get::<_, i32>(5)? != 0,
                revoked_jtis: serde_json::from_str(&jtis_str).unwrap_or_default(),
                created_at: row.get(7)?,
                expires_at: row.get(8)?,
                updates_expires_at: row.get(9)?,
                payment_provider: row.get(10)?,
                payment_provider_customer_id: row.get(11)?,
                payment_provider_subscription_id: row.get(12)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn list_license_keys_for_project(conn: &Connection, project_id: &str) -> Result<Vec<LicenseKeyWithProduct>> {
    let mut stmt = conn.prepare(
        "SELECT lk.id, lk.key, lk.product_id, lk.customer_id, lk.activation_count, lk.revoked, lk.revoked_jtis, lk.created_at, lk.expires_at, lk.updates_expires_at, lk.payment_provider, lk.payment_provider_customer_id, lk.payment_provider_subscription_id, p.name, p.project_id
         FROM license_keys lk
         JOIN products p ON lk.product_id = p.id
         WHERE p.project_id = ?1
         ORDER BY lk.created_at DESC",
    )?;

    let licenses = stmt
        .query_map(params![project_id], |row| {
            let jtis_str: String = row.get(6)?;
            Ok(LicenseKeyWithProduct {
                license: LicenseKey {
                    id: row.get(0)?,
                    key: row.get(1)?,
                    product_id: row.get(2)?,
                    customer_id: row.get(3)?,
                    activation_count: row.get(4)?,
                    revoked: row.get::<_, i32>(5)? != 0,
                    revoked_jtis: serde_json::from_str(&jtis_str).unwrap_or_default(),
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    updates_expires_at: row.get(9)?,
                    payment_provider: row.get(10)?,
                    payment_provider_customer_id: row.get(11)?,
                    payment_provider_subscription_id: row.get(12)?,
                },
                product_name: row.get(13)?,
                project_id: row.get(14)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(licenses)
}

pub fn increment_activation_count(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE license_keys SET activation_count = activation_count + 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

pub fn revoke_license_key(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("UPDATE license_keys SET revoked = 1 WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn add_revoked_jti(conn: &Connection, license_id: &str, jti: &str) -> Result<()> {
    let license = get_license_key_by_id(conn, license_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    let mut jtis = license.revoked_jtis;
    jtis.push(jti.to_string());
    let json = serde_json::to_string(&jtis)?;

    conn.execute(
        "UPDATE license_keys SET revoked_jtis = ?1 WHERE id = ?2",
        params![json, license_id],
    )?;
    Ok(())
}

/// Find a license by payment provider and subscription ID (for subscription renewals)
pub fn get_license_key_by_subscription(
    conn: &Connection,
    provider: &str,
    subscription_id: &str,
) -> Result<Option<LicenseKey>> {
    conn.query_row(
        "SELECT id, key, product_id, customer_id, activation_count, revoked, revoked_jtis, created_at, expires_at, updates_expires_at, payment_provider, payment_provider_customer_id, payment_provider_subscription_id
         FROM license_keys WHERE payment_provider = ?1 AND payment_provider_subscription_id = ?2",
        params![provider, subscription_id],
        |row| {
            let jtis_str: String = row.get(6)?;
            Ok(LicenseKey {
                id: row.get(0)?,
                key: row.get(1)?,
                product_id: row.get(2)?,
                customer_id: row.get(3)?,
                activation_count: row.get(4)?,
                revoked: row.get::<_, i32>(5)? != 0,
                revoked_jtis: serde_json::from_str(&jtis_str).unwrap_or_default(),
                created_at: row.get(7)?,
                expires_at: row.get(8)?,
                updates_expires_at: row.get(9)?,
                payment_provider: row.get(10)?,
                payment_provider_customer_id: row.get(11)?,
                payment_provider_subscription_id: row.get(12)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

/// Extend license expiration dates (for subscription renewals)
pub fn extend_license_expiration(
    conn: &Connection,
    license_id: &str,
    new_expires_at: Option<i64>,
    new_updates_expires_at: Option<i64>,
) -> Result<()> {
    conn.execute(
        "UPDATE license_keys SET expires_at = ?1, updates_expires_at = ?2 WHERE id = ?3",
        params![new_expires_at, new_updates_expires_at, license_id],
    )?;
    Ok(())
}

// ============ Redemption Codes ============

const REDEMPTION_CODE_TTL_SECONDS: i64 = 30 * 60; // 30 minutes

pub fn generate_redemption_code_string() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    // Use URL-safe base64-like characters, shorter than license keys
    let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
        .chars()
        .collect();

    (0..16)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

pub fn create_redemption_code(
    conn: &Connection,
    license_key_id: &str,
) -> Result<RedemptionCode> {
    let id = gen_id();
    let code = generate_redemption_code_string();
    let now = now();
    let expires_at = now + REDEMPTION_CODE_TTL_SECONDS;

    conn.execute(
        "INSERT INTO redemption_codes (id, code, license_key_id, expires_at, used, created_at)
         VALUES (?1, ?2, ?3, ?4, 0, ?5)",
        params![&id, &code, license_key_id, expires_at, now],
    )?;

    Ok(RedemptionCode {
        id,
        code,
        license_key_id: license_key_id.to_string(),
        expires_at,
        used: false,
        created_at: now,
    })
}

pub fn get_redemption_code_by_code(conn: &Connection, code: &str) -> Result<Option<RedemptionCode>> {
    conn.query_row(
        "SELECT id, code, license_key_id, expires_at, used, created_at
         FROM redemption_codes WHERE code = ?1",
        params![code],
        |row| {
            Ok(RedemptionCode {
                id: row.get(0)?,
                code: row.get(1)?,
                license_key_id: row.get(2)?,
                expires_at: row.get(3)?,
                used: row.get::<_, i32>(4)? != 0,
                created_at: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn mark_redemption_code_used(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE redemption_codes SET used = 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

pub fn cleanup_expired_redemption_codes(conn: &Connection) -> Result<usize> {
    let now = now();
    let deleted = conn.execute(
        "DELETE FROM redemption_codes WHERE expires_at < ?1 OR used = 1",
        params![now],
    )?;
    Ok(deleted)
}

// ============ Devices ============

pub fn create_device(
    conn: &Connection,
    license_key_id: &str,
    device_id: &str,
    device_type: DeviceType,
    jti: &str,
    name: Option<&str>,
) -> Result<Device> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO devices (id, license_key_id, device_id, device_type, name, jti, activated_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![&id, license_key_id, device_id, device_type.as_str(), name, jti, now, now],
    )?;

    Ok(Device {
        id,
        license_key_id: license_key_id.to_string(),
        device_id: device_id.to_string(),
        device_type,
        name: name.map(String::from),
        jti: jti.to_string(),
        activated_at: now,
        last_seen_at: now,
    })
}

pub fn get_device_by_jti(conn: &Connection, jti: &str) -> Result<Option<Device>> {
    conn.query_row(
        "SELECT id, license_key_id, device_id, device_type, name, jti, activated_at, last_seen_at
         FROM devices WHERE jti = ?1",
        params![jti],
        |row| {
            Ok(Device {
                id: row.get(0)?,
                license_key_id: row.get(1)?,
                device_id: row.get(2)?,
                device_type: DeviceType::from_str(&row.get::<_, String>(3)?).unwrap(),
                name: row.get(4)?,
                jti: row.get(5)?,
                activated_at: row.get(6)?,
                last_seen_at: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn get_device_for_license(
    conn: &Connection,
    license_key_id: &str,
    device_id: &str,
) -> Result<Option<Device>> {
    conn.query_row(
        "SELECT id, license_key_id, device_id, device_type, name, jti, activated_at, last_seen_at
         FROM devices WHERE license_key_id = ?1 AND device_id = ?2",
        params![license_key_id, device_id],
        |row| {
            Ok(Device {
                id: row.get(0)?,
                license_key_id: row.get(1)?,
                device_id: row.get(2)?,
                device_type: DeviceType::from_str(&row.get::<_, String>(3)?).unwrap(),
                name: row.get(4)?,
                jti: row.get(5)?,
                activated_at: row.get(6)?,
                last_seen_at: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn list_devices_for_license(conn: &Connection, license_key_id: &str) -> Result<Vec<Device>> {
    let mut stmt = conn.prepare(
        "SELECT id, license_key_id, device_id, device_type, name, jti, activated_at, last_seen_at
         FROM devices WHERE license_key_id = ?1 ORDER BY activated_at DESC",
    )?;

    let devices = stmt
        .query_map(params![license_key_id], |row| {
            Ok(Device {
                id: row.get(0)?,
                license_key_id: row.get(1)?,
                device_id: row.get(2)?,
                device_type: DeviceType::from_str(&row.get::<_, String>(3)?).unwrap(),
                name: row.get(4)?,
                jti: row.get(5)?,
                activated_at: row.get(6)?,
                last_seen_at: row.get(7)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(devices)
}

pub fn count_devices_for_license(conn: &Connection, license_key_id: &str) -> Result<i32> {
    conn.query_row(
        "SELECT COUNT(*) FROM devices WHERE license_key_id = ?1",
        params![license_key_id],
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

pub fn delete_device_by_device_id(
    conn: &Connection,
    license_key_id: &str,
    device_id: &str,
) -> Result<bool> {
    let deleted = conn.execute(
        "DELETE FROM devices WHERE license_key_id = ?1 AND device_id = ?2",
        params![license_key_id, device_id],
    )?;
    Ok(deleted > 0)
}

// ============ Payment Sessions ============

pub fn create_payment_session(conn: &Connection, input: &CreatePaymentSession) -> Result<PaymentSession> {
    let id = gen_id();
    let now = now();

    conn.execute(
        "INSERT INTO payment_sessions (id, product_id, device_id, device_type, customer_id, created_at, completed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
        params![&id, &input.product_id, &input.device_id, input.device_type.as_str(), &input.customer_id, now],
    )?;

    Ok(PaymentSession {
        id,
        product_id: input.product_id.clone(),
        device_id: input.device_id.clone(),
        device_type: input.device_type,
        customer_id: input.customer_id.clone(),
        created_at: now,
        completed: false,
    })
}

pub fn get_payment_session(conn: &Connection, id: &str) -> Result<Option<PaymentSession>> {
    conn.query_row(
        "SELECT id, product_id, device_id, device_type, customer_id, created_at, completed
         FROM payment_sessions WHERE id = ?1",
        params![id],
        |row| {
            Ok(PaymentSession {
                id: row.get(0)?,
                product_id: row.get(1)?,
                device_id: row.get(2)?,
                device_type: DeviceType::from_str(&row.get::<_, String>(3)?).unwrap(),
                customer_id: row.get(4)?,
                created_at: row.get(5)?,
                completed: row.get::<_, i32>(6)? != 0,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn mark_payment_session_completed(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE payment_sessions SET completed = 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

// ============ Audit Log Maintenance ============

/// Purge audit logs older than the specified number of days.
/// Returns the number of deleted records.
/// This should be called periodically (e.g., on startup or via cron) for GDPR compliance.
pub fn purge_old_audit_logs(conn: &Connection, retention_days: i64) -> Result<usize> {
    let cutoff = now() - (retention_days * 86400);
    let deleted = conn.execute(
        "DELETE FROM audit_logs WHERE timestamp < ?1",
        params![cutoff],
    )?;
    Ok(deleted)
}
