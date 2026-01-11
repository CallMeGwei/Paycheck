use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ActorType {
    User,
    Public,
    System,
}

/// All possible audit log actions.
/// Using an enum ensures compile-time checking and prevents typos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum AuditAction {
    // User management
    CreateUser,
    UpdateUser,
    DeleteUser,

    // Operator management
    CreateOperator,
    UpdateOperator,
    DeleteOperator,
    BootstrapOperator,

    // Organization management
    CreateOrganization,
    UpdateOrganization,
    DeleteOrganization,

    // Org member management
    CreateOrgMember,
    UpdateOrgMember,
    DeleteOrgMember,

    // Project management
    CreateProject,
    UpdateProject,
    DeleteProject,

    // Project member management
    CreateProjectMember,
    UpdateProjectMember,
    DeleteProjectMember,

    // Product management
    CreateProduct,
    UpdateProduct,
    DeleteProduct,

    // Payment config management
    CreatePaymentConfig,
    UpdatePaymentConfig,
    DeletePaymentConfig,

    // License management
    CreateLicense,
    UpdateLicenseEmail,
    RevokeLicense,

    // Activation
    GenerateActivationCode,

    // Device management
    DeactivateDevice,

    // Token operations
    RefreshToken,

    // API key management
    CreateApiKey,
    RevokeApiKey,

    // Seeding (dev/bootstrap)
    SeedOperator,
    SeedOrganization,
    SeedOrgMember,
    SeedProject,
    SeedProduct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: i64,
    pub actor_type: ActorType,
    /// User ID (references users.id, null for public/system)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// User email (denormalized for query convenience)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    /// User name (denormalized for query convenience)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    /// Name of the resource being acted upon (e.g., organization name, product name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    pub details: Option<serde_json::Value>,
    pub org_id: Option<String>,
    /// Name of the organization at the time of the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
    pub project_id: Option<String>,
    /// Name of the project at the time of the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Names to include in an audit log entry for human-readable display.
/// All fields are optional - IDs will be shown as fallback.
#[derive(Debug, Clone, Default)]
pub struct AuditLogNames {
    /// Name of the user performing the action
    pub user_name: Option<String>,
    /// Email of the user performing the action
    pub user_email: Option<String>,
    /// Name of the resource being acted upon
    pub resource_name: Option<String>,
    /// Name of the organization context
    pub org_name: Option<String>,
    /// Name of the project context
    pub project_name: Option<String>,
}

impl AuditLogNames {
    /// Set the resource name.
    pub fn resource(mut self, name: impl Into<Option<String>>) -> Self {
        self.resource_name = name.into();
        self
    }

    /// Set the organization context name.
    pub fn org(mut self, name: impl Into<Option<String>>) -> Self {
        self.org_name = name.into();
        self
    }

    /// Set the project context name.
    pub fn project(mut self, name: impl Into<Option<String>>) -> Self {
        self.project_name = name.into();
        self
    }
}

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub actor_type: Option<ActorType>,
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub org_id: Option<String>,
    pub project_id: Option<String>,
    pub from_timestamp: Option<i64>,
    pub to_timestamp: Option<i64>,
    /// Maximum number of items to return (default: 50, max: 100)
    pub limit: Option<i64>,
    /// Number of items to skip (default: 0)
    pub offset: Option<i64>,
}

impl AuditLogQuery {
    /// Get the limit, clamped to valid range
    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }

    /// Get the offset, minimum 0
    pub fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

impl AuditLog {
    /// Format as a human-readable string for display.
    ///
    /// Format: `[TIMESTAMP] [ActorType] "User" VERB RESOURCE in "Org" [project "Project"]`
    ///
    /// Examples:
    /// - `[2024-01-15 14:32:05] [User] "John Smith" created organization "Acme Corp"`
    /// - `[2024-01-15 14:32:05] [System] seeded operator "Dev Operator"`
    pub fn formatted(&self) -> String {
        use chrono::{TimeZone, Utc};

        // Timestamp
        let timestamp = Utc
            .timestamp_opt(self.timestamp, 0)
            .single()
            .map(|dt| format!("[{}]", dt.format("%Y-%m-%d %H:%M:%S")))
            .unwrap_or_else(|| format!("[{}]", self.timestamp));

        // Actor type in brackets - fixed width for alignment
        let actor_type = match self.actor_type {
            ActorType::User => "[User]  ",
            ActorType::Public => "[Public]",
            ActorType::System => "[System]",
        };

        // User display: prefer name, then email, then ID
        let user_display = self
            .user_name
            .as_ref()
            .map(|n| format!("\"{}\"", n))
            .or_else(|| self.user_email.as_ref().map(|e| format!("<{}>", e)))
            .or_else(|| self.user_id.as_ref().map(|id| format!("({})", id)))
            .unwrap_or_default();

        // Convert action to past-tense verb + object
        let verb_phrase = Self::action_to_verb_phrase(&self.action, &self.resource_type);

        // Resource: prefer name (quoted), fall back to ID
        let resource_display = self
            .resource_name
            .as_ref()
            .map(|n| format!("\"{}\"", n))
            .unwrap_or_else(|| self.resource_id.clone());

        // Org context: "in "Org Name"" or "in (org_id)"
        let org_context = if let Some(ref name) = self.org_name {
            format!(" in \"{}\"", name)
        } else if let Some(ref id) = self.org_id {
            format!(" in ({})", id)
        } else {
            String::new()
        };

        // Project context: only show if we have a name AND it differs from resource_name
        let project_context = match (&self.project_name, &self.resource_name) {
            (Some(proj_name), Some(res_name)) if proj_name == res_name => {
                // Skip if project name equals resource name (e.g., when creating a project)
                String::new()
            }
            (Some(name), _) => format!(" project \"{}\"", name),
            // Don't show project ID fallback - UUIDs aren't useful for humans
            _ => String::new(),
        };

        format!(
            "{} {} {} {} {}{}{}",
            timestamp,
            actor_type,
            user_display,
            verb_phrase,
            resource_display,
            org_context,
            project_context
        )
    }

    /// Convert an action string to a past-tense verb phrase.
    /// e.g., "create_organization" -> "created organization"
    fn action_to_verb_phrase(action: &str, resource_type: &str) -> String {
        let parts: Vec<&str> = action.split('_').collect();
        if parts.is_empty() {
            return action.to_string();
        }

        let verb = Self::to_past_tense(parts[0]);

        // If action has more parts, use them as the object
        // Otherwise fall back to resource_type
        if parts.len() > 1 {
            let object = parts[1..].join(" ");
            format!("{} {}", verb, object)
        } else {
            format!("{} {}", verb, resource_type)
        }
    }

    /// Convert a verb to past tense.
    fn to_past_tense(verb: &str) -> &str {
        match verb {
            "create" => "created",
            "update" => "updated",
            "delete" => "deleted",
            "revoke" => "revoked",
            "generate" => "generated",
            "refresh" => "refreshed",
            "send" => "sent",
            "deactivate" => "deactivated",
            "seed" => "seeded",
            "bootstrap" => "bootstrapped",
            "add" => "added",
            "remove" => "removed",
            "lookup" => "looked up",
            "list" => "listed",
            "get" => "retrieved",
            "request" => "requested",
            "extend" => "extended",
            "activate" => "activated",
            "mark" => "marked",
            "increment" => "incremented",
            "purge" => "purged",
            other => other, // Unknown verbs pass through unchanged
        }
    }
}

/// Wrapper for AuditLog that includes a human-readable `formatted` field.
/// Used in JSON responses so Console can display readable text without calling
/// the separate text endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct AuditLogResponse {
    #[serde(flatten)]
    pub log: AuditLog,
    /// Human-readable formatted string (excludes ID since it's already in `log.id`)
    pub formatted: String,
}

impl From<AuditLog> for AuditLogResponse {
    fn from(log: AuditLog) -> Self {
        let formatted = log.formatted();
        Self { log, formatted }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_formatted_basic() {
        let log = AuditLog {
            id: "log12345678".to_string(),
            timestamp: 1704067200, // 2024-01-01T00:00:00Z
            actor_type: ActorType::User,
            user_id: Some("user123".to_string()),
            user_email: Some("john@example.com".to_string()),
            user_name: Some("John Smith".to_string()),
            action: "create_organization".to_string(),
            resource_type: "organization".to_string(),
            resource_id: "org456".to_string(),
            resource_name: Some("Acme Corp".to_string()),
            details: None,
            org_id: None, // Org creation doesn't have org context
            org_name: None,
            project_id: None,
            project_name: None,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("test-agent".to_string()),
        };

        let formatted = log.formatted();
        // Expected: [2024-01-01 00:00:00] [User]   "John Smith" created organization "Acme Corp"
        assert!(formatted.contains("[2024-01-01 00:00:00]"));
        assert!(formatted.contains("[User]"));
        assert!(formatted.contains("\"John Smith\""));
        assert!(formatted.contains("created organization"));
        assert!(formatted.contains("\"Acme Corp\""));
    }

    #[test]
    fn test_formatted_system() {
        let log = AuditLog {
            id: "log12345678".to_string(),
            timestamp: 1704067200,
            actor_type: ActorType::System,
            user_id: None,
            user_email: None,
            user_name: None,
            action: "seed_operator".to_string(),
            resource_type: "operator".to_string(),
            resource_id: "op123".to_string(),
            resource_name: Some("Dev Operator".to_string()),
            details: None,
            org_id: None,
            org_name: None,
            project_id: None,
            project_name: None,
            ip_address: None,
            user_agent: None,
        };

        let formatted = log.formatted();
        // Expected: [2024-01-01 00:00:00] [System] seeded operator "Dev Operator"
        assert!(formatted.contains("[System]"));
        assert!(formatted.contains("seeded operator"));
        assert!(formatted.contains("\"Dev Operator\""));
    }

    #[test]
    fn test_formatted_project_not_duplicated() {
        // When resource_name == project_name, project context should be skipped
        let log = AuditLog {
            id: "log12345678".to_string(),
            timestamp: 1704067200,
            actor_type: ActorType::User,
            user_id: Some("user123".to_string()),
            user_email: None,
            user_name: Some("Jane Doe".to_string()),
            action: "create_project".to_string(),
            resource_type: "project".to_string(),
            resource_id: "proj123".to_string(),
            resource_name: Some("My Project".to_string()),
            details: None,
            org_id: Some("org456".to_string()),
            org_name: Some("Acme Corp".to_string()),
            project_id: Some("proj123".to_string()),
            project_name: Some("My Project".to_string()), // Same as resource_name
            ip_address: None,
            user_agent: None,
        };

        let formatted = log.formatted();
        // Project context should be skipped since it equals resource name
        assert!(formatted.contains("created project \"My Project\""));
        assert!(formatted.contains("in \"Acme Corp\""));
        // Count occurrences of "My Project" - should only appear once (in the resource, not in project context)
        assert_eq!(formatted.matches("\"My Project\"").count(), 1);
    }

    #[test]
    fn test_formatted_fallback_to_ids() {
        let log = AuditLog {
            id: "log12345678".to_string(),
            timestamp: 1704067200,
            actor_type: ActorType::User,
            user_id: Some("user123".to_string()),
            user_email: None,
            user_name: None, // No name, should fall back to ID
            action: "create_organization".to_string(),
            resource_type: "organization".to_string(),
            resource_id: "org456".to_string(),
            resource_name: None, // No name, should fall back to ID
            details: None,
            org_id: Some("org789".to_string()),
            org_name: None, // No name, should fall back to ID
            project_id: None,
            project_name: None,
            ip_address: None,
            user_agent: None,
        };

        let formatted = log.formatted();
        assert!(formatted.contains("(user123)")); // User ID in parens
        assert!(formatted.contains("org456")); // Resource ID without parens
        assert!(formatted.contains("in (org789)")); // Org ID in parens
    }

    #[test]
    fn test_action_to_verb_phrase() {
        assert_eq!(
            AuditLog::action_to_verb_phrase("create_organization", "organization"),
            "created organization"
        );
        assert_eq!(
            AuditLog::action_to_verb_phrase("revoke_license", "license"),
            "revoked license"
        );
        assert_eq!(
            AuditLog::action_to_verb_phrase("send_activation_code", "license"),
            "sent activation code"
        );
        assert_eq!(
            AuditLog::action_to_verb_phrase("deactivate_device", "device"),
            "deactivated device"
        );
    }

    #[test]
    fn test_audit_log_response_includes_formatted() {
        let log = AuditLog {
            id: "log12345678".to_string(),
            timestamp: 1704067200,
            actor_type: ActorType::User,
            user_id: Some("user123".to_string()),
            user_email: Some("john@example.com".to_string()),
            user_name: Some("John Smith".to_string()),
            action: "create_organization".to_string(),
            resource_type: "organization".to_string(),
            resource_id: "org456".to_string(),
            resource_name: Some("Acme Corp".to_string()),
            details: None,
            org_id: None,
            org_name: None,
            project_id: None,
            project_name: None,
            ip_address: None,
            user_agent: None,
        };

        let response: AuditLogResponse = log.into();
        assert!(response.formatted.contains("[User]"));
        assert!(response.formatted.contains("\"John Smith\""));
        assert!(response.formatted.contains("created organization"));
        assert_eq!(response.log.id, "log12345678");
    }
}
