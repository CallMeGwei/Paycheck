use rusqlite::Connection;

/// Initialize the main database schema (everything except audit logs)
pub fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        -- Operators (Paycheck ops team)
        CREATE TABLE IF NOT EXISTS operators (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'view')),
            api_key_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            created_by TEXT REFERENCES operators(id)
        );

        -- Organizations (customers - indie devs, companies)
        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            stripe_config TEXT,
            ls_config TEXT,
            default_provider TEXT CHECK (default_provider IS NULL OR default_provider IN ('stripe', 'lemonsqueezy')),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        -- Organization members
        CREATE TABLE IF NOT EXISTS org_members (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            email TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
            api_key_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(org_id, email)
        );
        CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_id);
        CREATE INDEX IF NOT EXISTS idx_org_members_email ON org_members(email);

        -- Projects (software products being licensed)
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            license_key_prefix TEXT NOT NULL DEFAULT 'PC',
            private_key BLOB NOT NULL,
            public_key TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id);
        CREATE INDEX IF NOT EXISTS idx_projects_domain ON projects(domain);

        -- Project members (for 'member' role org members who need explicit access)
        CREATE TABLE IF NOT EXISTS project_members (
            id TEXT PRIMARY KEY,
            org_member_id TEXT NOT NULL REFERENCES org_members(id) ON DELETE CASCADE,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK (role IN ('admin', 'view')),
            created_at INTEGER NOT NULL,
            UNIQUE(org_member_id, project_id)
        );
        CREATE INDEX IF NOT EXISTS idx_project_members_project ON project_members(project_id);
        CREATE INDEX IF NOT EXISTS idx_project_members_member ON project_members(org_member_id);

        -- Products (tiers/plans within a project)
        CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            tier TEXT NOT NULL,
            license_exp_days INTEGER,
            updates_exp_days INTEGER,
            activation_limit INTEGER NOT NULL DEFAULT 0,
            device_limit INTEGER NOT NULL DEFAULT 0,
            features TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_products_project ON products(project_id);

        -- License keys
        CREATE TABLE IF NOT EXISTS license_keys (
            id TEXT PRIMARY KEY,
            key TEXT NOT NULL UNIQUE,
            product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            customer_id TEXT,
            activation_count INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0,
            revoked_jtis TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            updates_expires_at INTEGER,
            payment_provider TEXT,
            payment_provider_customer_id TEXT,
            payment_provider_subscription_id TEXT,
            payment_provider_order_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_license_keys_product ON license_keys(product_id);
        CREATE INDEX IF NOT EXISTS idx_license_keys_key ON license_keys(key);
        CREATE INDEX IF NOT EXISTS idx_license_keys_customer ON license_keys(customer_id);
        CREATE INDEX IF NOT EXISTS idx_license_keys_provider_customer ON license_keys(payment_provider, payment_provider_customer_id);
        CREATE INDEX IF NOT EXISTS idx_license_keys_provider_subscription ON license_keys(payment_provider, payment_provider_subscription_id);
        CREATE INDEX IF NOT EXISTS idx_license_keys_provider_order ON license_keys(payment_provider, payment_provider_order_id);

        -- Redemption codes (short-lived codes for URL-safe license redemption)
        CREATE TABLE IF NOT EXISTS redemption_codes (
            id TEXT PRIMARY KEY,
            code TEXT NOT NULL UNIQUE,
            license_key_id TEXT NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_redemption_codes_code ON redemption_codes(code);
        CREATE INDEX IF NOT EXISTS idx_redemption_codes_license ON redemption_codes(license_key_id);
        CREATE INDEX IF NOT EXISTS idx_redemption_codes_expires ON redemption_codes(expires_at);

        -- Devices (activated devices for a license)
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            license_key_id TEXT NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
            device_id TEXT NOT NULL,
            device_type TEXT NOT NULL CHECK (device_type IN ('uuid', 'machine')),
            name TEXT,
            jti TEXT NOT NULL,
            activated_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            UNIQUE(license_key_id, device_id)
        );
        CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_key_id);
        CREATE INDEX IF NOT EXISTS idx_devices_jti ON devices(jti);

        -- Payment sessions (temporary, for tracking buy flow)
        CREATE TABLE IF NOT EXISTS payment_sessions (
            id TEXT PRIMARY KEY,
            product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            device_id TEXT NOT NULL,
            device_type TEXT NOT NULL CHECK (device_type IN ('uuid', 'machine')),
            customer_id TEXT,
            created_at INTEGER NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_payment_sessions_product ON payment_sessions(product_id);
        "#,
    )?;
    Ok(())
}

/// Initialize the audit log database schema (separate DB file)
/// Optimized for append-only workload with WAL mode
pub fn init_audit_db(conn: &Connection) -> rusqlite::Result<()> {
    // WAL mode: writes are sequential appends, much faster for append-only workloads
    // synchronous=NORMAL: safe with WAL, faster than FULL
    // journal_size_limit: prevent WAL from growing indefinitely
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA wal_autocheckpoint = 1000;
        PRAGMA journal_size_limit = 67108864;

        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            actor_type TEXT NOT NULL CHECK (actor_type IN ('operator', 'org_member', 'public', 'system')),
            actor_id TEXT,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            details TEXT,
            org_id TEXT,
            project_id TEXT,
            ip_address TEXT,
            user_agent TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_type, actor_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs(org_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_project ON audit_logs(project_id);
        "#,
    )?;
    Ok(())
}
