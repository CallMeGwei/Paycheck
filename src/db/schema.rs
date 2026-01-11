use rusqlite::Connection;

/// Initialize the main database schema (everything except audit logs)
pub fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        -- Users (identity - source of truth for name/email)
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

        -- Operators (Paycheck ops team - references users for identity)
        CREATE TABLE IF NOT EXISTS operators (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'view')),
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_operators_user ON operators(user_id);

        -- API keys (unified, tied to user identity)
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            user_manageable INTEGER NOT NULL DEFAULT 1,  -- 0 = Console-managed, hidden from user
            created_at INTEGER NOT NULL,
            last_used_at INTEGER,
            expires_at INTEGER,
            revoked_at INTEGER,

            UNIQUE(user_id, name)
        );
        CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
        CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

        -- API key scopes (optional restrictions on what a key can access)
        CREATE TABLE IF NOT EXISTS api_key_scopes (
            id TEXT PRIMARY KEY,
            api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
            org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
            access TEXT NOT NULL CHECK (access IN ('view', 'admin'))
        );
        CREATE INDEX IF NOT EXISTS idx_api_key_scopes_lookup ON api_key_scopes(api_key_id, org_id);
        -- Unique constraint for org-level scopes (project_id is NULL)
        CREATE UNIQUE INDEX IF NOT EXISTS idx_api_key_scopes_org_unique ON api_key_scopes(api_key_id, org_id) WHERE project_id IS NULL;
        -- Unique constraint for project-level scopes (project_id is NOT NULL)
        CREATE UNIQUE INDEX IF NOT EXISTS idx_api_key_scopes_project_unique ON api_key_scopes(api_key_id, org_id, project_id) WHERE project_id IS NOT NULL;

        -- Organizations (customers - indie devs, companies)
        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            stripe_config TEXT,
            ls_config TEXT,
            resend_api_key BLOB,
            payment_provider TEXT CHECK (payment_provider IS NULL OR payment_provider IN ('stripe', 'lemonsqueezy')),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        -- Organization members (references users for identity)
        CREATE TABLE IF NOT EXISTS org_members (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
            created_at INTEGER NOT NULL,
            UNIQUE(user_id, org_id)
        );
        CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_id);
        CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id);

        -- Projects (software products being licensed)
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            license_key_prefix TEXT NOT NULL DEFAULT 'PC',
            private_key BLOB NOT NULL,
            public_key TEXT NOT NULL,
            redirect_url TEXT,
            email_from TEXT,
            email_enabled INTEGER NOT NULL DEFAULT 1,
            email_webhook_url TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_public_key ON projects(public_key);

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

        -- Product payment config (payment provider settings per product)
        CREATE TABLE IF NOT EXISTS product_payment_config (
            id TEXT PRIMARY KEY,
            product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            provider TEXT NOT NULL CHECK (provider IN ('stripe', 'lemonsqueezy')),

            -- Stripe fields
            stripe_price_id TEXT,
            price_cents INTEGER,
            currency TEXT,

            -- LemonSqueezy fields
            ls_variant_id TEXT,

            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,

            UNIQUE(product_id, provider)
        );
        CREATE INDEX IF NOT EXISTS idx_payment_config_product ON product_payment_config(product_id);

        -- Licenses (no user-facing keys - email hash is the identity)
        -- email_hash: SHA-256 hash of purchase email (no PII stored)
        -- project_id: denormalized for efficient lookups
        CREATE TABLE IF NOT EXISTS licenses (
            id TEXT PRIMARY KEY,
            email_hash TEXT,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
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
        CREATE INDEX IF NOT EXISTS idx_licenses_product ON licenses(product_id);
        CREATE INDEX IF NOT EXISTS idx_licenses_project ON licenses(project_id);
        CREATE INDEX IF NOT EXISTS idx_licenses_email_hash ON licenses(email_hash, project_id);
        CREATE INDEX IF NOT EXISTS idx_licenses_customer ON licenses(customer_id);
        CREATE INDEX IF NOT EXISTS idx_licenses_provider_customer ON licenses(payment_provider, payment_provider_customer_id);
        CREATE INDEX IF NOT EXISTS idx_licenses_provider_subscription ON licenses(payment_provider, payment_provider_subscription_id);
        CREATE INDEX IF NOT EXISTS idx_licenses_provider_order ON licenses(payment_provider, payment_provider_order_id);

        -- Activation codes (short-lived codes in PREFIX-XXXX-XXXX-XXXX-XXXX format)
        CREATE TABLE IF NOT EXISTS activation_codes (
            id TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL UNIQUE,
            license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_activation_codes_hash ON activation_codes(code_hash);
        CREATE INDEX IF NOT EXISTS idx_activation_codes_license ON activation_codes(license_id);
        CREATE INDEX IF NOT EXISTS idx_activation_codes_expires ON activation_codes(expires_at);

        -- Devices (activated devices for a license)
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
            device_id TEXT NOT NULL,
            device_type TEXT NOT NULL CHECK (device_type IN ('uuid', 'machine')),
            name TEXT,
            jti TEXT NOT NULL,
            activated_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            UNIQUE(license_id, device_id)
        );
        CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_id);
        CREATE INDEX IF NOT EXISTS idx_devices_jti ON devices(jti);

        -- Payment sessions (temporary, for tracking buy flow)
        -- Device info removed: purchase ≠ activation. Device created at /redeem time.
        -- Redirect URL removed: now configured per-project, not per-session.
        CREATE TABLE IF NOT EXISTS payment_sessions (
            id TEXT PRIMARY KEY,
            product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            customer_id TEXT,
            created_at INTEGER NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            license_id TEXT REFERENCES licenses(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_payment_sessions_product ON payment_sessions(product_id);

        -- Webhook events (for replay attack prevention)
        CREATE TABLE IF NOT EXISTS webhook_events (
            id TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            event_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(provider, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_webhook_events_lookup ON webhook_events(provider, event_id);
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
            actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'public', 'system')),
            user_id TEXT,                         -- references users.id (null for public/system)
            user_email TEXT,                      -- denormalized for query convenience
            user_name TEXT,                       -- denormalized for query convenience
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            resource_name TEXT,
            details TEXT,
            org_id TEXT,
            org_name TEXT,
            project_id TEXT,
            project_name TEXT,
            ip_address TEXT,
            user_agent TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs(org_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_project ON audit_logs(project_id);
        "#,
    )?;
    Ok(())
}
