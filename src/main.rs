use axum::Router;
use clap::Parser;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::sync::Arc;
use std::time::Duration;

use paycheck::config::Config;
use paycheck::crypto::{EmailHasher, MasterKey};
use paycheck::db::{AppState, MigrationTarget, create_pool, init_audit_db, init_db, queries, run_migrations};
use paycheck::email::EmailService;
use paycheck::handlers;
use paycheck::jwt::{self, JwksCache};
use paycheck::models::{
    self, ActorType, AuditAction, AuditLogNames, CreateOrgMember, CreateProduct, CreateProject,
    CreateProviderLink, CreateUser, OperatorRole, OrgMemberRole,
};
use paycheck::rate_limit::ActivationRateLimiter;

#[derive(Parser, Debug)]
#[command(name = "paycheck")]
#[command(about = "Offline-first licensing system for indie developers")]
struct Cli {
    /// Seed the database with dev data (operator, org, member, project, product)
    #[arg(long)]
    seed: bool,

    /// Delete databases on exit (dev mode only, useful for fresh starts)
    #[arg(long)]
    ephemeral: bool,

    /// Rotate the master encryption key. Requires --old-key-file and --new-key-file.
    #[arg(long)]
    rotate_key: bool,

    /// Path to the old master key file (for --rotate-key)
    #[arg(long, requires = "rotate_key")]
    old_key_file: Option<String>,

    /// Path to the new master key file (for --rotate-key)
    #[arg(long, requires = "rotate_key")]
    new_key_file: Option<String>,
}

fn bootstrap_first_operator(state: &AppState, email: &str) {
    let mut conn = state
        .db
        .get()
        .expect("Failed to get db connection for bootstrap");
    let audit_conn = state
        .audit
        .get()
        .expect("Failed to get audit db connection");

    let count = queries::count_operators(&conn).expect("Failed to count operators");
    if count > 0 {
        tracing::info!("Operators already exist, skipping bootstrap");
        return;
    }

    // Create user first
    let user = queries::create_user(
        &conn,
        &CreateUser {
            email: email.to_string(),
            name: "Bootstrap Operator".to_string(),
        },
    )
    .expect("Failed to create bootstrap user");

    // Grant operator role to user
    let user = queries::grant_operator_role(&conn, &user.id, OperatorRole::Owner)
        .expect("Failed to grant operator role");

    // Create API key for the operator's user
    let (_api_key_record, api_key) =
        queries::create_api_key(&mut conn, &user.id, "Default", None, true, None)
            .expect("Failed to create bootstrap API key");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // user_id
        AuditAction::BootstrapOperator.as_ref(),
        "operator",
        &user.id,
        Some(&serde_json::json!({
            "email": email,
            "role": "owner",
        })),
        None,
        None,
        None,
        None,
        &AuditLogNames::default().resource(user.name.clone()),
        None, // auth_type (system action)
        None, // auth_credential
    )
    .expect("Failed to create audit log for bootstrap");

    tracing::info!("============================================");
    tracing::info!("BOOTSTRAP OPERATOR CREATED");
    tracing::info!("Email: {}", email);
    tracing::info!("API Key: {}", api_key);
    tracing::info!("============================================");
    tracing::info!("SAVE THIS API KEY - IT WILL NOT BE SHOWN AGAIN");
    tracing::info!("============================================");
}

/// Seeds the database with dev data for testing.
/// Creates: operator, organization, org member, project, and product.
/// Only runs in dev mode and when database is empty.
fn seed_dev_data(state: &AppState) {
    let mut conn = state
        .db
        .get()
        .expect("Failed to get db connection for seeding");
    let audit_conn = state
        .audit
        .get()
        .expect("Failed to get audit db connection");

    // Check if already seeded (any operators exist)
    let count = queries::count_operators(&conn).expect("Failed to count operators");
    if count > 0 {
        tracing::info!("Database already has data, skipping seed");
        return;
    }

    // 1. Create operator user and grant operator role
    let operator_user = queries::create_user(
        &conn,
        &CreateUser {
            email: "dev@paycheck.local".to_string(),
            name: "Dev Operator".to_string(),
        },
    )
    .expect("Failed to create operator user");

    let operator_user = queries::grant_operator_role(&conn, &operator_user.id, OperatorRole::Owner)
        .expect("Failed to grant operator role");

    // Create API key for operator
    let (_, operator_api_key) =
        queries::create_api_key(&mut conn, &operator_user.id, "Default", None, true, None)
            .expect("Failed to create operator API key");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // user_id
        AuditAction::SeedOperator.as_ref(),
        "operator",
        &operator_user.id,
        None,
        None,
        None,
        None,
        None,
        &AuditLogNames::default().resource_user(&operator_user.name, &operator_user.email),
        None, // auth_type (system action)
        None, // auth_credential
    )
    .expect("Failed to create audit log");

    // 2. Create organization (no owner user - just the org)
    let org = queries::create_organization(
        &conn,
        &models::CreateOrganization {
            name: "Dev Org".to_string(),
            owner_user_id: None,
        },
    )
    .expect("Failed to create dev organization");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // user_id
        AuditAction::SeedOrg.as_ref(),
        "org",
        &org.id,
        None,
        None,
        None,
        None,
        None,
        &AuditLogNames::default().resource(org.name.clone()),
        None, // auth_type (system action)
        None, // auth_credential
    )
    .expect("Failed to create audit log");

    // 3. Create org member user and member
    let member_user = queries::create_user(
        &conn,
        &CreateUser {
            email: "dev@devorg.local".to_string(),
            name: "Dev Member".to_string(),
        },
    )
    .expect("Failed to create member user");

    let member = queries::create_org_member(
        &conn,
        &org.id,
        &CreateOrgMember {
            user_id: member_user.id.clone(),
            role: OrgMemberRole::Owner,
        },
    )
    .expect("Failed to create dev org member");

    // Create an API key for the member
    let (_, member_api_key) =
        queries::create_api_key(&mut conn, &member_user.id, "Default", None, true, None)
            .expect("Failed to create dev org member API key");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // user_id
        AuditAction::SeedOrgMember.as_ref(),
        "org_member",
        &member.id,
        None,
        Some(&org.id),
        None,
        None,
        None,
        &AuditLogNames::default()
            .resource_user(&member_user.name, &member_user.email)
            .org(org.name.clone()),
        None, // auth_type (system action)
        None, // auth_credential
    )
    .expect("Failed to create audit log");

    // 4. Create project
    let (private_key, public_key) = jwt::generate_keypair();
    let project_input = CreateProject {
        name: "Dev Project".to_string(),
        license_key_prefix: "PC".to_string(),
        redirect_url: None,
        email_from: None,
        email_enabled: true,
        email_webhook_url: None,
    };
    let project = queries::create_project(
        &conn,
        &org.id,
        &project_input,
        &private_key,
        &public_key,
        &state.master_key,
    )
    .expect("Failed to create dev project");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // user_id
        AuditAction::SeedProject.as_ref(),
        "project",
        &project.id,
        None,
        Some(&org.id),
        Some(&project.id),
        None,
        None,
        &AuditLogNames::default()
            .resource(project.name.clone())
            .org(org.name.clone())
            .project(project.name.clone()),
        None, // auth_type (system action)
        None, // auth_credential
    )
    .expect("Failed to create audit log");

    // 5. Create product
    let product_input = CreateProduct {
        name: "Pro License".to_string(),
        tier: "pro".to_string(),
        license_exp_days: Some(365),
        updates_exp_days: Some(365),
        activation_limit: None, // unlimited
        device_limit: Some(5),
        device_inactive_days: None,
        features: vec![
            "advanced-export".to_string(),
            "cloud-sync".to_string(),
            "priority-support".to_string(),
        ],
        price_cents: Some(4999),
        currency: Some("usd".to_string()),
    };
    let product = queries::create_product(&conn, &project.id, &product_input)
        .expect("Failed to create dev product");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // user_id
        AuditAction::SeedProduct.as_ref(),
        "product",
        &product.id,
        None,
        Some(&org.id),
        Some(&project.id),
        None,
        None,
        &AuditLogNames::default()
            .resource(product.name.clone())
            .org(org.name.clone())
            .project(project.name.clone()),
        None, // auth_type (system action)
        None, // auth_credential
    )
    .expect("Failed to create audit log");

    // 6. Create provider link for product (use your real Stripe price ID in test mode)
    let provider_link_input = CreateProviderLink {
        provider: "stripe".to_string(),
        linked_id: "price_REPLACE_WITH_YOUR_STRIPE_PRICE_ID".to_string(),
    };
    let _provider_link = queries::create_provider_link(&conn, &product.id, &provider_link_input)
        .expect("Failed to create dev provider link");

    // Print copy-paste friendly output
    println!();
    println!("══════════════════════════════════════════════════════════════════");
    println!("                     DEV ENVIRONMENT READY");
    println!("══════════════════════════════════════════════════════════════════");
    println!();
    println!("──────────────────────────────────────────────────────────────────");
    println!("Bruno env vars (paste into Local.bru with 2-space indent):");
    println!("──────────────────────────────────────────────────────────────────");
    println!();
    println!("  operator_api_key: {}", operator_api_key);
    println!("  org_member_api_key: {}", member_api_key);
    println!("  org_id: {}", org.id);
    println!("  project_id: {}", project.id);
    println!("  product_id: {}", product.id);
    println!("  project_pub_key: {}", public_key);
    println!("  user_id: {}", operator_user.id);
    println!();
    println!("──────────────────────────────────────────────────────────────────");
    println!("Quick test (no Stripe needed):");
    println!("──────────────────────────────────────────────────────────────────");
    println!();
    println!("1. Create a license via operator impersonation (returns activation_code):");
    println!();
    println!(
        "curl http://localhost:4242/orgs/{}/projects/{}/licenses \\",
        org.id, project.id
    );
    println!("  -H 'Authorization: Bearer {}' \\", operator_api_key);
    println!("  -H 'X-On-Behalf-Of: {}' \\", member.user_id);
    println!("  -H 'Content-Type: application/json' \\");
    println!("  -d '{{\"product_id\": \"{}\"}}'", product.id);
    println!();
    println!("2. Activate with code & get JWT:");
    println!();
    println!("curl http://localhost:4242/redeem \\");
    println!("  -H 'Content-Type: application/json' \\");
    println!(
        "  -d '{{\"code\": \"<CODE>\", \"device_id\": \"dev-1\", \"device_type\": \"uuid\"}}'"
    );
    println!();
    println!("──────────────────────────────────────────────────────────────────");
    println!("For real Stripe payments:");
    println!("  - Update org with stripe_secret_key and stripe_webhook_secret");
    println!("  - Update product payment_config with stripe_price_id");
    println!("  - Use ngrok to expose webhook: POST /webhook/stripe");
    println!("══════════════════════════════════════════════════════════════════");
    println!();
}

/// Rotate the master encryption key.
/// Decrypts all project private keys with the old key and re-encrypts with the new key.
/// Uses a transaction to ensure all-or-nothing semantics.
fn rotate_master_key(
    db_path: &str,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<(), String> {
    use rusqlite::Connection;

    let mut conn =
        Connection::open(db_path).map_err(|e| format!("Failed to open database: {}", e))?;

    // Start transaction - any error will cause automatic rollback when conn is dropped
    let tx = conn
        .transaction()
        .map_err(|e| format!("Failed to start transaction: {}", e))?;

    // Get all projects
    let projects =
        queries::list_all_projects(&tx).map_err(|e| format!("Failed to list projects: {}", e))?;

    if projects.is_empty() {
        println!("No projects found. Nothing to rotate.");
        return Ok(());
    }

    println!("Found {} project(s) to rotate.", projects.len());

    for project in &projects {
        // Decrypt with old key
        let plaintext = old_key
            .decrypt_private_key(&project.id, &project.private_key)
            .map_err(|e| format!("Failed to decrypt project {}: {}", project.id, e))?;

        // Re-encrypt with new key
        let new_ciphertext = new_key
            .encrypt_private_key(&project.id, &plaintext)
            .map_err(|e| format!("Failed to re-encrypt project {}: {}", project.id, e))?;

        // Update private key in database
        queries::update_project_private_key(&tx, &project.id, &new_ciphertext)
            .map_err(|e| format!("Failed to update project {} in database: {}", project.id, e))?;

        println!("  [OK] Project: {} ({})", project.name, project.id);
    }

    // Rotate organization service configs (stripe, lemonsqueezy, resend)
    let service_configs = queries::list_all_org_service_configs(&tx)
        .map_err(|e| format!("Failed to list org service configs: {}", e))?;

    if !service_configs.is_empty() {
        println!();
        println!(
            "Found {} organization service config(s) to rotate.",
            service_configs.len()
        );

        for config in &service_configs {
            // Decrypt with old key
            let plaintext = old_key
                .decrypt_private_key(&config.org_id, &config.config_encrypted)
                .map_err(|e| {
                    format!(
                        "Failed to decrypt {} config for org {}: {}",
                        config.provider.as_str(),
                        config.org_id,
                        e
                    )
                })?;

            // Re-encrypt with new key
            let new_enc = new_key
                .encrypt_private_key(&config.org_id, &plaintext)
                .map_err(|e| {
                    format!(
                        "Failed to re-encrypt {} config for org {}: {}",
                        config.provider.as_str(),
                        config.org_id,
                        e
                    )
                })?;

            // Update in database
            queries::update_org_service_config_encrypted(&tx, &config.id, &new_enc).map_err(
                |e| {
                    format!(
                        "Failed to update {} config for org {}: {}",
                        config.provider.as_str(),
                        config.org_id,
                        e
                    )
                },
            )?;

            println!(
                "  [OK] {} ({}) for org: {}",
                config.provider.as_str(),
                config.category.as_str(),
                config.org_id
            );
        }
    }

    // Rotate email HMAC key (stored encrypted in system_config)
    if let Some(encrypted) = queries::get_system_config(&tx, EmailHasher::CONFIG_KEY)
        .map_err(|e| format!("Failed to check for email HMAC key: {}", e))?
    {
        // Decrypt with old key, re-encrypt with new key
        let plaintext = old_key
            .decrypt_private_key("system-config", &encrypted)
            .map_err(|e| format!("Failed to decrypt email HMAC key: {}", e))?;

        let new_encrypted = new_key
            .encrypt_private_key("system-config", &plaintext)
            .map_err(|e| format!("Failed to re-encrypt email HMAC key: {}", e))?;

        queries::set_system_config(&tx, EmailHasher::CONFIG_KEY, &new_encrypted)
            .map_err(|e| format!("Failed to update email HMAC key: {}", e))?;

        println!();
        println!("  [OK] Email HMAC key");
    }

    // Commit the transaction
    tx.commit()
        .map_err(|e| format!("Failed to commit transaction: {}", e))?;

    // Track if email HMAC key was rotated
    let email_key_rotated = queries::get_system_config(&conn, EmailHasher::CONFIG_KEY)
        .map_err(|e| format!("Failed to check for email HMAC key after commit: {}", e))?
        .is_some();

    println!();
    println!("SUCCESS: All keys rotated to new master key.");
    println!("  {} project(s)", projects.len());
    if !service_configs.is_empty() {
        println!(
            "  {} organization service config(s)",
            service_configs.len()
        );
    }
    if email_key_rotated {
        println!("  1 email HMAC key");
    }
    println!();
    println!("Next steps:");
    println!("  1. Update PAYCHECK_MASTER_KEY_FILE to point to the new key file");
    println!("  2. Securely delete the old key file");
    println!("  3. Restart the server");

    Ok(())
}

/// Spawns a background task that periodically runs maintenance routines.
/// Different routines run at offset intervals to spread the load:
/// - Activation codes: every 5 minutes (every tick)
/// - Rate limiter: every 5 minutes (every tick)
/// - Webhook events: every hour, offset by 15 min (iteration % 12 == 3)
/// - Payment sessions: every hour, offset by 30 min (iteration % 12 == 6)
fn spawn_cleanup_task(
    state: AppState,
    webhook_event_retention_days: i64,
    payment_session_retention_days: i64,
) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(5 * 60); // 5 minutes per tick
        let mut iteration: u64 = 0;

        loop {
            tokio::time::sleep(interval).await;
            iteration += 1;

            // Clean up expired activation codes (every tick = 5 min)
            match state.db.get() {
                Ok(conn) => match queries::cleanup_expired_activation_codes(&conn) {
                    Ok(count) => {
                        if count > 0 {
                            tracing::debug!("Cleaned up {} expired activation codes", count);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to cleanup activation codes: {}", e);
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to get db connection for cleanup: {}", e);
                }
            }

            // Clean up rate limiter expired entries (every tick = 5 min)
            state.activation_rate_limiter.cleanup();

            // Clean up old webhook events (every 12 ticks = 1 hour, offset by 3 ticks = 15 min)
            // Only runs if retention is configured (> 0)
            if webhook_event_retention_days > 0 && iteration % 12 == 3 {
                match state.db.get() {
                    Ok(conn) => {
                        match queries::purge_old_webhook_events(&conn, webhook_event_retention_days)
                        {
                            Ok(count) => {
                                if count > 0 {
                                    tracing::info!(
                                        "Purged {} webhook events older than {} days",
                                        count,
                                        webhook_event_retention_days
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to purge old webhook events: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to get db connection for webhook cleanup: {}", e);
                    }
                }
            }

            // Clean up old incomplete payment sessions (every 12 ticks = 1 hour, offset by 6 ticks = 30 min)
            // Only runs if retention is configured (> 0)
            if payment_session_retention_days > 0 && iteration % 12 == 6 {
                match state.db.get() {
                    Ok(conn) => match queries::purge_old_payment_sessions(
                        &conn,
                        payment_session_retention_days,
                    ) {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!(
                                    "Purged {} abandoned payment sessions older than {} days",
                                    count,
                                    payment_session_retention_days
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to purge old payment sessions: {}", e);
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            "Failed to get db connection for payment session cleanup: {}",
                            e
                        );
                    }
                }
            }
        }
    });

    tracing::info!(
        "Background maintenance task started (activation codes: 5min, hourly: webhook events, payment sessions)"
    );
}

#[tokio::main]
async fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Handle key rotation command (before normal startup)
    if cli.rotate_key {
        use paycheck::config::load_master_key_from_file;

        let old_key_file = cli
            .old_key_file
            .as_ref()
            .expect("--rotate-key requires --old-key-file");
        let new_key_file = cli
            .new_key_file
            .as_ref()
            .expect("--rotate-key requires --new-key-file");

        println!("Master Key Rotation");
        println!("===================");
        println!();

        // Load old key
        println!("Loading old key from: {}", old_key_file);
        let old_key = load_master_key_from_file(old_key_file).unwrap_or_else(|e| {
            eprintln!("Failed to load old key: {}", e);
            std::process::exit(1);
        });

        // Load new key
        println!("Loading new key from: {}", new_key_file);
        let new_key = load_master_key_from_file(new_key_file).unwrap_or_else(|e| {
            eprintln!("Failed to load new key: {}", e);
            std::process::exit(1);
        });

        println!();

        // Get database path from env or default
        dotenvy::dotenv().ok();
        let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "paycheck.db".to_string());

        println!("Using database: {}", db_path);
        println!();

        // Run rotation
        if let Err(e) = rotate_master_key(&db_path, &old_key, &new_key) {
            eprintln!();
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }

        // Exit after rotation (don't start server)
        return;
    }

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "paycheck=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env();

    if config.dev_mode {
        tracing::info!("Running in DEVELOPMENT mode");
    }

    if config.console_origins.is_empty() {
        tracing::warn!(
            "No PAYCHECK_CONSOLE_ORIGINS configured - admin APIs will reject browser requests"
        );
    } else {
        tracing::info!("Console CORS origins: {:?}", config.console_origins);
    }

    // Create database connection pools
    let db_pool = create_pool(&config.database_path).expect("Failed to create database pool");
    let audit_pool =
        create_pool(&config.audit_database_path).expect("Failed to create audit database pool");

    // Run database migrations (with auto-backup before schema changes)
    {
        let mut conn = db_pool.get().expect("Failed to get connection for migration");
        run_migrations(
            &mut conn,
            &config.database_path,
            MigrationTarget::Main,
            config.migration_backup_count,
        )
        .expect("Failed to run database migrations");
    }
    {
        let mut conn = audit_pool.get().expect("Failed to get audit connection for migration");
        run_migrations(
            &mut conn,
            &config.audit_database_path,
            MigrationTarget::Audit,
            config.migration_backup_count,
        )
        .expect("Failed to run audit database migrations");
    }

    // Initialize database schemas (idempotent - creates tables if missing)
    {
        let conn = db_pool.get().expect("Failed to get connection");
        init_db(&conn).expect("Failed to initialize database");
    }
    {
        let conn = audit_pool.get().expect("Failed to get audit connection");
        init_audit_db(&conn).expect("Failed to initialize audit database");
    }

    // Initialize email service with system-level Resend API key
    let email_service = EmailService::new(
        config.resend_api_key.clone(),
        config.default_from_email.clone(),
    );

    // Initialize JWKS cache for first-party JWT authentication
    let jwks_cache = Arc::new(JwksCache::new());

    // Log trusted issuers if any are configured
    if !config.trusted_issuers.is_empty() {
        tracing::info!(
            "Trusted JWT issuers configured: {:?}",
            config
                .trusted_issuers
                .iter()
                .map(|i| &i.issuer)
                .collect::<Vec<_>>()
        );
    }

    // Initialize email hasher (stable HMAC key stored encrypted in DB)
    let email_hasher = {
        let conn = db_pool
            .get()
            .expect("Failed to get connection for email hasher init");

        // Try to load existing encrypted HMAC key
        match queries::get_system_config(&conn, EmailHasher::CONFIG_KEY) {
            Ok(Some(encrypted)) => {
                // Decrypt the HMAC key using the master key
                // We use a fixed entity ID for system config encryption
                let hmac_key_bytes = config
                    .master_key
                    .decrypt_private_key("system-config", &encrypted)
                    .expect("Failed to decrypt email HMAC key - was master key rotated without migration?");

                if hmac_key_bytes.len() != 32 {
                    panic!(
                        "Invalid email HMAC key length: expected 32, got {}",
                        hmac_key_bytes.len()
                    );
                }

                let mut key = [0u8; 32];
                key.copy_from_slice(&hmac_key_bytes);
                tracing::debug!("Loaded existing email HMAC key from database");
                EmailHasher::from_bytes(key)
            }
            Ok(None) => {
                // Generate new HMAC key, encrypt, and store
                let hmac_key = EmailHasher::generate_key();
                let encrypted = config
                    .master_key
                    .encrypt_private_key("system-config", &hmac_key)
                    .expect("Failed to encrypt email HMAC key");

                queries::set_system_config(&conn, EmailHasher::CONFIG_KEY, &encrypted)
                    .expect("Failed to store email HMAC key");

                tracing::info!("Generated and stored new email HMAC key");
                EmailHasher::from_bytes(hmac_key)
            }
            Err(e) => {
                panic!("Failed to check for existing email HMAC key: {}", e);
            }
        }
    };

    let state = AppState {
        db: db_pool,
        audit: audit_pool,
        base_url: config.base_url.clone(),
        audit_log_enabled: config.audit_log_enabled,
        master_key: config.master_key.clone(),
        email_hasher,
        success_page_url: config.success_page_url.clone(),
        activation_rate_limiter: Arc::new(ActivationRateLimiter::default()),
        email_service: Arc::new(email_service),
        jwks_cache,
        trusted_issuers: config.trusted_issuers.clone(),
    };

    // Purge old public audit logs on startup (0 = never purge)
    // Only public (end-user) logs are purged; internal actions are kept forever.
    if config.public_audit_log_retention_days > 0 {
        let conn = state
            .audit
            .get()
            .expect("Failed to get audit connection for purge");
        match queries::purge_old_public_audit_logs(&conn, config.public_audit_log_retention_days) {
            Ok(count) if count > 0 => {
                tracing::info!(
                    "Purged {} public audit log entries older than {} days",
                    count,
                    config.public_audit_log_retention_days
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to purge old public audit logs: {}", e);
            }
        }
    }

    // Purge soft-deleted records on startup (0 = never auto-purge)
    // Records can still be manually hard-deleted via operator API.
    if config.soft_delete_retention_days > 0 {
        let conn = state
            .db
            .get()
            .expect("Failed to get db connection for soft delete purge");
        match queries::purge_soft_deleted_records(&conn, config.soft_delete_retention_days) {
            Ok(result) if result.total() > 0 => {
                tracing::info!(
                    "Purged {} soft-deleted records older than {} days (users: {}, orgs: {}, members: {}, projects: {}, products: {}, licenses: {})",
                    result.total(),
                    config.soft_delete_retention_days,
                    result.users,
                    result.organizations,
                    result.org_members,
                    result.projects,
                    result.products,
                    result.licenses
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to purge soft-deleted records: {}", e);
            }
        }
    }

    // Seed dev data if --seed flag is passed (only in dev mode)
    if cli.seed {
        if !config.dev_mode {
            tracing::warn!("--seed flag ignored: not in dev mode (set PAYCHECK_ENV=dev)");
        } else {
            if cli.ephemeral {
                println!();
                println!("⚠️  EPHEMERAL MODE: databases will be deleted on exit");
            }
            seed_dev_data(&state);
        }
    }

    // Bootstrap first operator if configured (fallback for non-seed usage)
    if let Some(ref email) = config.bootstrap_operator_email {
        bootstrap_first_operator(&state, email);
    }

    // Start background maintenance task (activation codes, webhook events, payment sessions, rate limiter)
    spawn_cleanup_task(
        state.clone(),
        config.webhook_event_retention_days,
        config.payment_session_retention_days,
    );

    // Build the application router
    let console_cors = config.console_cors_layer();
    let app = Router::new()
        // Public endpoints (no auth, permissive CORS for customer websites)
        .merge(handlers::public::router(config.rate_limit))
        // Webhook endpoints (provider-specific auth, no CORS needed - server-to-server)
        .merge(handlers::webhooks::router())
        // Operator API (operator key auth, console CORS only)
        .merge(handlers::operators::router(state.clone()).layer(console_cors.clone()))
        // Organization API (org member key auth, console CORS only, high rate limit)
        .merge(handlers::orgs::router(state.clone(), config.rate_limit).layer(console_cors))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start the server
    // In dev mode, try successive ports if the default is taken
    let (listener, actual_port) = if config.dev_mode {
        let mut port = config.port;
        loop {
            let addr = format!("{}:{}", config.host, port);
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => break (l, port),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    tracing::debug!("Port {} in use, trying {}", port, port + 1);
                    port += 1;
                    if port > config.port + 100 {
                        panic!("Could not find available port after 100 attempts");
                    }
                }
                Err(e) => panic!("Failed to bind to address: {}", e),
            }
        }
    } else {
        let addr = config.addr();
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("Failed to bind to address");
        (listener, config.port)
    };

    // Track if we should clean up on exit
    let cleanup_on_exit = cli.ephemeral && config.dev_mode;
    let db_path = config.database_path.clone();
    let audit_path = config.audit_database_path.clone();

    if cleanup_on_exit {
        tracing::info!("EPHEMERAL MODE: databases will be deleted on exit");
    }

    let actual_addr = format!("{}:{}", config.host, actual_port);
    if actual_port != config.port {
        tracing::info!(
            "Port {} was in use, using port {} instead",
            config.port,
            actual_port
        );
    }
    tracing::info!("Paycheck server listening on {}", actual_addr);

    // Run server with graceful shutdown
    // Use into_make_service_with_connect_info to enable IP-based rate limiting
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("Failed to start server");

    // Cleanup on exit if ephemeral mode
    if cleanup_on_exit {
        tracing::info!("Cleaning up ephemeral databases...");
        if let Err(e) = std::fs::remove_file(&db_path) {
            tracing::warn!("Failed to remove {}: {}", db_path, e);
        } else {
            tracing::info!("Removed {}", db_path);
        }
        if let Err(e) = std::fs::remove_file(&audit_path) {
            tracing::warn!("Failed to remove {}: {}", audit_path, e);
        } else {
            tracing::info!("Removed {}", audit_path);
        }
        // Also remove WAL and SHM files if they exist
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
        let _ = std::fs::remove_file(format!("{}-wal", audit_path));
        let _ = std::fs::remove_file(format!("{}-shm", audit_path));
        tracing::info!("Ephemeral cleanup complete");
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
    tracing::info!("Shutdown signal received, stopping server...");
}
