use axum::Router;
use clap::Parser;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::sync::Arc;
use std::time::Duration;

use paycheck::config::Config;
use paycheck::crypto::MasterKey;
use paycheck::db::{AppState, create_pool, init_audit_db, init_db, queries};
use paycheck::email::EmailService;
use paycheck::handlers;
use paycheck::jwt;
use paycheck::models::{
    self, ActorType, AuditLogNames, CreateOperator, CreateOrgMember, CreatePaymentConfig, CreateProduct,
    CreateProject, OperatorRole, OrgMemberRole,
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
    let conn = state
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

    let input = CreateOperator {
        email: email.to_string(),
        name: "Bootstrap Operator".to_string(),
        role: OperatorRole::Owner,
        external_user_id: None,
    };

    let (operator, api_key) =
        queries::create_operator(&conn, &input).expect("Failed to create bootstrap operator");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // actor_id
        None, // impersonator_id
        "bootstrap_operator",
        "operator",
        &operator.id,
        Some(&serde_json::json!({
            "email": email,
            "role": "owner",
        })),
        None,
        None,
        None,
        None,
        &AuditLogNames::default().resource(operator.name.clone()),
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
    let conn = state
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

    // 1. Create operator
    let operator_input = CreateOperator {
        email: "dev@paycheck.local".to_string(),
        name: "Dev Operator".to_string(),
        role: OperatorRole::Owner,
        external_user_id: None,
    };
    let (operator, operator_api_key) =
        queries::create_operator(&conn, &operator_input).expect("Failed to create dev operator");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // actor_id
        None, // impersonator_id
        "seed_operator",
        "operator",
        &operator.id,
        None,
        None,
        None,
        None,
        None,
        &AuditLogNames::default().resource(operator.name.clone()),
    )
    .expect("Failed to create audit log");

    // 2. Create organization
    let org = queries::create_organization(
        &conn,
        &models::CreateOrganization {
            name: "Dev Org".to_string(),
            owner_email: None,
            owner_name: None,
            external_user_id: None,
        },
    )
    .expect("Failed to create dev organization");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // actor_id
        None, // impersonator_id
        "seed_organization",
        "organization",
        &org.id,
        None,
        None,
        None,
        None,
        None,
        &AuditLogNames::default().resource(org.name.clone()),
    )
    .expect("Failed to create audit log");

    // 3. Create org member
    let member_input = CreateOrgMember {
        email: "dev@devorg.local".to_string(),
        name: "Dev Member".to_string(),
        role: OrgMemberRole::Owner,
        external_user_id: None,
    };
    let member = queries::create_org_member(&conn, &org.id, &member_input)
        .expect("Failed to create dev org member");

    // Create an API key for the member
    let (_, member_api_key) = queries::create_org_member_api_key(&conn, &member.id, "Default", None)
        .expect("Failed to create dev org member API key");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // actor_id
        None, // impersonator_id
        "seed_org_member",
        "org_member",
        &member.id,
        None,
        Some(&org.id),
        None,
        None,
        None,
        &AuditLogNames::default()
            .resource(member.name.clone())
            .org(org.name.clone()),
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
        None, // actor_id
        None, // impersonator_id
        "seed_project",
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
    )
    .expect("Failed to create audit log");

    // 5. Create product
    let product_input = CreateProduct {
        name: "Pro License".to_string(),
        tier: "pro".to_string(),
        license_exp_days: Some(365),
        updates_exp_days: Some(365),
        activation_limit: 0,
        device_limit: 5,
        features: vec![
            "advanced-export".to_string(),
            "cloud-sync".to_string(),
            "priority-support".to_string(),
        ],
    };
    let product = queries::create_product(&conn, &project.id, &product_input)
        .expect("Failed to create dev product");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None, // actor_id
        None, // impersonator_id
        "seed_product",
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
    )
    .expect("Failed to create audit log");

    // 6. Create payment config for product
    let payment_config_input = CreatePaymentConfig {
        provider: "stripe".to_string(),
        stripe_price_id: None,
        price_cents: Some(4999), // $49.99
        currency: Some("usd".to_string()),
        ls_variant_id: None,
    };
    let _payment_config = queries::create_payment_config(&conn, &product.id, &payment_config_input)
        .expect("Failed to create dev payment config");

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
    println!("  org_api_key: {}", member_api_key);
    println!("  org_id: {}", org.id);
    println!("  project_id: {}", project.id);
    println!("  product_id: {}", product.id);
    println!("  project_pub_key: {}", public_key);
    println!("  member_id: {}", member.id);
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
    println!("  -H 'X-On-Behalf-Of: {}' \\", member.id);
    println!("  -H 'Content-Type: application/json' \\");
    println!("  -d '{{\"product_id\": \"{}\"}}'", product.id);
    println!();
    println!("2. Activate with code & get JWT:");
    println!();
    println!("curl http://localhost:4242/redeem \\");
    println!("  -H 'Content-Type: application/json' \\");
    println!("  -d '{{\"code\": \"<CODE>\", \"device_id\": \"dev-1\", \"device_type\": \"uuid\"}}'");
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

    // Rotate organization payment configs
    let organizations = queries::list_organizations(&tx)
        .map_err(|e| format!("Failed to list organizations: {}", e))?;

    let orgs_with_configs: Vec<_> = organizations
        .iter()
        .filter(|o| {
            o.stripe_config_encrypted.is_some()
                || o.ls_config_encrypted.is_some()
                || o.resend_api_key_encrypted.is_some()
        })
        .collect();

    if !orgs_with_configs.is_empty() {
        println!();
        println!(
            "Found {} organization(s) with encrypted configs.",
            orgs_with_configs.len()
        );

        for org in &orgs_with_configs {
            let new_stripe = if let Some(ref encrypted) = org.stripe_config_encrypted {
                let plaintext = old_key
                    .decrypt_private_key(&org.id, encrypted)
                    .map_err(|e| {
                        format!("Failed to decrypt Stripe config for org {}: {}", org.id, e)
                    })?;
                let new_enc = new_key
                    .encrypt_private_key(&org.id, &plaintext)
                    .map_err(|e| {
                        format!(
                            "Failed to re-encrypt Stripe config for org {}: {}",
                            org.id, e
                        )
                    })?;
                Some(new_enc)
            } else {
                None
            };

            let new_ls = if let Some(ref encrypted) = org.ls_config_encrypted {
                let plaintext = old_key
                    .decrypt_private_key(&org.id, encrypted)
                    .map_err(|e| {
                        format!(
                            "Failed to decrypt LemonSqueezy config for org {}: {}",
                            org.id, e
                        )
                    })?;
                let new_enc = new_key
                    .encrypt_private_key(&org.id, &plaintext)
                    .map_err(|e| {
                        format!(
                            "Failed to re-encrypt LemonSqueezy config for org {}: {}",
                            org.id, e
                        )
                    })?;
                Some(new_enc)
            } else {
                None
            };

            let new_resend = if let Some(ref encrypted) = org.resend_api_key_encrypted {
                let plaintext = old_key
                    .decrypt_private_key(&org.id, encrypted)
                    .map_err(|e| {
                        format!("Failed to decrypt Resend API key for org {}: {}", org.id, e)
                    })?;
                let new_enc = new_key
                    .encrypt_private_key(&org.id, &plaintext)
                    .map_err(|e| {
                        format!(
                            "Failed to re-encrypt Resend API key for org {}: {}",
                            org.id, e
                        )
                    })?;
                Some(new_enc)
            } else {
                None
            };

            queries::update_organization_encrypted_configs(
                &tx,
                &org.id,
                new_stripe.as_deref(),
                new_ls.as_deref(),
                new_resend.as_deref(),
            )
            .map_err(|e| format!("Failed to update encrypted configs for org {}: {}", org.id, e))?;

            println!("  [OK] Org: {} ({})", org.name, org.id);
        }
    }

    // Commit the transaction
    tx.commit()
        .map_err(|e| format!("Failed to commit transaction: {}", e))?;

    println!();
    println!("SUCCESS: All keys rotated to new master key.");
    println!("  {} project(s)", projects.len());
    if !orgs_with_configs.is_empty() {
        println!(
            "  {} organization payment config(s)",
            orgs_with_configs.len()
        );
    }
    println!();
    println!("Next steps:");
    println!("  1. Update PAYCHECK_MASTER_KEY_FILE to point to the new key file");
    println!("  2. Securely delete the old key file");
    println!("  3. Restart the server");

    Ok(())
}

/// Spawns a background task that periodically cleans up expired activation codes.
/// Runs every 5 minutes to remove codes that have expired or been used.
fn spawn_cleanup_task(state: AppState) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(5 * 60); // 5 minutes

        loop {
            tokio::time::sleep(interval).await;

            // Clean up expired activation codes
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

            // Also clean up rate limiter expired entries
            state.activation_rate_limiter.cleanup();
        }
    });

    tracing::info!("Background cleanup task started (runs every 5 minutes)");
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
        tracing::warn!("No PAYCHECK_CONSOLE_ORIGINS configured - admin APIs will reject browser requests");
    } else {
        tracing::info!("Console CORS origins: {:?}", config.console_origins);
    }

    // Create database connection pools
    let db_pool = create_pool(&config.database_path).expect("Failed to create database pool");
    let audit_pool =
        create_pool(&config.audit_database_path).expect("Failed to create audit database pool");

    // Initialize database schemas
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

    let state = AppState {
        db: db_pool,
        audit: audit_pool,
        base_url: config.base_url.clone(),
        audit_log_enabled: config.audit_log_enabled,
        master_key: config.master_key.clone(),
        success_page_url: config.success_page_url.clone(),
        activation_rate_limiter: Arc::new(ActivationRateLimiter::default()),
        email_service: Arc::new(email_service),
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

    // Start background cleanup task for expired redemption codes
    spawn_cleanup_task(state.clone());

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
    let addr = config.addr();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    // Track if we should clean up on exit
    let cleanup_on_exit = cli.ephemeral && config.dev_mode;
    let db_path = config.database_path.clone();
    let audit_path = config.audit_database_path.clone();

    if cleanup_on_exit {
        tracing::info!("EPHEMERAL MODE: databases will be deleted on exit");
    }

    tracing::info!("Paycheck server listening on {}", addr);

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
