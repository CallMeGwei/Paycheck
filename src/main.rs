use axum::Router;
use clap::Parser;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::time::Duration;

use paycheck::config::Config;
use paycheck::crypto::MasterKey;
use paycheck::db::{create_pool, init_audit_db, init_db, queries, AppState};
use paycheck::handlers;
use paycheck::jwt;
use paycheck::models::{
    self, ActorType, CreateOperator, CreateOrgMember, CreateProduct, CreateProject, OrgMemberRole,
    OperatorRole,
};

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
    let conn = state.db.get().expect("Failed to get db connection for bootstrap");
    let audit_conn = state.audit.get().expect("Failed to get audit db connection");

    let count = queries::count_operators(&conn).expect("Failed to count operators");
    if count > 0 {
        tracing::info!("Operators already exist, skipping bootstrap");
        return;
    }

    let api_key = queries::generate_api_key();

    let input = CreateOperator {
        email: email.to_string(),
        name: "Bootstrap Operator".to_string(),
        role: OperatorRole::Owner,
    };

    let operator = queries::create_operator(&conn, &input, &api_key, None)
        .expect("Failed to create bootstrap operator");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None,
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
    let conn = state.db.get().expect("Failed to get db connection for seeding");
    let audit_conn = state.audit.get().expect("Failed to get audit db connection");

    // Check if already seeded (any operators exist)
    let count = queries::count_operators(&conn).expect("Failed to count operators");
    if count > 0 {
        tracing::info!("Database already has data, skipping seed");
        return;
    }

    tracing::info!("============================================");
    tracing::info!("SEEDING DEV DATA");
    tracing::info!("============================================");

    // 1. Create operator
    let operator_api_key = queries::generate_api_key();
    let operator_input = CreateOperator {
        email: "dev@paycheck.local".to_string(),
        name: "Dev Operator".to_string(),
        role: OperatorRole::Owner,
    };
    let operator = queries::create_operator(&conn, &operator_input, &operator_api_key, None)
        .expect("Failed to create dev operator");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None,
        "seed_operator",
        "operator",
        &operator.id,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("Failed to create audit log");

    tracing::info!("Operator: {} ({})", operator.email, operator.name);
    tracing::info!("Operator API Key: {}", operator_api_key);
    tracing::info!("");

    // 2. Create organization
    let org = queries::create_organization(
        &conn,
        &models::CreateOrganization {
            name: "Dev Org".to_string(),
            owner_email: None,
            owner_name: None,
        },
    )
    .expect("Failed to create dev organization");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None,
        "seed_organization",
        "organization",
        &org.id,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("Failed to create audit log");

    tracing::info!("Organization: {} (id: {})", org.name, org.id);
    tracing::info!("");

    // 3. Create org member
    let member_api_key = queries::generate_api_key();
    let member_input = CreateOrgMember {
        email: "dev@devorg.local".to_string(),
        name: "Dev Member".to_string(),
        role: OrgMemberRole::Owner,
    };
    let member = queries::create_org_member(&conn, &org.id, &member_input, &member_api_key)
        .expect("Failed to create dev org member");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None,
        "seed_org_member",
        "org_member",
        &member.id,
        None,
        Some(&org.id),
        None,
        None,
        None,
    )
    .expect("Failed to create audit log");

    tracing::info!("Org Member: {} ({})", member.email, member.name);
    tracing::info!("Org Member API Key: {}", member_api_key);
    tracing::info!("");

    // 4. Create project
    let (private_key, public_key) = jwt::generate_keypair();
    let project_id = uuid::Uuid::new_v4().to_string();
    let encrypted_private_key = state
        .master_key
        .encrypt_private_key(&project_id, &private_key)
        .expect("Failed to encrypt project private key");
    let project_input = CreateProject {
        name: "Dev Project".to_string(),
        domain: "localhost".to_string(),
        license_key_prefix: "PC".to_string(),
    };
    let project = queries::create_project_with_id(
        &conn,
        &project_id,
        &org.id,
        &project_input,
        &encrypted_private_key,
        &public_key,
    )
    .expect("Failed to create dev project");

    queries::create_audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::System,
        None,
        "seed_project",
        "project",
        &project.id,
        None,
        Some(&org.id),
        Some(&project.id),
        None,
        None,
    )
    .expect("Failed to create audit log");

    tracing::info!("Project: {} (id: {})", project.name, project.id);
    tracing::info!("Project Domain: {}", project.domain);
    tracing::info!("Project Public Key: {}", project.public_key);
    tracing::info!("");

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
        None,
        "seed_product",
        "product",
        &product.id,
        None,
        Some(&org.id),
        Some(&project.id),
        None,
        None,
    )
    .expect("Failed to create audit log");

    tracing::info!("Product: {} (id: {})", product.name, product.id);
    tracing::info!("Product Tier: {}", product.tier);
    tracing::info!("Product Features: {:?}", product.features);
    tracing::info!("");

    tracing::info!("============================================");
    tracing::info!("DEV DATA SEEDED SUCCESSFULLY");
    tracing::info!("============================================");

    // Print copy-paste friendly output (no log formatting, 2-space indent for Bruno env file)
    println!();
    println!("--- COPY FROM HERE ---");
    println!("  operator_api_key: {}", operator_api_key);
    println!("  org_api_key: {}", member_api_key);
    println!("  org_id: {}", org.id);
    println!("  project_id: {}", project.id);
    println!("  product_id: {}", product.id);
    println!("--- END COPY ---");
    println!();
}


/// Rotate the master encryption key.
/// Decrypts all project private keys with the old key and re-encrypts with the new key.
fn rotate_master_key(db_path: &str, old_key: &MasterKey, new_key: &MasterKey) -> Result<(), String> {
    use paycheck::db::DbPool;
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    // Create a minimal DB pool just for rotation
    let manager = SqliteConnectionManager::file(db_path);
    let pool: DbPool = Pool::builder()
        .max_size(1)
        .build(manager)
        .map_err(|e| format!("Failed to create database pool: {}", e))?;

    let conn = pool
        .get()
        .map_err(|e| format!("Failed to get database connection: {}", e))?;

    // Get all projects
    let projects = queries::list_all_projects(&conn)
        .map_err(|e| format!("Failed to list projects: {}", e))?;

    if projects.is_empty() {
        println!("No projects found. Nothing to rotate.");
        return Ok(());
    }

    println!("Found {} project(s) to rotate.", projects.len());

    let mut rotated = 0;
    let mut errors = 0;

    for project in &projects {
        // Check if the key is encrypted
        if !MasterKey::is_encrypted(&project.private_key) {
            println!(
                "  [SKIP] Project {} has unencrypted key (run without --rotate-key first to migrate)",
                project.id
            );
            continue;
        }

        // Decrypt with old key
        let plaintext = match old_key.decrypt_private_key(&project.id, &project.private_key) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "  [ERROR] Failed to decrypt project {} with old key: {}",
                    project.id, e
                );
                errors += 1;
                continue;
            }
        };

        // Re-encrypt with new key
        let new_ciphertext = match new_key.encrypt_private_key(&project.id, &plaintext) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "  [ERROR] Failed to re-encrypt project {} with new key: {}",
                    project.id, e
                );
                errors += 1;
                continue;
            }
        };

        // Update private key in database
        if let Err(e) = queries::update_project_private_key(&conn, &project.id, &new_ciphertext) {
            eprintln!(
                "  [ERROR] Failed to update project {} in database: {}",
                project.id, e
            );
            errors += 1;
            continue;
        }

        // Rotate payment configs if they exist and are encrypted
        let mut config_error = false;

        let new_stripe = if let Some(ref encrypted) = project.stripe_config_encrypted {
            if MasterKey::is_encrypted(encrypted) {
                match old_key.decrypt_private_key(&project.id, encrypted) {
                    Ok(plaintext) => match new_key.encrypt_private_key(&project.id, &plaintext) {
                        Ok(new_enc) => Some(new_enc),
                        Err(e) => {
                            eprintln!(
                                "  [ERROR] Failed to re-encrypt Stripe config for project {}: {}",
                                project.id, e
                            );
                            config_error = true;
                            None
                        }
                    },
                    Err(e) => {
                        eprintln!(
                            "  [ERROR] Failed to decrypt Stripe config for project {}: {}",
                            project.id, e
                        );
                        config_error = true;
                        None
                    }
                }
            } else {
                // Unencrypted - just keep as is (will be migrated on startup)
                Some(encrypted.clone())
            }
        } else {
            None
        };

        let new_ls = if let Some(ref encrypted) = project.ls_config_encrypted {
            if MasterKey::is_encrypted(encrypted) {
                match old_key.decrypt_private_key(&project.id, encrypted) {
                    Ok(plaintext) => match new_key.encrypt_private_key(&project.id, &plaintext) {
                        Ok(new_enc) => Some(new_enc),
                        Err(e) => {
                            eprintln!(
                                "  [ERROR] Failed to re-encrypt LemonSqueezy config for project {}: {}",
                                project.id, e
                            );
                            config_error = true;
                            None
                        }
                    },
                    Err(e) => {
                        eprintln!(
                            "  [ERROR] Failed to decrypt LemonSqueezy config for project {}: {}",
                            project.id, e
                        );
                        config_error = true;
                        None
                    }
                }
            } else {
                // Unencrypted - just keep as is (will be migrated on startup)
                Some(encrypted.clone())
            }
        } else {
            None
        };

        if config_error {
            errors += 1;
            continue;
        }

        // Update payment configs if any exist
        let has_payment_configs =
            project.stripe_config_encrypted.is_some() || project.ls_config_encrypted.is_some();
        if has_payment_configs
            && queries::update_project_payment_configs(
                &conn,
                &project.id,
                new_stripe.as_deref(),
                new_ls.as_deref(),
            )
            .is_err()
        {
            eprintln!(
                "  [ERROR] Failed to update payment configs for project {}",
                project.id
            );
            errors += 1;
            continue;
        }

        println!("  [OK] Rotated project: {} ({})", project.name, project.id);
        rotated += 1;
    }

    println!();
    println!("Rotation complete:");
    println!("  Rotated: {}", rotated);
    println!("  Errors:  {}", errors);
    println!("  Skipped: {}", projects.len() - rotated - errors);

    if errors > 0 {
        return Err(format!(
            "Rotation completed with {} error(s). Review output above.",
            errors
        ));
    }

    if rotated > 0 {
        println!();
        println!("SUCCESS: All keys rotated to new master key.");
        println!();
        println!("Next steps:");
        println!("  1. Update PAYCHECK_MASTER_KEY_FILE to point to the new key file");
        println!("  2. Securely delete the old key file");
        println!("  3. Restart the server");
    }

    Ok(())
}

/// Spawns a background task that periodically cleans up expired redemption codes.
/// Runs every 5 minutes to remove codes that have expired or been used.
fn spawn_cleanup_task(state: AppState) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(5 * 60); // 5 minutes

        loop {
            tokio::time::sleep(interval).await;

            match state.db.get() {
                Ok(conn) => {
                    match queries::cleanup_expired_redemption_codes(&conn) {
                        Ok(count) => {
                            if count > 0 {
                                tracing::debug!("Cleaned up {} expired redemption codes", count);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to cleanup redemption codes: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get db connection for cleanup: {}", e);
                }
            }
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

        let old_key_file = cli.old_key_file.as_ref().expect(
            "--rotate-key requires --old-key-file"
        );
        let new_key_file = cli.new_key_file.as_ref().expect(
            "--rotate-key requires --new-key-file"
        );

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
        let db_path = std::env::var("DATABASE_PATH")
            .unwrap_or_else(|_| "paycheck.db".to_string());

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

    let state = AppState {
        db: db_pool,
        audit: audit_pool,
        base_url: config.base_url.clone(),
        audit_log_enabled: config.audit_log_enabled,
        master_key: config.master_key.clone(),
    };

    // Purge old audit logs on startup (0 = never purge)
    if config.audit_log_retention_days > 0 {
        let conn = state.audit.get().expect("Failed to get audit connection for purge");
        match queries::purge_old_audit_logs(&conn, config.audit_log_retention_days) {
            Ok(count) if count > 0 => {
                tracing::info!("Purged {} audit log entries older than {} days", count, config.audit_log_retention_days);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to purge old audit logs: {}", e);
            }
        }
    }

    // Seed dev data if --seed flag is passed (only in dev mode)
    if cli.seed {
        if !config.dev_mode {
            tracing::warn!("--seed flag ignored: not in dev mode (set PAYCHECK_ENV=dev)");
        } else {
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
    let mut app = Router::new()
        // Public endpoints (no auth)
        .merge(handlers::public::router())
        // Webhook endpoints (provider-specific auth)
        .merge(handlers::webhooks::router())
        // Operator API (operator key auth)
        .merge(handlers::operators::router(state.clone()))
        // Organization API (org member key auth)
        .merge(handlers::orgs::router(state.clone()));

    // Dev-only endpoints (only in dev mode)
    if config.dev_mode {
        use axum::routing::post;
        app = app.route("/dev/create-license", post(handlers::dev::create_dev_license));
        tracing::info!("DEV endpoints enabled: POST /dev/create-license");
    }

    let app = app.layer(TraceLayer::new_for_http()).with_state(state);

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
    axum::serve(listener, app)
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
