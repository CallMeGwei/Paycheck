use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_path: String,
    pub audit_database_path: String,
    pub base_url: String,
    pub bootstrap_operator_email: Option<String>,
    pub dev_mode: bool,
    /// Enable/disable audit logging entirely
    pub audit_log_enabled: bool,
    /// Days to retain audit logs before purging (0 = never purge)
    pub audit_log_retention_days: i64,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        let dev_mode = env::var("PAYCHECK_ENV")
            .map(|v| v == "dev" || v == "development")
            .unwrap_or(false);

        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3000);

        let base_url = env::var("BASE_URL")
            .unwrap_or_else(|_| format!("http://{}:{}", host, port));

        let audit_log_enabled = env::var("AUDIT_LOG_ENABLED")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        let audit_log_retention_days: i64 = env::var("AUDIT_LOG_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(90);

        Self {
            host,
            port,
            database_path: env::var("DATABASE_PATH")
                .unwrap_or_else(|_| "paycheck.db".to_string()),
            audit_database_path: env::var("AUDIT_DATABASE_PATH")
                .unwrap_or_else(|_| "paycheck_audit.db".to_string()),
            base_url,
            bootstrap_operator_email: env::var("BOOTSTRAP_OPERATOR_EMAIL").ok(),
            dev_mode,
            audit_log_enabled,
            audit_log_retention_days,
        }
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
