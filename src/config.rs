use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_path: String,
    pub base_url: String,
    pub bootstrap_operator_email: Option<String>,
    pub dev_mode: bool,
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

        Self {
            host,
            port,
            database_path: env::var("DATABASE_PATH")
                .unwrap_or_else(|_| "paycheck.db".to_string()),
            base_url,
            bootstrap_operator_email: env::var("BOOTSTRAP_OPERATOR_EMAIL").ok(),
            dev_mode,
        }
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
