//! New Paycheck client with public key-based initialization

use crate::device::{generate_uuid, get_machine_id};
use crate::error::{map_status_to_error_code, PaycheckError, Result};
use crate::jwt::{decode_token, is_jwt_expired, is_license_expired, verify_token};
use crate::storage::{keys, MemoryStorage, StorageAdapter};
use crate::types::*;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

/// Default Paycheck API URL
pub const DEFAULT_BASE_URL: &str = "https://api.paycheck.dev";

/// Configuration options for the Paycheck client
#[derive(Clone, Default)]
pub struct PaycheckOptions {
    /// Paycheck server URL (default: "https://api.paycheck.dev")
    pub base_url: Option<String>,
    /// Custom storage adapter (default: MemoryStorage)
    pub storage: Option<Arc<dyn StorageAdapter>>,
    /// Device type (default: Machine for desktop)
    pub device_type: Option<DeviceType>,
    /// Override device ID (default: auto-generated)
    pub device_id: Option<String>,
    /// Auto-refresh expired tokens (default: true)
    pub auto_refresh: Option<bool>,
}

impl std::fmt::Debug for PaycheckOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaycheckOptions")
            .field("base_url", &self.base_url)
            .field("storage", &"<storage>")
            .field("device_type", &self.device_type)
            .field("device_id", &self.device_id)
            .field("auto_refresh", &self.auto_refresh)
            .finish()
    }
}

/// Result from offline validation
#[derive(Debug, Clone)]
pub struct OfflineValidateResult {
    /// Whether the license is valid
    pub valid: bool,
    /// Decoded claims if valid
    pub claims: Option<LicenseClaims>,
    /// Reason for invalidity
    pub reason: Option<String>,
}

/// Result from sync operation
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Whether the license is valid
    pub valid: bool,
    /// Decoded claims if valid
    pub claims: Option<LicenseClaims>,
    /// Whether the server was reached
    pub synced: bool,
    /// Whether operating in offline mode (using cached JWT)
    pub offline: bool,
    /// Reason for invalidity
    pub reason: Option<String>,
}

/// Result from importing a token
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// Whether the token was valid and imported
    pub valid: bool,
    /// Decoded claims if valid
    pub claims: Option<LicenseClaims>,
    /// Reason for invalidity
    pub reason: Option<String>,
}

/// Paycheck SDK client.
///
/// Initialize with your project's public key from the Paycheck dashboard.
/// The public key enables offline JWT signature verification using Ed25519.
///
/// # Example
/// ```rust,ignore
/// use paycheck_sdk::Paycheck;
///
/// let paycheck = Paycheck::new("your-base64-public-key", Default::default())?;
///
/// // Start a purchase
/// let result = paycheck.checkout("product-uuid", None).await?;
///
/// // Validate license (offline, verifies Ed25519 signature)
/// let result = paycheck.validate(None);
/// ```
pub struct Paycheck {
    public_key: String,
    base_url: String,
    storage: Arc<dyn StorageAdapter>,
    auto_refresh: bool,
    device_id: String,
    device_type: DeviceType,
    http: HttpClient,
}

impl Paycheck {
    /// Create a new Paycheck client.
    ///
    /// # Arguments
    /// * `public_key` - Base64-encoded Ed25519 public key from your Paycheck dashboard
    /// * `options` - Optional configuration
    pub fn new(public_key: &str, options: PaycheckOptions) -> Result<Self> {
        if public_key.is_empty() {
            return Err(PaycheckError::validation("public_key is required"));
        }

        let base_url = options
            .base_url
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        let storage: Arc<dyn StorageAdapter> =
            options.storage.unwrap_or_else(|| Arc::new(MemoryStorage::new()));

        let device_type = options.device_type.unwrap_or(DeviceType::Machine);
        let auto_refresh = options.auto_refresh.unwrap_or(true);

        let device_id = options.device_id.unwrap_or_else(|| {
            if let Some(id) = storage.get(keys::DEVICE_ID) {
                return id;
            }

            let id = match device_type {
                DeviceType::Machine => get_machine_id().unwrap_or_else(|_| generate_uuid()),
                DeviceType::Uuid => generate_uuid(),
            };

            storage.set(keys::DEVICE_ID, &id);
            id
        });

        let http = HttpClient::builder()
            .user_agent("paycheck-sdk-rust/0.2.0")
            .build()
            .map_err(|e| PaycheckError::network(e.to_string()))?;

        Ok(Self {
            public_key: public_key.to_string(),
            base_url,
            storage,
            auto_refresh,
            device_id,
            device_type,
            http,
        })
    }

    // ==================== Core Methods ====================

    /// Start a checkout session to purchase a product.
    pub async fn checkout(
        &self,
        product_id: &str,
        options: Option<CheckoutOptions>,
    ) -> Result<CheckoutResult> {
        #[derive(Serialize)]
        struct BuyRequest {
            public_key: String,
            product_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            provider: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            customer_id: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            redirect: Option<String>,
        }

        let opts = options.unwrap_or_default();
        let body = BuyRequest {
            public_key: self.public_key.clone(),
            product_id: product_id.to_string(),
            provider: opts.provider,
            customer_id: opts.customer_id,
            redirect: opts.redirect,
        };

        self.post("/buy", &body).await
    }

    /// Validate the stored license.
    ///
    /// By default, performs offline validation by verifying the Ed25519 signature
    /// and checking expiration.
    pub fn validate(&self, token: Option<&str>) -> OfflineValidateResult {
        let token = match token {
            Some(t) => t.to_string(),
            None => match self.get_token() {
                Some(t) => t,
                None => {
                    return OfflineValidateResult {
                        valid: false,
                        claims: None,
                        reason: None,
                    };
                }
            },
        };

        // Verify signature
        if !verify_token(&token, &self.public_key) {
            return OfflineValidateResult {
                valid: false,
                claims: None,
                reason: Some("Invalid signature".to_string()),
            };
        }

        // Decode claims
        let claims = match decode_token(&token) {
            Ok(c) => c,
            Err(_) => {
                return OfflineValidateResult {
                    valid: false,
                    claims: None,
                    reason: Some("Invalid token format".to_string()),
                };
            }
        };

        // Check device ID matches
        if claims.device_id != self.device_id {
            return OfflineValidateResult {
                valid: false,
                claims: Some(claims),
                reason: Some("Device mismatch".to_string()),
            };
        }

        // Check license expiration
        if is_license_expired(&claims) {
            return OfflineValidateResult {
                valid: false,
                claims: Some(claims),
                reason: Some("License expired".to_string()),
            };
        }

        OfflineValidateResult {
            valid: true,
            claims: Some(claims),
            reason: None,
        }
    }

    /// Online validation check (also checks revocation).
    pub async fn validate_online(&self) -> Result<ValidateResult> {
        let Some(token) = self.get_token() else {
            return Ok(ValidateResult {
                valid: false,
                license_exp: None,
                updates_exp: None,
            });
        };

        let claims = match decode_token(&token) {
            Ok(c) => c,
            Err(_) => {
                return Ok(ValidateResult {
                    valid: false,
                    license_exp: None,
                    updates_exp: None,
                });
            }
        };

        let url = format!(
            "{}/validate?public_key={}&jti={}",
            self.base_url,
            urlencoding::encode(&self.public_key),
            claims.jti
        );

        match self.get::<ValidateResponse>(&url).await {
            Ok(r) => Ok(r.into()),
            Err(_) => Ok(ValidateResult {
                valid: false,
                license_exp: None,
                updates_exp: None,
            }),
        }
    }

    /// Sync with the server and validate the license.
    ///
    /// This is the recommended method for online/subscription apps. It:
    /// 1. Tries to reach the server to check for updates (renewals, revocation)
    /// 2. Refreshes the token if the server has newer expiration dates
    /// 3. Falls back to offline validation if the server is unreachable
    ///
    /// Always returns a result - never returns an error for network failures.
    ///
    /// # Example
    /// ```rust,ignore
    /// // On app startup for subscription apps
    /// let result = paycheck.sync().await;
    ///
    /// if result.valid {
    ///     if result.offline {
    ///         println!("Offline mode - using cached license");
    ///     }
    ///     load_app(&result.claims.unwrap().tier);
    /// } else {
    ///     if !result.synced {
    ///         println!("Please connect to verify your license");
    ///     } else {
    ///         show_activation_prompt();
    ///     }
    /// }
    /// ```
    pub async fn sync(&self) -> SyncResult {
        let Some(token) = self.get_token() else {
            return SyncResult {
                valid: false,
                claims: None,
                synced: false,
                offline: true,
                reason: None,
            };
        };

        // First, verify signature locally
        if !verify_token(&token, &self.public_key) {
            return SyncResult {
                valid: false,
                claims: None,
                synced: false,
                offline: true,
                reason: Some("Invalid signature".to_string()),
            };
        }

        // Decode claims
        let mut claims = match decode_token(&token) {
            Ok(c) => c,
            Err(_) => {
                return SyncResult {
                    valid: false,
                    claims: None,
                    synced: false,
                    offline: true,
                    reason: Some("Invalid token format".to_string()),
                };
            }
        };

        // Check device ID matches
        if claims.device_id != self.device_id {
            return SyncResult {
                valid: false,
                claims: Some(claims),
                synced: false,
                offline: true,
                reason: Some("Device mismatch".to_string()),
            };
        }

        // Try to sync with server
        let url = format!(
            "{}/validate?public_key={}&jti={}",
            self.base_url,
            urlencoding::encode(&self.public_key),
            claims.jti
        );

        match self.get::<ValidateResponse>(&url).await {
            Ok(response) => {
                if !response.valid {
                    return SyncResult {
                        valid: false,
                        claims: Some(claims),
                        synced: true,
                        offline: false,
                        reason: Some("Revoked or invalid".to_string()),
                    };
                }

                // Check if server has updated expiration - refresh token if so
                if response.license_exp != claims.license_exp {
                    if let Ok(new_token) = self.refresh_token().await {
                        if let Ok(new_claims) = decode_token(&new_token) {
                            claims = new_claims;
                        }
                    }
                    // Refresh failed, but validation passed - continue with current token
                }

                // Check license expiration with potentially updated claims
                if is_license_expired(&claims) {
                    return SyncResult {
                        valid: false,
                        claims: Some(claims),
                        synced: true,
                        offline: false,
                        reason: Some("License expired".to_string()),
                    };
                }

                SyncResult {
                    valid: true,
                    claims: Some(claims),
                    synced: true,
                    offline: false,
                    reason: None,
                }
            }
            Err(_) => {
                // Server unreachable - fall back to offline validation
                if is_license_expired(&claims) {
                    return SyncResult {
                        valid: false,
                        claims: Some(claims),
                        synced: false,
                        offline: true,
                        reason: Some("License expired".to_string()),
                    };
                }

                SyncResult {
                    valid: true,
                    claims: Some(claims),
                    synced: false,
                    offline: true,
                    reason: None,
                }
            }
        }
    }

    /// Import a JWT token directly (offline activation).
    ///
    /// Use this when you have a JWT from another source (clipboard, QR code,
    /// file, enterprise IT distribution). The token is verified locally using
    /// Ed25519 signature verification - no network required.
    ///
    /// # Example
    /// ```rust,ignore
    /// // Offline activation from clipboard
    /// let jwt = get_clipboard_text();
    /// let result = paycheck.import_token(&jwt);
    /// if result.valid {
    ///     println!("Activated offline! Tier: {}", result.claims.unwrap().tier);
    /// }
    /// ```
    pub fn import_token(&self, token: &str) -> ImportResult {
        // Verify Ed25519 signature
        if !verify_token(token, &self.public_key) {
            return ImportResult {
                valid: false,
                claims: None,
                reason: Some("Invalid signature".to_string()),
            };
        }

        // Decode and validate claims
        let claims = match decode_token(token) {
            Ok(c) => c,
            Err(_) => {
                return ImportResult {
                    valid: false,
                    claims: None,
                    reason: Some("Invalid token format".to_string()),
                };
            }
        };

        // Check device ID matches
        if claims.device_id != self.device_id {
            return ImportResult {
                valid: false,
                claims: Some(claims),
                reason: Some("Device mismatch".to_string()),
            };
        }

        // Check license expiration
        if is_license_expired(&claims) {
            return ImportResult {
                valid: false,
                claims: Some(claims),
                reason: Some("License expired".to_string()),
            };
        }

        // Valid - store the token
        self.storage.set(keys::TOKEN, token);

        ImportResult {
            valid: true,
            claims: Some(claims),
            reason: None,
        }
    }

    /// Activate with a short-lived activation code.
    pub async fn activate_with_code(
        &self,
        code: &str,
        options: Option<DeviceInfo>,
    ) -> Result<ActivationResult> {
        let mut url = format!(
            "{}/redeem?public_key={}&code={}&device_id={}&device_type={}",
            self.base_url,
            urlencoding::encode(&self.public_key),
            code,
            self.device_id,
            self.device_type
        );

        if let Some(name) = options.and_then(|d| d.device_name) {
            url.push_str(&format!("&device_name={}", urlencoding::encode(&name)));
        }

        let response: RedeemResponse = self.get(&url).await?;

        self.storage.set(keys::TOKEN, &response.token);

        Ok(response.into())
    }

    // ==================== Helper Methods ====================

    /// Quick check if a valid license is stored.
    /// Performs offline signature verification.
    pub fn is_licensed(&self) -> bool {
        self.validate(None).valid
    }

    /// Get decoded license claims (without signature verification).
    pub fn get_license(&self) -> Option<LicenseClaims> {
        let token = self.get_token()?;
        decode_token(&token).ok()
    }

    /// Check if license has a specific feature.
    pub fn has_feature(&self, feature: &str) -> bool {
        self.get_license()
            .map(|c| c.features.iter().any(|f| f == feature))
            .unwrap_or(false)
    }

    /// Get the product tier.
    pub fn get_tier(&self) -> Option<String> {
        self.get_license().map(|c| c.tier)
    }

    /// Check if the license is expired.
    pub fn is_expired(&self) -> bool {
        self.get_license()
            .map(|c| is_license_expired(&c))
            .unwrap_or(true)
    }

    /// Check if the license covers a specific version by its release timestamp.
    pub fn covers_version(&self, timestamp: i64) -> bool {
        self.get_license()
            .map(|c| crate::jwt::covers_version(&c, timestamp))
            .unwrap_or(false)
    }

    // ==================== Token Management ====================

    /// Get the stored JWT token.
    pub fn get_token(&self) -> Option<String> {
        self.storage.get(keys::TOKEN)
    }

    /// Clear stored token.
    pub fn clear_token(&self) {
        self.storage.remove(keys::TOKEN);
    }

    /// Refresh the JWT token.
    pub async fn refresh_token(&self) -> Result<String> {
        let token = self.get_token().ok_or_else(PaycheckError::no_token)?;

        #[derive(Deserialize)]
        struct RefreshResponse {
            token: String,
        }

        let response: RefreshResponse = self.post_with_auth("/refresh", &(), &token).await?;

        self.storage.set(keys::TOKEN, &response.token);
        Ok(response.token)
    }

    // ==================== Device Management ====================

    /// Deactivate this device.
    pub async fn deactivate(&self) -> Result<DeactivateResult> {
        let token = self.ensure_fresh_token().await?;

        let response: DeactivateResponse = self
            .post_with_auth("/devices/deactivate", &(), &token)
            .await?;

        self.clear_token();

        Ok(response.into())
    }

    /// Get full license information including devices.
    /// Uses the stored JWT token for authentication.
    pub async fn get_license_info(&self) -> Result<LicenseInfo> {
        let token = self.ensure_fresh_token().await?;

        let url = format!(
            "{}/license?public_key={}",
            self.base_url,
            urlencoding::encode(&self.public_key)
        );

        let response: LicenseInfoResponse = self.get_with_auth(&url, &token).await?;
        Ok(response.into())
    }

    // ==================== Callback Handling ====================

    /// Handle the callback URL after payment redirect.
    ///
    /// Extracts the activation code and project ID from the callback URL.
    /// Use the code with `activate_with_code()` to complete activation.
    pub fn handle_callback(&self, url: &str) -> Result<CallbackResult> {
        let parsed =
            Url::parse(url).map_err(|_| PaycheckError::validation("Invalid callback URL"))?;

        let mut result = CallbackResult {
            status: CallbackStatus::Pending,
            code: None,
            project_id: None,
        };

        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "status" => {
                    result.status = if value == "success" {
                        CallbackStatus::Success
                    } else {
                        CallbackStatus::Pending
                    };
                }
                "code" => {
                    result.code = Some(value.to_string());
                }
                "project_id" => {
                    result.project_id = Some(value.to_string());
                }
                _ => {}
            }
        }

        Ok(result)
    }

    // ==================== Internal Helpers ====================

    async fn ensure_fresh_token(&self) -> Result<String> {
        let token = self.get_token().ok_or_else(PaycheckError::no_token)?;

        if self.auto_refresh {
            if let Ok(claims) = decode_token(&token) {
                if is_jwt_expired(&claims) {
                    return self.refresh_token().await;
                }
            }
        }

        Ok(token)
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| PaycheckError::network(e.to_string()))?;

        self.handle_response(response).await
    }

    async fn get_with_auth<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        token: &str,
    ) -> Result<T> {
        let response = self
            .http
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| PaycheckError::network(e.to_string()))?;

        self.handle_response(response).await
    }

    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| PaycheckError::network(e.to_string()))?;

        self.handle_response(response).await
    }

    async fn post_with_auth<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        token: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(body)
            .send()
            .await
            .map_err(|e| PaycheckError::network(e.to_string()))?;

        self.handle_response(response).await
    }

    async fn handle_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status().as_u16();

        if !response.status().is_success() {
            #[derive(Deserialize)]
            struct ErrorResponse {
                error: Option<String>,
                details: Option<String>,
            }

            let error_body: ErrorResponse = response.json().await.unwrap_or(ErrorResponse {
                error: Some("Unknown error".to_string()),
                details: None,
            });

            let message = match (&error_body.error, &error_body.details) {
                (Some(err), Some(details)) => format!("{}: {}", err, details),
                (Some(err), None) => err.clone(),
                (None, Some(details)) => details.clone(),
                (None, None) => format!("Request failed: {}", status),
            };
            let code = map_status_to_error_code(status, &message);

            return Err(PaycheckError::with_status(code, message, status));
        }

        response
            .json()
            .await
            .map_err(|e| PaycheckError::network(e.to_string()))
    }
}

impl std::fmt::Debug for Paycheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paycheck")
            .field("base_url", &self.base_url)
            .field("device_id", &self.device_id)
            .field("device_type", &self.device_type)
            .field("auto_refresh", &self.auto_refresh)
            .finish()
    }
}

/// Checkout options for the new API
#[derive(Debug, Clone, Default)]
pub struct CheckoutOptions {
    /// Payment provider
    pub provider: Option<String>,
    /// Customer ID
    pub customer_id: Option<String>,
    /// Redirect URL after payment
    pub redirect: Option<String>,
}
