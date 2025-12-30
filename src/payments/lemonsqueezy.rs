use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use hmac::{Hmac, Mac};

use crate::error::{AppError, Result};
use crate::models::LemonSqueezyConfig;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize)]
struct CreateCheckoutRequest {
    data: CheckoutData,
}

#[derive(Debug, Serialize)]
struct CheckoutData {
    #[serde(rename = "type")]
    data_type: String,
    attributes: CheckoutAttributes,
    relationships: CheckoutRelationships,
}

#[derive(Debug, Serialize)]
struct CheckoutAttributes {
    custom_price: Option<u64>,
    product_options: ProductOptions,
    checkout_options: CheckoutOptions,
    checkout_data: CheckoutDataPayload,
}

#[derive(Debug, Serialize)]
struct ProductOptions {
    redirect_url: String,
}

#[derive(Debug, Serialize)]
struct CheckoutOptions {
    button_color: String,
}

#[derive(Debug, Serialize)]
struct CheckoutDataPayload {
    custom: CustomData,
}

#[derive(Debug, Serialize)]
struct CustomData {
    paycheck_session_id: String,
    project_id: String,
    product_id: String,
}

#[derive(Debug, Serialize)]
struct CheckoutRelationships {
    store: RelationshipData,
    variant: RelationshipData,
}

#[derive(Debug, Serialize)]
struct RelationshipData {
    data: RelationshipId,
}

#[derive(Debug, Serialize)]
struct RelationshipId {
    #[serde(rename = "type")]
    data_type: String,
    id: String,
}

#[derive(Debug, Deserialize)]
struct CreateCheckoutResponse {
    data: CheckoutResponseData,
}

#[derive(Debug, Deserialize)]
struct CheckoutResponseData {
    id: String,
    attributes: CheckoutResponseAttributes,
}

#[derive(Debug, Deserialize)]
struct CheckoutResponseAttributes {
    url: String,
}

#[derive(Debug, Clone)]
pub struct LemonSqueezyClient {
    client: Client,
    api_key: String,
    store_id: String,
    webhook_secret: String,
}

impl LemonSqueezyClient {
    pub fn new(config: &LemonSqueezyConfig) -> Self {
        Self {
            client: Client::new(),
            api_key: config.api_key.clone(),
            store_id: config.store_id.clone(),
            webhook_secret: config.webhook_secret.clone(),
        }
    }

    pub async fn create_checkout(
        &self,
        session_id: &str,
        project_id: &str,
        product_id: &str,
        variant_id: &str,
        redirect_url: &str,
    ) -> Result<(String, String)> {
        let request = CreateCheckoutRequest {
            data: CheckoutData {
                data_type: "checkouts".to_string(),
                attributes: CheckoutAttributes {
                    custom_price: None,
                    product_options: ProductOptions {
                        redirect_url: redirect_url.to_string(),
                    },
                    checkout_options: CheckoutOptions {
                        button_color: "#7c3aed".to_string(),
                    },
                    checkout_data: CheckoutDataPayload {
                        custom: CustomData {
                            paycheck_session_id: session_id.to_string(),
                            project_id: project_id.to_string(),
                            product_id: product_id.to_string(),
                        },
                    },
                },
                relationships: CheckoutRelationships {
                    store: RelationshipData {
                        data: RelationshipId {
                            data_type: "stores".to_string(),
                            id: self.store_id.clone(),
                        },
                    },
                    variant: RelationshipData {
                        data: RelationshipId {
                            data_type: "variants".to_string(),
                            id: variant_id.to_string(),
                        },
                    },
                },
            },
        };

        let response = self
            .client
            .post("https://api.lemonsqueezy.com/v1/checkouts")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Accept", "application/vnd.api+json")
            .header("Content-Type", "application/vnd.api+json")
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("LemonSqueezy API error: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!("LemonSqueezy API error: {}", error_text)));
        }

        let checkout: CreateCheckoutResponse = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse LemonSqueezy response: {}", e)))?;

        Ok((checkout.data.id, checkout.data.attributes.url))
    }

    pub fn verify_webhook_signature(&self, payload: &[u8], signature: &str) -> Result<bool> {
        let mut mac = HmacSha256::new_from_slice(self.webhook_secret.as_bytes())
            .map_err(|_| AppError::Internal("Invalid webhook secret".into()))?;
        mac.update(payload);
        let expected = hex::encode(mac.finalize().into_bytes());

        Ok(expected == signature)
    }
}

#[derive(Debug, Deserialize)]
pub struct LemonSqueezyWebhookEvent {
    pub meta: LemonSqueezyMeta,
    pub data: LemonSqueezyEventData,
}

#[derive(Debug, Deserialize)]
pub struct LemonSqueezyMeta {
    pub event_name: String,
    pub custom_data: Option<LemonSqueezyCustomData>,
}

#[derive(Debug, Deserialize)]
pub struct LemonSqueezyCustomData {
    pub paycheck_session_id: Option<String>,
    pub project_id: Option<String>,
    pub product_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LemonSqueezyEventData {
    pub id: String,
    pub attributes: LemonSqueezyOrderAttributes,
}

#[derive(Debug, Deserialize)]
pub struct LemonSqueezyOrderAttributes {
    pub status: String,
    pub user_email: Option<String>,
}
