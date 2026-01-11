use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub tier: String,
    pub license_exp_days: Option<i32>,
    pub updates_exp_days: Option<i32>,
    pub activation_limit: i32,
    pub device_limit: i32,
    pub features: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateProduct {
    pub name: String,
    pub tier: String,
    #[serde(default)]
    pub license_exp_days: Option<i32>,
    #[serde(default)]
    pub updates_exp_days: Option<i32>,
    #[serde(default)]
    pub activation_limit: i32,
    #[serde(default)]
    pub device_limit: i32,
    #[serde(default)]
    pub features: Vec<String>,
}

impl CreateProduct {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(AppError::BadRequest("name cannot be empty".into()));
        }
        if self.tier.trim().is_empty() {
            return Err(AppError::BadRequest("tier cannot be empty".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateProduct {
    pub name: Option<String>,
    pub tier: Option<String>,
    pub license_exp_days: Option<Option<i32>>,
    pub updates_exp_days: Option<Option<i32>>,
    pub activation_limit: Option<i32>,
    pub device_limit: Option<i32>,
    pub features: Option<Vec<String>>,
}

impl UpdateProduct {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref name) = self.name {
            if name.trim().is_empty() {
                return Err(AppError::BadRequest("name cannot be empty".into()));
            }
        }
        if let Some(ref tier) = self.tier {
            if tier.trim().is_empty() {
                return Err(AppError::BadRequest("tier cannot be empty".into()));
            }
        }
        Ok(())
    }
}
