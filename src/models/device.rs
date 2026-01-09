use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum DeviceType {
    Uuid,
    Machine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub license_id: String,
    pub device_id: String,
    pub device_type: DeviceType,
    pub name: Option<String>,
    pub jti: String,
    pub activated_at: i64,
    pub last_seen_at: i64,
}
