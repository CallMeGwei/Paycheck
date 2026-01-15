//! Public API tests - customer-facing endpoints

#[path = "public/buy.rs"]
mod buy;

#[path = "public/callback.rs"]
mod callback;

#[path = "public/redeem.rs"]
mod redeem;

#[path = "public/validate.rs"]
mod validate;

#[path = "public/license.rs"]
mod license;

#[path = "public/devices.rs"]
mod devices;

#[path = "public/refresh.rs"]
mod refresh;
