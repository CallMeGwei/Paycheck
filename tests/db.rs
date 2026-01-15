//! Database tests - CRUD operations, licensing, devices, soft delete

#[path = "db/crud.rs"]
mod crud;

#[path = "db/license.rs"]
mod license;

#[path = "db/device.rs"]
mod device;

#[path = "db/soft_delete.rs"]
mod soft_delete;
