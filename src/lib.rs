//! Paycheck - Offline-first licensing system for indie developers
//!
//! This library provides the core functionality for the Paycheck licensing system,
//! including database operations, JWT handling, payment provider integration, and API handlers.

pub mod config;
pub mod crypto;
pub mod db;
pub mod email;
pub mod error;
pub mod extractors;
pub mod handlers;
pub mod jwt;
pub mod middleware;
pub mod models;
pub mod payments;
pub mod rate_limit;
pub mod util;
