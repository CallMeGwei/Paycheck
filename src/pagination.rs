//! Pagination types for list endpoints.
//!
//! Provides consistent pagination across all list endpoints.

use serde::{Deserialize, Serialize};

/// Query parameters for paginated list endpoints.
#[derive(Debug, Deserialize, Default)]
pub struct PaginationQuery {
    /// Maximum number of items to return (default: 50, max: 100)
    #[serde(default)]
    pub limit: Option<i64>,
    /// Number of items to skip (default: 0)
    #[serde(default)]
    pub offset: Option<i64>,
}

impl PaginationQuery {
    /// Get the limit, clamped to valid range
    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }

    /// Get the offset, minimum 0
    pub fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

/// Paginated response wrapper for list endpoints.
#[derive(Debug, Serialize)]
pub struct Paginated<T> {
    /// The items in this page
    pub items: Vec<T>,
    /// Total number of items (across all pages)
    pub total: i64,
    /// Maximum items per page (as requested)
    pub limit: i64,
    /// Items skipped (as requested)
    pub offset: i64,
    /// Whether there are more items beyond this page
    pub has_more: bool,
}

impl<T> Paginated<T> {
    /// Create a new paginated response
    pub fn new(items: Vec<T>, total: i64, limit: i64, offset: i64) -> Self {
        let has_more = offset + (items.len() as i64) < total;
        Self {
            items,
            total,
            limit,
            offset,
            has_more,
        }
    }
}
