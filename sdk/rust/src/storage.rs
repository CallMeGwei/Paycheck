//! Storage adapters for the Paycheck SDK

use std::collections::HashMap;
use std::sync::RwLock;

/// Storage keys
pub mod keys {
    pub const TOKEN: &str = concat!("paycheck:", "token");
    pub const DEVICE_ID: &str = concat!("paycheck:", "device_id");
}

/// Storage adapter trait for custom storage implementations
pub trait StorageAdapter: Send + Sync {
    /// Get a value by key
    fn get(&self, key: &str) -> Option<String>;

    /// Set a value by key
    fn set(&self, key: &str, value: &str);

    /// Remove a value by key
    fn remove(&self, key: &str);
}

/// In-memory storage adapter
///
/// Useful for testing or ephemeral storage.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    store: RwLock<HashMap<String, String>>,
}

impl MemoryStorage {
    /// Create a new memory storage
    pub fn new() -> Self {
        Self::default()
    }
}

impl StorageAdapter for MemoryStorage {
    fn get(&self, key: &str) -> Option<String> {
        self.store.read().ok()?.get(key).cloned()
    }

    fn set(&self, key: &str, value: &str) {
        if let Ok(mut store) = self.store.write() {
            store.insert(key.to_string(), value.to_string());
        }
    }

    fn remove(&self, key: &str) {
        if let Ok(mut store) = self.store.write() {
            store.remove(key);
        }
    }
}

/// File-based storage adapter
///
/// Stores data in a JSON file in the app's data directory.
#[cfg(feature = "native-storage")]
pub struct FileStorage {
    path: std::path::PathBuf,
    cache: RwLock<HashMap<String, String>>,
}

#[cfg(feature = "native-storage")]
impl FileStorage {
    /// Create a new file storage for the given app name
    ///
    /// Data is stored in:
    /// - Linux: `~/.local/share/{app_name}/paycheck.json`
    /// - macOS: `~/Library/Application Support/{app_name}/paycheck.json`
    /// - Windows: `C:\Users\{User}\AppData\Roaming\{app_name}\paycheck.json`
    pub fn new(app_name: &str) -> Option<Self> {
        let dirs = directories::ProjectDirs::from("", "", app_name)?;
        let data_dir = dirs.data_dir();

        // Create directory if it doesn't exist
        std::fs::create_dir_all(data_dir).ok()?;

        let path = data_dir.join("paycheck.json");

        // Load existing data
        let cache = if path.exists() {
            let contents = std::fs::read_to_string(&path).ok()?;
            serde_json::from_str(&contents).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Some(Self {
            path,
            cache: RwLock::new(cache),
        })
    }

    /// Save the cache to disk
    fn save(&self) {
        if let Ok(cache) = self.cache.read() {
            if let Ok(contents) = serde_json::to_string_pretty(&*cache) {
                let _ = std::fs::write(&self.path, contents);
            }
        }
    }
}

#[cfg(feature = "native-storage")]
impl StorageAdapter for FileStorage {
    fn get(&self, key: &str) -> Option<String> {
        self.cache.read().ok()?.get(key).cloned()
    }

    fn set(&self, key: &str, value: &str) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(key.to_string(), value.to_string());
        }
        self.save();
    }

    fn remove(&self, key: &str) {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(key);
        }
        self.save();
    }
}

#[cfg(feature = "native-storage")]
impl std::fmt::Debug for FileStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStorage")
            .field("path", &self.path)
            .finish()
    }
}
