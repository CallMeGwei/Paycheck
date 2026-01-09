//! Device ID generation utilities

use crate::error::{PaycheckError, PaycheckErrorCode, Result};

/// Generate a random UUID v4
pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generate a stable machine ID for desktop apps.
///
/// Platform-specific implementation:
/// - Linux: `/etc/machine-id`
/// - macOS: IOPlatformSerialNumber from IOKit
/// - Windows: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
///
/// The ID is hashed for privacy before returning.
pub fn get_machine_id() -> Result<String> {
    let raw_id = get_raw_machine_id()?;

    // Hash the ID for privacy (don't expose actual hardware IDs)
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    raw_id.hash(&mut hasher);
    let hash = hasher.finish();

    Ok(format!("machine-{:016x}", hash))
}

#[cfg(target_os = "linux")]
fn get_raw_machine_id() -> Result<String> {
    // Try /etc/machine-id first (systemd)
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let id = id.trim();
        if !id.is_empty() {
            return Ok(id.to_string());
        }
    }

    // Fallback to /var/lib/dbus/machine-id
    if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        let id = id.trim();
        if !id.is_empty() {
            return Ok(id.to_string());
        }
    }

    Err(PaycheckError::new(
        PaycheckErrorCode::ValidationError,
        "Could not determine machine ID. Try using device_type: uuid instead.",
    ))
}

#[cfg(target_os = "macos")]
fn get_raw_machine_id() -> Result<String> {
    // Use IOKit to get the platform serial number
    // This requires running: ioreg -rd1 -c IOPlatformExpertDevice
    let output = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map_err(|_| {
            PaycheckError::new(
                PaycheckErrorCode::ValidationError,
                "Failed to run ioreg command",
            )
        })?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Parse the IOPlatformSerialNumber from the output
    for line in output_str.lines() {
        if line.contains("IOPlatformSerialNumber") {
            // Line format: "IOPlatformSerialNumber" = "XXXXX"
            if let Some(start) = line.rfind('"') {
                if let Some(end) = line[..start].rfind('"') {
                    let serial = &line[end + 1..start];
                    if !serial.is_empty() {
                        return Ok(serial.to_string());
                    }
                }
            }
        }
    }

    // Fallback: try hardware UUID
    for line in output_str.lines() {
        if line.contains("IOPlatformUUID") {
            if let Some(start) = line.rfind('"') {
                if let Some(end) = line[..start].rfind('"') {
                    let uuid = &line[end + 1..start];
                    if !uuid.is_empty() {
                        return Ok(uuid.to_string());
                    }
                }
            }
        }
    }

    Err(PaycheckError::new(
        PaycheckErrorCode::ValidationError,
        "Could not determine machine ID. Try using device_type: uuid instead.",
    ))
}

#[cfg(target_os = "windows")]
fn get_raw_machine_id() -> Result<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let crypto = hklm
        .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
        .map_err(|_| {
            PaycheckError::new(
                PaycheckErrorCode::ValidationError,
                "Failed to open Cryptography registry key",
            )
        })?;

    let machine_guid: String = crypto.get_value("MachineGuid").map_err(|_| {
        PaycheckError::new(
            PaycheckErrorCode::ValidationError,
            "Failed to read MachineGuid from registry",
        )
    })?;

    Ok(machine_guid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn get_raw_machine_id() -> Result<String> {
    Err(PaycheckError::new(
        PaycheckErrorCode::ValidationError,
        "Machine ID not supported on this platform. Use device_type: uuid instead.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_uuid() {
        let id1 = generate_uuid();
        let id2 = generate_uuid();

        // UUIDs should be different
        assert_ne!(id1, id2);

        // UUIDs should be valid format
        assert!(uuid::Uuid::parse_str(&id1).is_ok());
        assert!(uuid::Uuid::parse_str(&id2).is_ok());
    }

    #[test]
    fn test_machine_id_consistency() {
        // Machine ID should be consistent across calls
        if let Ok(id1) = get_machine_id() {
            if let Ok(id2) = get_machine_id() {
                assert_eq!(id1, id2);
            }
        }
    }
}
