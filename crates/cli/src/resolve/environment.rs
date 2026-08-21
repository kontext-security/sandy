use std::{env, ffi::OsString};

use sandy_core::{EnvironmentEntry, OsValue};

pub(crate) fn sanitized_environment(session_tmp: &std::path::Path) -> Vec<EnvironmentEntry> {
    let mut entries = Vec::new();
    for (key, value) in env::vars_os() {
        if sensitive_key(&key) || key == "TMPDIR" {
            continue;
        }
        entries.push(EnvironmentEntry {
            key: OsValue::from_os_str(&key),
            value: OsValue::from_os_str(&value),
        });
    }
    entries.push(EnvironmentEntry {
        key: OsValue::from_os_str(OsString::from("TMPDIR").as_os_str()),
        value: OsValue::from_os_str(session_tmp.as_os_str()),
    });
    entries
}

fn sensitive_key(key: &std::ffi::OsStr) -> bool {
    let Some(key) = key.to_str() else {
        return false;
    };
    key.starts_with("DYLD_")
        || key.starts_with("KONTEXT_")
        || matches!(key, "SSH_AUTH_SOCK" | "GIT_ASKPASS" | "SSH_ASKPASS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_sensitive_names() {
        assert!(sensitive_key(std::ffi::OsStr::new("DYLD_INSERT_LIBRARIES")));
        assert!(sensitive_key(std::ffi::OsStr::new("KONTEXT_SOCKET")));
        assert!(sensitive_key(std::ffi::OsStr::new("SSH_AUTH_SOCK")));
        assert!(!sensitive_key(std::ffi::OsStr::new("PATH")));
    }
}
