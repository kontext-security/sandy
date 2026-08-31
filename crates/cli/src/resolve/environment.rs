use std::{env, ffi::OsString, path::Path};

use sandy_core::{EnvironmentEntry, OsValue};

pub(crate) fn sanitized_environment(
    session_tmp: &Path,
    default_ca_bundle: Option<&Path>,
) -> Vec<EnvironmentEntry> {
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
    append_default_ca_bundle(&mut entries, default_ca_bundle);
    entries
}

/// Returns the platform-maintained public root bundle when the caller has not
/// selected a certificate source explicitly.
///
/// Pointing clients at the operating system's public PEM bundle preserves
/// ordinary provider TLS without granting access to broader credential stores
/// or macOS Keychain services.
pub(crate) fn default_ca_bundle() -> Option<&'static Path> {
    if env::var_os("SSL_CERT_FILE").is_some_and(|value| !value.is_empty()) {
        return None;
    }
    [
        "/etc/ssl/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ]
    .into_iter()
    .map(Path::new)
    .find(|path| path.is_file())
}

fn append_default_ca_bundle(entries: &mut Vec<EnvironmentEntry>, bundle: Option<&Path>) {
    let Some(bundle) = bundle else {
        return;
    };
    if let Some(entry) = entries
        .iter_mut()
        .find(|entry| entry.key.as_bytes() == b"SSL_CERT_FILE")
    {
        if entry.value.as_bytes().is_empty() {
            entry.value = OsValue::from_os_str(bundle.as_os_str());
        }
        return;
    }
    entries.push(EnvironmentEntry {
        key: OsValue::from_os_str(std::ffi::OsStr::new("SSL_CERT_FILE")),
        value: OsValue::from_os_str(bundle.as_os_str()),
    });
}

fn sensitive_key(key: &std::ffi::OsStr) -> bool {
    let Some(key) = key.to_str() else {
        return false;
    };
    key.starts_with("DYLD_")
        || key.starts_with("LD_")
        || key.starts_with("KONTEXT_")
        || matches!(key, "SSH_AUTH_SOCK" | "GIT_ASKPASS" | "SSH_ASKPASS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_sensitive_names() {
        assert!(sensitive_key(std::ffi::OsStr::new("DYLD_INSERT_LIBRARIES")));
        assert!(sensitive_key(std::ffi::OsStr::new("LD_PRELOAD")));
        assert!(sensitive_key(std::ffi::OsStr::new("LD_LIBRARY_PATH")));
        assert!(sensitive_key(std::ffi::OsStr::new("KONTEXT_SOCKET")));
        assert!(sensitive_key(std::ffi::OsStr::new("SSH_AUTH_SOCK")));
        assert!(!sensitive_key(std::ffi::OsStr::new("PATH")));
    }

    #[test]
    fn adds_default_ca_bundle_without_overriding_an_explicit_value() {
        let mut entries = Vec::new();
        append_default_ca_bundle(&mut entries, Some(Path::new("/system/roots.pem")));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key.as_bytes(), b"SSL_CERT_FILE");
        assert_eq!(entries[0].value.as_bytes(), b"/system/roots.pem");

        append_default_ca_bundle(&mut entries, Some(Path::new("/other/roots.pem")));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_bytes(), b"/system/roots.pem");
    }

    #[test]
    fn replaces_an_empty_ca_bundle_value() {
        let mut entries = vec![EnvironmentEntry {
            key: OsValue::from_os_str(std::ffi::OsStr::new("SSL_CERT_FILE")),
            value: OsValue::from_os_str(std::ffi::OsStr::new("")),
        }];
        append_default_ca_bundle(&mut entries, Some(Path::new("/system/roots.pem")));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.as_bytes(), b"/system/roots.pem");
    }
}
