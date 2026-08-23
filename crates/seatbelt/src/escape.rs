//! Single SBPL string-literal escaping boundary.

use crate::SeatbeltError;

/// Produces one quoted SBPL string literal from a validated policy value.
///
/// Quotes and backslashes have unambiguous escapes. Control characters are rejected instead of
/// encoded because Apple's private parser behavior is not a stable serialization contract for
/// them, and accepting literal newlines would make generated-policy review unsafe.
pub(crate) fn quoted(value: &str) -> Result<String, SeatbeltError> {
    if value.as_bytes().contains(&0) {
        return Err(SeatbeltError::Nul);
    }
    if value.chars().any(char::is_control) {
        return Err(SeatbeltError::ControlCharacter);
    }

    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            other => output.push(other),
        }
    }
    output.push('"');
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_and_backslashes() -> Result<(), SeatbeltError> {
        assert_eq!(quoted(r#"/tmp/a\"b"#)?, r#""/tmp/a\\\"b""#);
        Ok(())
    }

    #[test]
    fn rejects_control_characters() {
        assert!(matches!(
            quoted("/tmp/a\nb"),
            Err(SeatbeltError::ControlCharacter)
        ));
    }
}
