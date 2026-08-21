use crate::SeatbeltError;

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
