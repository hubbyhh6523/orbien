//! Sanitises untrusted strings before they are written to the log (#11).
//!
//! Mirrors `orbien_client::sanitize::sanitize_for_logging`, plus truncation:
//! server log fields are capped at 128 chars so a hostile client cannot
//! flood the log with a single huge value. Same rules as the client:
//! - `\n` / `\r` → replaced with a space (prevents fake log lines)
//! - ANSI CSI escape sequences (`ESC [` … final-byte) → stripped entirely
//! - Other C0/C1 control characters (U+0000–U+001F, U+007F), except `\t` → dropped
//! - All printable characters and `\t` are preserved unchanged.

pub const MAX_LOG_FIELD_LEN: usize = 128;

pub fn sanitize_for_logging(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\n' | '\r' => out.push(' '),
            '\x1B' => {
                // ANSI CSI sequence: ESC '[' <params> <final-byte A-Za-z>
                if chars.peek() == Some(&'[') {
                    chars.next(); // consume '['
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() {
                            break;
                        }
                    }
                } else {
                    // Other two-byte escape: skip the following character.
                    chars.next();
                }
            }
            c if c.is_control() && c != '\t' => { /* drop */ }
            _ => out.push(ch),
        }
    }
    if out.chars().count() > MAX_LOG_FIELD_LEN {
        out = out.chars().take(MAX_LOG_FIELD_LEN).collect();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newlines_become_spaces() {
        assert_eq!(
            sanitize_for_logging("line1\nline2\rline3"),
            "line1 line2 line3"
        );
    }

    #[test]
    fn ansi_color_stripped() {
        assert_eq!(sanitize_for_logging("\x1B[31mred\x1B[0mnormal"), "rednormal");
    }

    #[test]
    fn long_input_truncated() {
        let out = sanitize_for_logging(&"x".repeat(200));
        assert_eq!(out.chars().count(), MAX_LOG_FIELD_LEN);
    }
}
