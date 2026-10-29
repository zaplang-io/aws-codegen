//! Deterministic identifier handling: Zap keyword/reserved escaping and the
//! case conversions the generator needs. AWS member, shape and operation names
//! are mostly PascalCase and rarely collide with Zap keywords, but the escaping
//! is applied uniformly so a model that *does* collide generates valid Zap.

/// Every reserved word the Zap lexer recognizes (crates/syntax/src/token.rs).
/// An identifier equal to one of these (case-sensitive, as the lexer matches)
/// must be escaped before it can appear in generated source.
pub const ZAP_KEYWORDS: &[&str] = &[
    "def",
    "return",
    "if",
    "elif",
    "else",
    "while",
    "do",
    "for",
    "in",
    "range",
    "match",
    "when",
    "case",
    "break",
    "continue",
    "auto",
    "const",
    "raise",
    "assert",
    "try",
    "except",
    "finally",
    "with",
    "as",
    "yield",
    "lambda",
    "import",
    "python",
    "spawn",
    "channel",
    "select",
    "close",
    "scope",
    "struct",
    "interface",
    "enum",
    "annotation",
    "decorator",
    "True",
    "False",
    "None",
    "and",
    "or",
    "not",
    "int32",
    "int64",
    "float32",
    "float64",
    "i32",
    "i64",
    "f32",
    "f64",
    "bool",
    "char",
    "str",
    "bytes",
    "bigint",
    "complex",
    "list",
    "dict",
    "set",
    "heap",
    "array",
    // `self` is the receiver binding in methods — reserved in effect.
    "self",
];

/// True if `s` collides with a Zap keyword.
pub fn is_keyword(s: &str) -> bool {
    ZAP_KEYWORDS.contains(&s)
}

/// Turn an arbitrary model name into a valid Zap identifier, deterministically.
///
/// - non-alphanumeric/underscore characters become `_`;
/// - a leading digit is prefixed with `_`;
/// - a keyword collision (or an empty result) gets a trailing `_`.
///
/// Returns `(ident, changed)` where `changed` is true when the result differs
/// from the input, so callers can flag it (a wire name that no longer matches
/// the field name — the derive rename hook is a #346 follow-up).
pub fn escape_ident(name: &str) -> (String, bool) {
    let mut out = String::with_capacity(name.len() + 1);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if i == 0 && ch.is_ascii_digit() {
                out.push('_');
            }
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    if is_keyword(&out) {
        out.push('_');
    }
    let changed = out != name;
    (out, changed)
}

/// Convert a PascalCase/camelCase name to snake_case, then escape it.
/// Runs of uppercase (e.g. `TTL`, `SSESpecification`) are handled so
/// `GetItem` -> `get_item` and `ListTagsOfResource` -> `list_tags_of_resource`.
pub fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    let chars: Vec<char> = name.chars().collect();
    for i in 0..chars.len() {
        let c = chars[i];
        if c == '_' || c == '-' || c == ' ' {
            if !out.ends_with('_') && !out.is_empty() {
                out.push('_');
            }
            continue;
        }
        if c.is_ascii_uppercase() {
            let prev = if i > 0 { Some(chars[i - 1]) } else { None };
            let next = chars.get(i + 1).copied();
            let boundary = match (prev, next) {
                (None, _) => false,
                // lower|digit -> Upper : word boundary (getItem).
                (Some(p), _) if p.is_ascii_lowercase() || p.is_ascii_digit() => true,
                // Upper -> Upper followed by lower : boundary before the run's
                // last cap (SSESpec -> sse_spec).
                (Some(p), Some(n)) if p.is_ascii_uppercase() && n.is_ascii_lowercase() => true,
                _ => false,
            };
            if boundary && !out.ends_with('_') {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    let (esc, _) = escape_ident(&out);
    esc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_escaping() {
        assert_eq!(escape_ident("in"), ("in_".to_string(), true));
        assert_eq!(escape_ident("select"), ("select_".to_string(), true));
        assert_eq!(escape_ident("str"), ("str_".to_string(), true));
        // PascalCase does not collide (lexer is case-sensitive).
        assert_eq!(escape_ident("Select"), ("Select".to_string(), false));
        assert_eq!(escape_ident("TableName"), ("TableName".to_string(), false));
    }

    #[test]
    fn non_ident_chars_and_digits() {
        assert_eq!(escape_ident("a.b-c"), ("a_b_c".to_string(), true));
        assert_eq!(escape_ident("3d"), ("_3d".to_string(), true));
        assert_eq!(escape_ident(""), ("_".to_string(), true));
    }

    #[test]
    fn snake() {
        assert_eq!(snake_case("GetItem"), "get_item");
        assert_eq!(snake_case("ListTagsOfResource"), "list_tags_of_resource");
        assert_eq!(snake_case("DescribeTimeToLive"), "describe_time_to_live");
        assert_eq!(snake_case("SSESpecification"), "sse_specification");
        assert_eq!(snake_case("PutItem"), "put_item");
    }
}
