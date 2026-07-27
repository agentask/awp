//! RFC 8785 (JCS) canonicalization, hand-rolled: no mature off-the-shelf
//! Rust crate was confirmed trustworthy at the time this SDK was written.
//! Validated against `github.com/gowebpki/jcs` (the same library the Go
//! reference implementation depends on) via `tests/jcs_crosscheck.rs`'s
//! fixture bytes — see that file for how the ground truth was generated.
//!
//! AWP's own wire types only ever produce strings, bools, integers, nested
//! objects/arrays, and null — never floats — so the RFC 8785 §3.2.2.3
//! ECMA-262 number-formatting rules below matter mostly for defensiveness
//! and the crosscheck fixtures, not for any real signed AWP object.

use serde_json::Value;

pub fn canonicalize(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&format_number(n)),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: sort object member names by UTF-16 code unit
            // ordering, not raw byte/codepoint ordering. For all-ASCII keys
            // (every AWP wire field name) UTF-16 and byte order coincide, but
            // this is done properly so non-ASCII keys sort correctly too.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(&map[*k], out);
            }
            out.push('}');
        }
    }
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let au: Vec<u16> = a.encode_utf16().collect();
    let bu: Vec<u16> = b.encode_utf16().collect();
    au.cmp(&bu)
}

/// RFC 8785 §3.2.2.3: numbers are formatted per ECMA-262 `ToString` applied
/// to the IEEE-754 double the JSON number parses to. serde_json's Number
/// already round-trips integers exactly and its `to_string()` on an f64
/// matches Rust's own `{}` Display for f64, which (like most modern
/// runtimes) produces the shortest round-trippable decimal — the same
/// contract ECMA-262 requires. The one divergence to guard against:
/// serde_json prints integral floats however they were written (e.g.
/// preserves "1.0"); ECMA-262 ToString never emits a trailing ".0" for an
/// integral value. We detect that case and fall back to formatting via the
/// f64 Display path, which strips it.
fn format_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n
        .as_f64()
        .expect("serde_json::Number is always representable as f64");
    if f.is_nan() || f.is_infinite() {
        // Not valid JSON; RFC 8785 doesn't define behavior. AWP never
        // produces this, so this branch exists only for robustness.
        return "null".to_string();
    }
    format_f64_ecma262(f)
}

/// ECMA-262 (2021) §6.1.6.1.20 `Number::toString` (radix 10), the exact
/// algorithm RFC 8785 §3.2.2.3 mandates. Rust's `{:e}` Display on f64
/// already produces the shortest round-trippable decimal digit string (the
/// same "s" this spec's step 5 wants) — this function takes that digit
/// string + decimal exponent and re-renders them per steps 6-8's fixed vs.
/// exponential notation rules, rather than trusting Rust's own `{}`
/// Display (which uses a different threshold for when to switch to
/// exponential notation than ECMA-262 does: Rust never does, ECMA-262
/// switches at 1e21 and 1e-7).
fn format_f64_ecma262(f: f64) -> String {
    if f == 0.0 {
        // ECMA-262 ToString prints both +0 and -0 as "0".
        return "0".to_string();
    }
    let negative = f < 0.0;
    let abs = f.abs();

    // Rust's `{:e}` gives "<digits>e<exp>" where <digits> has an implicit
    // decimal point after the first digit and is the shortest
    // round-trippable representation — exactly ECMA-262 step 5's "s" and
    // "n" (s = digits as an integer, n = exp + 1, i.e. 10^(n-1) <= abs <
    // 10^n).
    let sci = format!("{:e}", abs);
    let (mantissa, exp_str) = sci
        .split_once('e')
        .expect("Rust's {:e} always contains 'e'");
    let exp: i64 = exp_str
        .parse()
        .expect("Rust's {:e} exponent is always a valid integer");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let k = digits.len() as i64; // number of significant digits
    let n = exp + 1; // 10^(n-1) <= abs < 10^n

    let mut body = if k <= n && n <= 21 {
        // Step 6: integer, zero-padded, no fractional part.
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        // Step 7: decimal point within the digit string.
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        // Step 8: 0.000<digits>, no exponential notation yet.
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        // Step 9: exponential notation (k == 1 shortcut folded in).
        let mantissa_str = if k == 1 {
            digits.to_string()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        let e = n - 1;
        format!(
            "{mantissa_str}e{}{}",
            if e >= 0 { "+" } else { "-" },
            e.abs()
        )
    };

    if negative {
        body.insert(0, '-');
    }
    body
}

/// RFC 8785 §3.2.2.2 string escaping matches standard JSON string escaping
/// (control chars \b \f \n \r \t escaped, \" and \\ escaped, everything else
/// literal UTF-8) — the same rules serde_json's own string serializer
/// follows, so this reimplements it directly rather than depending on
/// serde_json::to_string producing the exact bytes we want elsewhere.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
