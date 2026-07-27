//! Minimal RFC3339 parsing, hand-rolled to avoid a chrono dependency for
//! what this SDK only ever needs to *parse* (UTC, optional fractional
//! seconds, `Z` or a numeric offset suffix — matching what Go's
//! `time.Parse(time.RFC3339, ...)` accepts).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn parse(s: &str) -> Result<SystemTime, String> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return Err(format!("too short for RFC3339: {s:?}"));
    }
    let year: i64 = s[0..4].parse().map_err(|_| format!("bad year in {s:?}"))?;
    if bytes[4] != b'-' {
        return Err(format!("bad separator in {s:?}"));
    }
    let month: u32 = s[5..7].parse().map_err(|_| format!("bad month in {s:?}"))?;
    let day: u32 = s[8..10].parse().map_err(|_| format!("bad day in {s:?}"))?;
    let hour: u32 = s[11..13]
        .parse()
        .map_err(|_| format!("bad hour in {s:?}"))?;
    let minute: u32 = s[14..16]
        .parse()
        .map_err(|_| format!("bad minute in {s:?}"))?;
    let second: u32 = s[17..19]
        .parse()
        .map_err(|_| format!("bad second in {s:?}"))?;

    let mut rest = &s[19..];
    let mut millis: u32 = 0;
    if rest.starts_with('.') {
        let end = rest[1..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let frac = &rest[1..end];
        let mut frac3 = frac.to_string();
        while frac3.len() < 3 {
            frac3.push('0');
        }
        millis = frac3[..3].parse().unwrap_or(0);
        rest = &rest[end..];
    }

    let offset_secs: i64 = if rest == "Z" || rest.is_empty() {
        0
    } else if let Some(sign) = rest.chars().next() {
        if sign != '+' && sign != '-' {
            return Err(format!("bad offset in {s:?}"));
        }
        let off = &rest[1..];
        if off.len() < 5 || off.as_bytes()[2] != b':' {
            return Err(format!("bad offset in {s:?}"));
        }
        let oh: i64 = off[0..2]
            .parse()
            .map_err(|_| format!("bad offset hour in {s:?}"))?;
        let om: i64 = off[3..5]
            .parse()
            .map_err(|_| format!("bad offset minute in {s:?}"))?;
        let total = oh * 3600 + om * 60;
        if sign == '+' {
            total
        } else {
            -total
        }
    } else {
        0
    };

    let days = days_from_civil(year, month, day);
    let secs_of_day = (hour as i64) * 3600 + (minute as i64) * 60 + (second as i64);
    let unix_secs = days * 86400 + secs_of_day - offset_secs;

    let base = if unix_secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(unix_secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs((-unix_secs) as u64)
    };
    Ok(base + Duration::from_millis(millis as u64))
}

/// Formats a SystemTime as bare RFC3339 UTC with NO fractional seconds
/// (Go's `time.RFC3339`, `2006-01-02T15:04:05Z07:00` applied to a UTC
/// time) — used only for delegation Link.expires. Deliberately distinct
/// from `identity::system_time_rfc3339_milli`: Envelope/Index timestamps
/// are always millisecond-precision; a delegation Link's `expires` never
/// carries fractional seconds on the wire (see `testdata/awp-sig/
/// post-with-delegation-2link.json`'s `expires: "2025-07-21T09:54:03Z"`).
/// Reusing one formatter for both would sign different bytes than a Go
/// peer expects.
pub fn format_no_fraction(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let (y, mo, d, h, mi, s) = crate::identity::civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Howard Hinnant's `days_from_civil`, the inverse of the breakdown used in
/// `identity::civil_from_unix`.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as u64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe as i64 - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_millisecond_form() {
        let t = parse("2026-07-21T08:54:13.123Z").unwrap();
        let dur = t.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_millis() % 1000, 123);
    }

    #[test]
    fn parses_no_fraction_form() {
        let t = parse("2025-07-21T09:54:03Z").unwrap();
        let dur = t.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_millis() % 1000, 0);
    }

    #[test]
    fn round_trips_with_formatter() {
        use crate::identity::system_time_rfc3339_milli;
        let t = UNIX_EPOCH + Duration::from_millis(1_753_088_043_123);
        let formatted = system_time_rfc3339_milli(t);
        let reparsed = parse(&formatted).unwrap();
        assert_eq!(reparsed, t);
    }
}
