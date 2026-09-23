//! Manager timestamps are RFC 3339 (Go's `time.Time` JSON). The desktop only
//! needs to show them as UTC clock times and coarse ages, so it parses them
//! without a date/time dependency.

/// Seconds since the Unix epoch, or None for empty or malformed input
/// (including Go's zero time, which predates any real observation).
pub fn parse(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = value.get(range)?;
        digits
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| digits.parse().ok())
            .flatten()
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = &value[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && matches!(&rest[..1], "+" | "-") && &rest[3..4] == ":" => {
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            let hours: i64 = rest[1..3].parse().ok()?;
            let minutes: i64 = rest[4..6].parse().ok()?;
            sign * (hours * 3600 + minutes * 60)
        }
        _ => return None,
    };
    if year < 1970 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// Milliseconds since the Unix epoch, keeping the fractional second.
pub fn parse_millis(value: &str) -> Option<i64> {
    let seconds = parse(value)?;
    let fraction = value
        .get(19..)
        .and_then(|rest| rest.strip_prefix('.'))
        .map(|rest| {
            rest.bytes()
                .take_while(u8::is_ascii_digit)
                .take(3)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let millis = fraction
        .iter()
        .chain(std::iter::repeat(&b'0'))
        .take(3)
        .fold(0, |acc, digit| acc * 10 + i64::from(digit - b'0'));
    Some(seconds * 1000 + millis)
}

/// UTC time of day with milliseconds, for packet timestamps.
pub fn clock_millis(millis: i64) -> String {
    format!(
        "{}.{:03}",
        clock(millis.div_euclid(1000)),
        millis.rem_euclid(1000)
    )
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for a Unix time in milliseconds (demo data).
pub fn format_millis(millis: i64) -> String {
    let base = format(millis.div_euclid(1000));
    format!("{}.{:03}Z", &base[..19], millis.rem_euclid(1000))
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix time (used by demo data).
pub fn format(seconds: i64) -> String {
    let (days, time) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        time / 60 % 60,
        time % 60
    )
}

/// UTC time of day, matching the Activity drawer.
pub fn clock(seconds: i64) -> String {
    let time = seconds.rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", time / 3600, time / 60 % 60, time % 60)
}

/// "now", "12 s", "4 m", "3 h", "2 d". Future times (clock skew) read "now".
pub fn age(then: i64, now: i64) -> String {
    let elapsed = now - then;
    match elapsed {
        ..=0 => "now".into(),
        1..=59 => format!("{elapsed} s"),
        60..=3599 => format!("{} m", elapsed / 60),
        3600..=86_399 => format!("{} h", elapsed / 3600),
        _ => format!("{} d", elapsed / 86_400),
    }
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

// Howard Hinnant's civil-calendar algorithms (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_rfc3339_and_rejects_zero_or_malformed_times() {
        assert_eq!(parse("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse("2026-09-22T09:42:06Z"), Some(1_790_070_126));
        assert_eq!(parse("2026-09-22T09:42:06.123456789Z"), Some(1_790_070_126));
        assert_eq!(parse("2026-09-22T11:42:06+02:00"), Some(1_790_070_126));
        assert_eq!(parse("2026-09-22T04:42:06-05:00"), Some(1_790_070_126));
        for bad in [
            "",
            "0001-01-01T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-09-22 09:42",
            "2026-09-22T09:42:06",
            "2026-09-22T09:42:06.Z",
            "2026-09-22T09:42:06+0200",
            "20x6-09-22T09:42:06Z",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn formatting_round_trips_and_ages_are_coarse() {
        for seconds in [0, 951_782_400, 1_790_070_126, 4_102_444_799] {
            assert_eq!(parse(&format(seconds)), Some(seconds));
        }
        assert_eq!(format(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(clock(1_790_070_126), "09:42:06");
        assert_eq!(age(100, 90), "now");
        assert_eq!(age(100, 112), "12 s");
        assert_eq!(age(0, 250), "4 m");
        assert_eq!(age(0, 3 * 3600 + 5), "3 h");
        assert_eq!(age(0, 2 * 86_400), "2 d");
        assert_eq!(
            parse_millis("2026-09-22T09:42:06.1Z"),
            Some(1_790_070_126_100)
        );
        assert_eq!(
            parse_millis("2026-09-22T09:42:06.123456789Z"),
            Some(1_790_070_126_123)
        );
        assert_eq!(
            parse_millis("2026-09-22T09:42:06Z"),
            Some(1_790_070_126_000)
        );
        assert_eq!(clock_millis(1_790_070_126_045), "09:42:06.045");
        assert_eq!(
            parse_millis(&format_millis(1_790_070_126_045)),
            Some(1_790_070_126_045)
        );
    }
}
