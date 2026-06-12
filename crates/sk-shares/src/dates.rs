//! UTC date ⇄ window index, dependency-free (Howard Hinnant's civil-date
//! algorithms). Booklets and CLIs speak dates; everything else speaks
//! window indices (`floor(unix / window_secs)`).

use crate::ShareError;

/// Days since 1970-01-01 for a proleptic-Gregorian civil date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64; // March-based month
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Inverse of `days_from_civil`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (era * 400 + yoe as i64 + (m <= 2) as i64, m, d)
}

/// `"YYYY-MM-DD"` (UTC midnight) → unix seconds.
pub fn parse_date(s: &str) -> Result<i64, ShareError> {
    let bad = || ShareError::BadDate(s.to_string());
    let parts: Vec<&str> = s.split('-').collect();
    let [y, m, d] = parts.as_slice() else { return Err(bad()) };
    let (y, m, d): (i64, u32, u32) = (
        y.parse().map_err(|_| bad())?,
        m.parse().map_err(|_| bad())?,
        d.parse().map_err(|_| bad())?,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }
    // reject 2026-02-31 style dates: roundtrip must be identity
    let days = days_from_civil(y, m, d);
    if civil_from_days(days) != (y, m, d) {
        return Err(bad());
    }
    Ok(days * 86_400)
}

pub fn window_for_date(s: &str, window_secs: u32) -> Result<u64, ShareError> {
    Ok(parse_date(s)? as u64 / window_secs as u64)
}

/// Start of `window` as `"YYYY-MM-DD"` (+`"+HH:MM"` for sub-day windows).
pub fn label_for_window(window: u64, window_secs: u32) -> String {
    let start = window * window_secs as u64;
    let (y, m, d) = civil_from_days((start / 86_400) as i64);
    let rem = start % 86_400;
    if rem == 0 && window_secs.is_multiple_of(86_400) {
        format!("{y:04}-{m:02}-{d:02}")
    } else {
        format!("{y:04}-{m:02}-{d:02}+{:02}:{:02}", rem / 3600, (rem % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(parse_date("1970-01-01").unwrap(), 0);
        assert_eq!(parse_date("2026-06-12").unwrap(), 1_781_222_400);
        assert_eq!(window_for_date("2026-06-12", 86_400).unwrap(), 20_616);
        assert_eq!(label_for_window(20_616, 86_400), "2026-06-12");
        assert_eq!(label_for_window(20_616 * 24 + 7, 3_600), "2026-06-12+07:00");
    }

    #[test]
    fn rejects_garbage() {
        for s in ["2026-02-31", "2026-13-01", "yesterday", "2026-6", "2026-06-12T00:00"] {
            assert!(parse_date(s).is_err(), "{s} should be rejected");
        }
    }

    #[test]
    fn roundtrip_every_day_for_two_years() {
        for day in 20_000..20_730 {
            let label = label_for_window(day, 86_400);
            assert_eq!(window_for_date(&label, 86_400).unwrap(), day);
        }
    }
}
