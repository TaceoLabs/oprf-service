//! Human-readable durations for configuration values and command line arguments.
//!
//! Durations are written as one or more `<integer><unit>` pairs, optionally separated by
//! whitespace, e.g. `500ms`, `10s`, `2min` or `1m 30s`. The pairs are summed up.
//!
//! | Unit                                       | Suffixes                          |
//! |--------------------------------------------|-----------------------------------|
//! | nanoseconds                                | `ns`, `nsec`                      |
//! | microseconds                               | `us`, `usec`                      |
//! | milliseconds                               | `ms`, `msec`                      |
//! | seconds                                    | `s`, `sec`, `second`, `seconds`   |
//! | minutes                                    | `m`, `min`, `minute`, `minutes`   |
//! | hours                                      | `h`, `hr`, `hour`, `hours`        |
//! | days                                       | `d`, `day`, `days`                |
//! | weeks                                      | `w`, `week`, `weeks`              |
//! | months (30.44 days)                        | `M`, `month`, `months`            |
//! | years (365.25 days)                        | `y`, `year`, `years`              |
//!
//! Use [`deserialize`] as `#[serde(deserialize_with = "oprf_types::duration::deserialize")]` for
//! config structs and [`parse`] as clap `value_parser`.

use std::{error::Error, fmt, time::Duration};

use serde::{Deserialize, Deserializer, de};

const NANOS_PER_SEC: u128 = 1_000_000_000;

/// Error returned by [`parse`] for malformed or out-of-range durations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseDurationError(String);

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid duration: {}", self.0)
    }
}

impl Error for ParseDurationError {}

/// Parses a duration like `10s`, `500ms` or `1m 30s`. See the [module docs](self) for the syntax.
///
/// # Errors
///
/// Returns a [`ParseDurationError`] if the input is empty, contains an unknown unit, a pair
/// without a number or unit, or if the total does not fit into a [`Duration`].
pub fn parse(input: &str) -> Result<Duration, ParseDurationError> {
    let mut rest = input.trim();
    if rest.is_empty() {
        return Err(ParseDurationError("empty input".to_owned()));
    }
    let mut total_nanos: u128 = 0;
    while !rest.is_empty() {
        let digits_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (digits, after_number) = rest.split_at(digits_end);
        let number: u128 = digits
            .parse()
            .map_err(|_| ParseDurationError(format!("expected a number in {input:?}")))?;
        let after_number = after_number.trim_start();
        let unit_end = after_number
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(after_number.len());
        let (unit, remaining) = after_number.split_at(unit_end);
        let unit_nanos = unit_nanos(unit)
            .ok_or_else(|| ParseDurationError(format!("unknown unit {unit:?} in {input:?}")))?;
        total_nanos = number
            .checked_mul(unit_nanos)
            .and_then(|nanos| total_nanos.checked_add(nanos))
            .ok_or_else(|| ParseDurationError(format!("{input:?} is too large")))?;
        rest = remaining.trim_start();
    }
    let secs = u64::try_from(total_nanos / NANOS_PER_SEC)
        .map_err(|_| ParseDurationError(format!("{input:?} is too large")))?;
    let subsec_nanos = u32::try_from(total_nanos % NANOS_PER_SEC)
        .map_err(|_| ParseDurationError(format!("{input:?} is too large")))?;
    Ok(Duration::new(secs, subsec_nanos))
}

/// Serde `deserialize_with` function that reads a duration string accepted by [`parse`].
///
/// # Errors
///
/// Fails if the value is not a string or if [`parse`] rejects it.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse(&value).map_err(de::Error::custom)
}

fn unit_nanos(unit: &str) -> Option<u128> {
    let nanos = match unit {
        "ns" | "nsec" => 1,
        "us" | "usec" => 1_000,
        "ms" | "msec" => 1_000_000,
        "s" | "sec" | "second" | "seconds" => NANOS_PER_SEC,
        "m" | "min" | "minute" | "minutes" => 60 * NANOS_PER_SEC,
        "h" | "hr" | "hour" | "hours" => 3_600 * NANOS_PER_SEC,
        "d" | "day" | "days" => 86_400 * NANOS_PER_SEC,
        "w" | "week" | "weeks" => 604_800 * NANOS_PER_SEC,
        "M" | "month" | "months" => 2_630_016 * NANOS_PER_SEC,
        "y" | "year" | "years" => 31_557_600 * NANOS_PER_SEC,
        _ => return None,
    };
    Some(nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_units() {
        assert_eq!(
            parse("10s").expect("valid duration"),
            Duration::from_secs(10)
        );
        assert_eq!(
            parse("500ms").expect("valid duration"),
            Duration::from_millis(500)
        );
        assert_eq!(
            parse("2min").expect("valid duration"),
            Duration::from_secs(120)
        );
        assert_eq!(
            parse("1 day").expect("valid duration"),
            Duration::from_hours(24)
        );
        assert_eq!(
            parse("1h").expect("valid duration"),
            Duration::from_hours(1)
        );
        assert_eq!(
            parse("1w").expect("valid duration"),
            Duration::from_hours(168)
        );
        assert_eq!(
            parse("7ns").expect("valid duration"),
            Duration::from_nanos(7)
        );
        assert_eq!(parse("0s").expect("valid duration"), Duration::ZERO);
    }

    #[test]
    fn parses_combined_units() {
        assert_eq!(
            parse("1m 30s").expect("valid duration"),
            Duration::from_secs(90)
        );
        assert_eq!(
            parse("1h30m").expect("valid duration"),
            Duration::from_mins(90)
        );
        assert_eq!(
            parse(" 1s 500ms ").expect("valid duration"),
            Duration::from_millis(1_500)
        );
    }

    #[test]
    fn rejects_malformed_input() {
        for input in ["", "  ", "10", "s", "10x", "1.5s", "-1s", "1s,2s", "1 s 2"] {
            parse(input).expect_err("rejected input");
        }
    }

    #[test]
    fn rejects_overflow() {
        parse("18446744073709551616s").expect_err("rejected input");
        parse("340282366920938463463374607431768211455y").expect_err("rejected input");
    }

    #[test]
    fn deserializes_from_string() {
        #[derive(Debug, Deserialize)]
        struct Config {
            #[serde(deserialize_with = "deserialize")]
            timeout: Duration,
        }
        let config: Config =
            serde_json::from_str(r#"{"timeout":"1m 30s"}"#).expect("valid duration");
        assert_eq!(config.timeout, Duration::from_secs(90));
        serde_json::from_str::<Config>(r#"{"timeout":"soon"}"#).expect_err("rejected input");
        serde_json::from_str::<Config>(r#"{"timeout":90}"#).expect_err("rejected input");
    }
}
