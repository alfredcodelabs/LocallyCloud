use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime};

use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleExpr {
    At(PrimitiveDateTime),
    Rate(Duration),
    Cron(CronExpr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpr {
    fields: [String; 6],
}

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;

    fn sleep_until<'a>(
        &'a self,
        due: OffsetDateTime,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let delta = due - self.now();
            if delta.is_positive() {
                let duration = StdDuration::try_from(delta).unwrap_or_default();
                tokio::time::sleep(duration).await;
            }
        })
    }
}

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Clone)]
pub struct SharedClock(pub Arc<dyn Clock>);

pub fn parse(expression: &str, allow_at: bool) -> Result<ScheduleExpr, String> {
    let expression = expression.trim();
    if let Some(inner) = expression
        .strip_prefix("at(")
        .and_then(|v| v.strip_suffix(')'))
    {
        if !allow_at {
            return Err("at() is not valid for EventBridge rules".into());
        }
        return parse_local_datetime(inner).map(ScheduleExpr::At);
    }
    if let Some(inner) = expression
        .strip_prefix("rate(")
        .and_then(|value| value.strip_suffix(')'))
    {
        let mut parts = inner.split_whitespace();
        let amount: i64 = parts
            .next()
            .ok_or_else(|| "rate value is required".to_string())?
            .parse()
            .map_err(|_| "rate value must be a positive integer".to_string())?;
        let unit = parts
            .next()
            .ok_or_else(|| "rate unit is required".to_string())?;
        if amount <= 0 || parts.next().is_some() {
            return Err("invalid rate expression".into());
        }
        let duration = match (amount, unit) {
            (1, "minute") => Duration::minutes(1),
            (1, "hour") => Duration::hours(1),
            (1, "day") => Duration::days(1),
            (value, "minutes") if value != 1 => Duration::minutes(amount),
            (value, "hours") if value != 1 => Duration::hours(amount),
            (value, "days") if value != 1 => Duration::days(amount),
            _ => return Err("rate unit or singular/plural form is invalid".into()),
        };
        return Ok(ScheduleExpr::Rate(duration));
    }
    if let Some(inner) = expression
        .strip_prefix("cron(")
        .and_then(|value| value.strip_suffix(')'))
    {
        let fields: Vec<String> = inner.split_whitespace().map(str::to_string).collect();
        let fields: [String; 6] = fields
            .try_into()
            .map_err(|_| "cron() requires six fields".to_string())?;
        let cron = CronExpr { fields };
        cron.validate()?;
        return Ok(ScheduleExpr::Cron(cron));
    }
    Err("expected at(), rate(), or cron() expression".into())
}

fn parse_local_datetime(value: &str) -> Result<PrimitiveDateTime, String> {
    let (date, time) = value
        .split_once('T')
        .ok_or_else(|| "at() requires YYYY-MM-DDTHH:MM:SS".to_string())?;
    let mut d = date.split('-');
    let year = parse_num(d.next(), "year")?;
    let month = Month::try_from(parse_num::<u8>(d.next(), "month")?)
        .map_err(|_| "invalid month".to_string())?;
    let day = parse_num(d.next(), "day")?;
    if d.next().is_some() {
        return Err("invalid date".into());
    }
    let mut t = time.split(':');
    let hour = parse_num(t.next(), "hour")?;
    let minute = parse_num(t.next(), "minute")?;
    let second = parse_num(t.next(), "second")?;
    if t.next().is_some() {
        return Err("invalid time".into());
    }
    let date =
        Date::from_calendar_date(year, month, day).map_err(|_| "invalid date".to_string())?;
    let time = Time::from_hms(hour, minute, second).map_err(|_| "invalid time".to_string())?;
    Ok(PrimitiveDateTime::new(date, time))
}

fn parse_num<T: std::str::FromStr>(value: Option<&str>, name: &str) -> Result<T, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .parse()
        .map_err(|_| format!("invalid {name}"))
}
impl CronExpr {
    fn validate(&self) -> Result<(), String> {
        let dom_unspecified = self.fields[2] == "?";
        let dow_unspecified = self.fields[4] == "?";
        if dom_unspecified == dow_unspecified {
            return Err("exactly one of day-of-month or day-of-week must be ?".into());
        }
        for (index, field) in self.fields.iter().enumerate() {
            if field.contains('?') && !matches!(index, 2 | 4) {
                return Err("? is valid only in a day field".into());
            }
            match index {
                0 => validate_field(field, 0, 59, NameSet::None)?,
                1 => validate_field(field, 0, 23, NameSet::None)?,
                2 => validate_day_of_month(field)?,
                3 => validate_field(field, 1, 12, NameSet::Month)?,
                4 => validate_day_of_week(field)?,
                _ => validate_field(field, 1970, 2199, NameSet::None)?,
            }
        }
        Ok(())
    }

    fn matches(&self, local: PrimitiveDateTime) -> bool {
        let date = local.date();
        field_matches(&self.fields[0], local.minute() as i32, 0, 59, NameSet::None)
            && field_matches(&self.fields[1], local.hour() as i32, 0, 23, NameSet::None)
            && day_of_month_matches(&self.fields[2], date)
            && field_matches(&self.fields[3], date.month() as i32, 1, 12, NameSet::Month)
            && day_of_week_matches(&self.fields[4], date)
            && field_matches(&self.fields[5], date.year(), 1970, 2199, NameSet::None)
    }
}

#[derive(Clone, Copy)]
enum NameSet {
    None,
    Month,
    Weekday,
}

fn validate_field(field: &str, min: i32, max: i32, names: NameSet) -> Result<(), String> {
    if field == "*" {
        return Ok(());
    }
    if field.is_empty() || field.contains('?') {
        return Err("invalid cron field".into());
    }
    for item in field.split(',') {
        let (base, step) = item.split_once('/').unwrap_or((item, "1"));
        let step: i32 = step.parse().map_err(|_| "invalid cron step".to_string())?;
        if step <= 0 {
            return Err("cron step must be positive".into());
        }
        let (start, end) = if base == "*" {
            (min, max)
        } else if let Some((left, right)) = base.split_once('-') {
            (cron_value(left, names)?, cron_value(right, names)?)
        } else {
            let value = cron_value(base, names)?;
            (value, if item.contains('/') { max } else { value })
        };
        if start < min || end > max || start > end {
            return Err("cron field is outside its range".into());
        }
    }
    Ok(())
}

fn cron_value(value: &str, names: NameSet) -> Result<i32, String> {
    let upper = value.to_ascii_uppercase();
    let named = match names {
        NameSet::None => None,
        NameSet::Month => [
            "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
        ]
        .iter()
        .position(|name| *name == upper)
        .map(|index| index as i32 + 1),
        NameSet::Weekday => ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
            .iter()
            .position(|name| *name == upper)
            .map(|index| index as i32 + 1),
    };
    if let Some(named) = named {
        Ok(named)
    } else {
        value.parse().map_err(|_| "invalid cron value".to_string())
    }
}

fn field_matches(field: &str, value: i32, min: i32, max: i32, names: NameSet) -> bool {
    if field == "*" || field == "?" {
        return true;
    }
    field.split(',').any(|item| {
        let (base, step) = item.split_once('/').unwrap_or((item, "1"));
        let step = step.parse::<i32>().unwrap_or(1);
        let (start, end) = if base == "*" {
            (min, max)
        } else if let Some((left, right)) = base.split_once('-') {
            (
                cron_value(left, names).unwrap_or(i32::MIN),
                cron_value(right, names).unwrap_or(i32::MIN),
            )
        } else {
            let exact = cron_value(base, names).unwrap_or(i32::MIN);
            (exact, if item.contains('/') { max } else { exact })
        };
        value >= start && value <= end && (value - start) % step == 0
    })
}

fn validate_day_of_month(field: &str) -> Result<(), String> {
    if field == "?" || field == "L" || field == "LW" {
        return Ok(());
    }
    if let Some(day) = field.strip_suffix('W') {
        let day: i32 = day.parse().map_err(|_| "invalid W day".to_string())?;
        return (1..=31)
            .contains(&day)
            .then_some(())
            .ok_or_else(|| "W day is outside its range".to_string());
    }
    validate_field(field, 1, 31, NameSet::None)
}

fn validate_day_of_week(field: &str) -> Result<(), String> {
    if field == "?" {
        return Ok(());
    }
    for item in field.split(',') {
        if let Some((day, occurrence)) = item.split_once('#') {
            let day = cron_value(day, NameSet::Weekday)?;
            let occurrence: i32 = occurrence
                .parse()
                .map_err(|_| "invalid # occurrence".to_string())?;
            if !(1..=7).contains(&day) || !(1..=5).contains(&occurrence) {
                return Err("day-of-week # value is outside its range".into());
            }
        } else if let Some(day) = item.strip_suffix('L') {
            let day = cron_value(day, NameSet::Weekday)?;
            if !(1..=7).contains(&day) {
                return Err("day-of-week L value is outside its range".into());
            }
        } else {
            validate_field(item, 1, 7, NameSet::Weekday)?;
        }
    }
    Ok(())
}

fn day_of_month_matches(field: &str, date: Date) -> bool {
    match field {
        "?" => true,
        "L" => date.day() == days_in_month(date.year(), date.month()),
        "LW" => date == last_business_day(date.year(), date.month()),
        value if value.ends_with('W') => {
            let Ok(day) = value.trim_end_matches('W').parse::<u8>() else {
                return false;
            };
            nearest_weekday(date.year(), date.month(), day).is_some_and(|day| day == date)
        }
        _ => field_matches(field, i32::from(date.day()), 1, 31, NameSet::None),
    }
}

fn day_of_week_matches(field: &str, date: Date) -> bool {
    if field == "?" {
        return true;
    }
    let weekday = weekday_number(date.weekday());
    field.split(',').any(|item| {
        if let Some((day, occurrence)) = item.split_once('#') {
            let day = cron_value(day, NameSet::Weekday).unwrap_or(i32::MIN);
            let occurrence = occurrence.parse::<u8>().unwrap_or(0);
            weekday == day && ((date.day() - 1) / 7 + 1) == occurrence
        } else if let Some(day) = item.strip_suffix('L') {
            let day = cron_value(day, NameSet::Weekday).unwrap_or(i32::MIN);
            weekday == day
                && date + Duration::days(7)
                    > Date::from_calendar_date(
                        date.year(),
                        date.month(),
                        days_in_month(date.year(), date.month()),
                    )
                    .expect("valid month end")
        } else {
            field_matches(item, weekday, 1, 7, NameSet::Weekday)
        }
    })
}

fn days_in_month(year: i32, month: Month) -> u8 {
    let next = if month == Month::December {
        Date::from_calendar_date(year + 1, Month::January, 1).expect("valid date")
    } else {
        Date::from_calendar_date(year, month.next(), 1).expect("valid date")
    };
    (next - Duration::days(1)).day()
}

fn last_business_day(year: i32, month: Month) -> Date {
    let mut date =
        Date::from_calendar_date(year, month, days_in_month(year, month)).expect("valid month end");
    while matches!(date.weekday(), Weekday::Saturday | Weekday::Sunday) {
        date -= Duration::days(1);
    }
    date
}

fn nearest_weekday(year: i32, month: Month, day: u8) -> Option<Date> {
    let day = day.min(days_in_month(year, month));
    let date = Date::from_calendar_date(year, month, day).ok()?;
    match date.weekday() {
        Weekday::Saturday if day == 1 => Some(date + Duration::days(2)),
        Weekday::Saturday => Some(date - Duration::days(1)),
        Weekday::Sunday if day == days_in_month(year, month) => Some(date - Duration::days(2)),
        Weekday::Sunday => Some(date + Duration::days(1)),
        _ => Some(date),
    }
}

fn weekday_number(day: Weekday) -> i32 {
    match day {
        Weekday::Sunday => 1,
        Weekday::Monday => 2,
        Weekday::Tuesday => 3,
        Weekday::Wednesday => 4,
        Weekday::Thursday => 5,
        Weekday::Friday => 6,
        Weekday::Saturday => 7,
    }
}
#[derive(Clone)]
struct TimeZone {
    transitions: Vec<(i64, i32)>,
    default_offset: i32,
    future: Option<PosixTimeZone>,
}

#[derive(Clone)]
struct PosixTimeZone {
    standard_offset: i32,
    daylight: Option<(i32, PosixRule, PosixRule)>,
}

#[derive(Clone, Copy)]
enum PosixRule {
    MonthWeekday {
        month: u8,
        week: u8,
        weekday: u8,
        seconds: i32,
    },
    JulianNoLeap {
        day: u16,
        seconds: i32,
    },
    Julian {
        day: u16,
        seconds: i32,
    },
}

impl TimeZone {
    fn load(name: &str) -> Result<Self, String> {
        if matches!(name, "UTC" | "Etc/UTC" | "Z") {
            return Ok(Self {
                transitions: Vec::new(),
                default_offset: 0,
                future: None,
            });
        }
        if name.is_empty()
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'+')
            })
        {
            return Err(format!("invalid IANA timezone {name}"));
        }
        let path = PathBuf::from("/usr/share/zoneinfo").join(name);
        let bytes = fs::read(path).map_err(|_| format!("unsupported IANA timezone {name}"))?;
        parse_tzif(&bytes).map_err(|error| format!("invalid IANA timezone {name}: {error}"))
    }

    fn offset_at(&self, instant: OffsetDateTime) -> Result<UtcOffset, String> {
        let timestamp = instant.unix_timestamp();
        let index = self
            .transitions
            .partition_point(|(transition, _)| *transition <= timestamp);
        let seconds = if self
            .transitions
            .last()
            .is_none_or(|(transition, _)| timestamp > *transition)
        {
            self.future
                .as_ref()
                .and_then(|future| future.offset_at(instant).ok())
                .unwrap_or_else(|| {
                    index
                        .checked_sub(1)
                        .and_then(|index| self.transitions.get(index))
                        .map(|(_, offset)| *offset)
                        .unwrap_or(self.default_offset)
                })
        } else {
            index
                .checked_sub(1)
                .and_then(|index| self.transitions.get(index))
                .map(|(_, offset)| *offset)
                .unwrap_or(self.default_offset)
        };
        UtcOffset::from_whole_seconds(seconds).map_err(|_| "invalid timezone offset".into())
    }

    fn local_to_utc(&self, local: PrimitiveDateTime) -> Result<OffsetDateTime, String> {
        let provisional = local.assume_utc();
        let first = self.offset_at(provisional)?;
        let mut instant = local.assume_offset(first).to_offset(UtcOffset::UTC);
        let actual = self.offset_at(instant)?;
        if actual != first {
            instant = local.assume_offset(actual).to_offset(UtcOffset::UTC);
        }
        Ok(instant)
    }
}

fn parse_tzif(bytes: &[u8]) -> Result<TimeZone, String> {
    if bytes.len() < 44 || &bytes[..4] != b"TZif" {
        return Err("missing TZif header".into());
    }
    let first = tzif_counts(bytes, 0)?;
    let version = bytes[4];
    let (header, time_size, counts) = if matches!(version, b'2' | b'3' | b'4') {
        let second = 44usize
            .checked_add(tzif_block_len(first, 4)?)
            .ok_or_else(|| "TZif block is too large".to_string())?;
        (second, 8usize, tzif_counts(bytes, second)?)
    } else {
        (0usize, 4usize, first)
    };
    let data = header + 44;
    let transition_bytes = counts.3 * time_size;
    let index_start = data + transition_bytes;
    let type_start = index_start + counts.3;
    let type_end = type_start + counts.4 * 6;
    if type_end > bytes.len() || counts.4 == 0 {
        return Err("truncated TZif data".into());
    }
    let mut types = Vec::with_capacity(counts.4);
    for index in 0..counts.4 {
        let offset = type_start + index * 6;
        types.push((read_i32(bytes, offset)?, bytes[offset + 4] != 0));
    }
    let default_offset = types
        .iter()
        .find(|(_, is_dst)| !*is_dst)
        .or_else(|| types.first())
        .map(|(offset, _)| *offset)
        .ok_or_else(|| "TZif has no local-time types".to_string())?;
    let mut transitions = Vec::with_capacity(counts.3);
    for index in 0..counts.3 {
        let offset = data + index * time_size;
        let timestamp = if time_size == 8 {
            read_i64(bytes, offset)?
        } else {
            i64::from(read_i32(bytes, offset)?)
        };
        let type_index = usize::from(bytes[index_start + index]);
        let (utc_offset, _) = types
            .get(type_index)
            .ok_or_else(|| "invalid TZif type index".to_string())?;
        transitions.push((timestamp, *utc_offset));
    }
    let block_end = header
        .checked_add(44)
        .and_then(|value| value.checked_add(tzif_block_len(counts, time_size).ok()?))
        .ok_or_else(|| "TZif block is too large".to_string())?;
    let future = if matches!(version, b'2' | b'3' | b'4') {
        bytes
            .get(block_end..)
            .and_then(|footer| footer.strip_prefix(b"\n"))
            .and_then(|footer| footer.split(|byte| *byte == b'\n').next())
            .filter(|footer| !footer.is_empty())
            .map(|footer| {
                std::str::from_utf8(footer)
                    .map_err(|_| "TZif POSIX footer is not UTF-8".to_string())
                    .and_then(parse_posix_timezone)
            })
            .transpose()?
    } else {
        None
    };
    Ok(TimeZone {
        transitions,
        default_offset,
        future,
    })
}

impl PosixTimeZone {
    fn offset_at(&self, instant: OffsetDateTime) -> Result<i32, String> {
        let Some((daylight_offset, start, end)) = self.daylight else {
            return Ok(self.standard_offset);
        };
        let year = instant.year();
        let start = start.transition(year, self.standard_offset)?;
        let end = end.transition(year, daylight_offset)?;
        let daylight = if start < end {
            instant >= start && instant < end
        } else {
            instant >= start || instant < end
        };
        Ok(if daylight {
            daylight_offset
        } else {
            self.standard_offset
        })
    }
}

impl PosixRule {
    fn transition(self, year: i32, prior_offset: i32) -> Result<OffsetDateTime, String> {
        let (date, seconds) = match self {
            Self::MonthWeekday {
                month,
                week,
                weekday,
                seconds,
            } => {
                let month = Month::try_from(month).map_err(|_| "invalid POSIX month")?;
                let first = Date::from_calendar_date(year, month, 1)
                    .map_err(|_| "invalid POSIX transition date")?;
                let first_weekday = posix_weekday(first.weekday());
                let mut day = 1
                    + (7 + i16::from(weekday) - i16::from(first_weekday)) % 7
                    + 7 * i16::from(week.saturating_sub(1));
                let last = i16::from(days_in_month(year, month));
                if week == 5 && day > last {
                    day -= 7;
                }
                let date = Date::from_calendar_date(year, month, day as u8)
                    .map_err(|_| "invalid POSIX transition date")?;
                (date, seconds)
            }
            Self::JulianNoLeap { day, seconds } => {
                let leap = Date::from_calendar_date(year, Month::December, 31)
                    .map_err(|_| "invalid POSIX transition year")?
                    .ordinal()
                    == 366;
                let ordinal = day + u16::from(leap && day >= 60);
                (
                    Date::from_ordinal_date(year, ordinal)
                        .map_err(|_| "invalid POSIX Julian transition")?,
                    seconds,
                )
            }
            Self::Julian { day, seconds } => (
                Date::from_ordinal_date(year, day + 1)
                    .map_err(|_| "invalid POSIX Julian transition")?,
                seconds,
            ),
        };
        let local =
            PrimitiveDateTime::new(date, Time::MIDNIGHT) + Duration::seconds(i64::from(seconds));
        let offset = UtcOffset::from_whole_seconds(prior_offset)
            .map_err(|_| "invalid POSIX timezone offset")?;
        Ok(local.assume_offset(offset).to_offset(UtcOffset::UTC))
    }
}

fn posix_weekday(day: Weekday) -> u8 {
    match day {
        Weekday::Sunday => 0,
        Weekday::Monday => 1,
        Weekday::Tuesday => 2,
        Weekday::Wednesday => 3,
        Weekday::Thursday => 4,
        Weekday::Friday => 5,
        Weekday::Saturday => 6,
    }
}

fn parse_posix_timezone(value: &str) -> Result<PosixTimeZone, String> {
    let mut cursor = 0;
    parse_posix_name(value, &mut cursor)?;
    let standard_offset = -parse_posix_hms(value, &mut cursor)?;
    if cursor == value.len() {
        return Ok(PosixTimeZone {
            standard_offset,
            daylight: None,
        });
    }
    parse_posix_name(value, &mut cursor)?;
    let daylight_offset = if value.as_bytes().get(cursor) == Some(&b',') {
        standard_offset + 3600
    } else {
        -parse_posix_hms(value, &mut cursor)?
    };
    if value.as_bytes().get(cursor) != Some(&b',') {
        return Err("POSIX daylight rules are required".into());
    }
    cursor += 1;
    let separator = value[cursor..]
        .find(',')
        .map(|index| cursor + index)
        .ok_or_else(|| "POSIX daylight end rule is required".to_string())?;
    let start = parse_posix_rule(&value[cursor..separator])?;
    let end = parse_posix_rule(&value[separator + 1..])?;
    Ok(PosixTimeZone {
        standard_offset,
        daylight: Some((daylight_offset, start, end)),
    })
}

fn parse_posix_name(value: &str, cursor: &mut usize) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.get(*cursor) == Some(&b'<') {
        let end = value[*cursor + 1..]
            .find('>')
            .map(|index| *cursor + 1 + index)
            .ok_or_else(|| "unterminated POSIX timezone name".to_string())?;
        if end == *cursor + 1 {
            return Err("empty POSIX timezone name".into());
        }
        *cursor = end + 1;
        return Ok(());
    }
    let start = *cursor;
    while bytes.get(*cursor).is_some_and(u8::is_ascii_alphabetic) {
        *cursor += 1;
    }
    if *cursor - start < 3 {
        return Err("POSIX timezone names require at least three letters".into());
    }
    Ok(())
}

fn parse_posix_hms(value: &str, cursor: &mut usize) -> Result<i32, String> {
    let bytes = value.as_bytes();
    let sign = match bytes.get(*cursor) {
        Some(b'-') => {
            *cursor += 1;
            -1
        }
        Some(b'+') => {
            *cursor += 1;
            1
        }
        _ => 1,
    };
    let start = *cursor;
    while bytes.get(*cursor).is_some_and(u8::is_ascii_digit) {
        *cursor += 1;
    }
    if start == *cursor {
        return Err("POSIX timezone offset is required".into());
    }
    let hours: i32 = value[start..*cursor]
        .parse()
        .map_err(|_| "invalid POSIX timezone hour")?;
    let mut seconds = hours * 3600;
    for factor in [60, 1] {
        if bytes.get(*cursor) != Some(&b':') {
            break;
        }
        *cursor += 1;
        let start = *cursor;
        while bytes.get(*cursor).is_some_and(u8::is_ascii_digit) {
            *cursor += 1;
        }
        let part: i32 = value[start..*cursor]
            .parse()
            .map_err(|_| "invalid POSIX timezone minute or second")?;
        if part > 59 {
            return Err("POSIX timezone minute or second is outside its range".into());
        }
        seconds += part * factor;
    }
    Ok(sign * seconds)
}

fn parse_posix_rule(value: &str) -> Result<PosixRule, String> {
    let (rule, time) = value.split_once('/').unwrap_or((value, "2"));
    let mut cursor = 0;
    let seconds = parse_posix_hms(time, &mut cursor)?;
    if cursor != time.len() {
        return Err("invalid POSIX transition time".into());
    }
    if let Some(rule) = rule.strip_prefix('M') {
        let values = rule
            .split('.')
            .map(str::parse::<u8>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "invalid POSIX month transition rule")?;
        if values.len() != 3
            || !(1..=12).contains(&values[0])
            || !(1..=5).contains(&values[1])
            || values[2] > 6
        {
            return Err("invalid POSIX month transition rule".into());
        }
        return Ok(PosixRule::MonthWeekday {
            month: values[0],
            week: values[1],
            weekday: values[2],
            seconds,
        });
    }
    if let Some(day) = rule.strip_prefix('J') {
        let day = day
            .parse::<u16>()
            .map_err(|_| "invalid POSIX Julian transition")?;
        if !(1..=365).contains(&day) {
            return Err("invalid POSIX Julian transition".into());
        }
        return Ok(PosixRule::JulianNoLeap { day, seconds });
    }
    let day = rule
        .parse::<u16>()
        .map_err(|_| "invalid POSIX Julian transition")?;
    if day > 365 {
        return Err("invalid POSIX Julian transition".into());
    }
    Ok(PosixRule::Julian { day, seconds })
}

fn tzif_counts(
    bytes: &[u8],
    header: usize,
) -> Result<(usize, usize, usize, usize, usize, usize), String> {
    if header + 44 > bytes.len() || &bytes[header..header + 4] != b"TZif" {
        return Err("truncated TZif header".into());
    }
    Ok((
        read_u32(bytes, header + 20)? as usize,
        read_u32(bytes, header + 24)? as usize,
        read_u32(bytes, header + 28)? as usize,
        read_u32(bytes, header + 32)? as usize,
        read_u32(bytes, header + 36)? as usize,
        read_u32(bytes, header + 40)? as usize,
    ))
}

fn tzif_block_len(
    counts: (usize, usize, usize, usize, usize, usize),
    time_size: usize,
) -> Result<usize, String> {
    counts
        .3
        .checked_mul(time_size + 1)
        .and_then(|length| length.checked_add(counts.4 * 6))
        .and_then(|length| length.checked_add(counts.5))
        .and_then(|length| length.checked_add(counts.2 * (time_size + 4)))
        .and_then(|length| length.checked_add(counts.1))
        .and_then(|length| length.checked_add(counts.0))
        .ok_or_else(|| "TZif block is too large".to_string())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "truncated TZif integer".to_string())?
        .try_into()
        .map_err(|_| "truncated TZif integer".to_string())?;
    Ok(u32::from_be_bytes(value))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, String> {
    Ok(read_u32(bytes, offset)? as i32)
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, String> {
    let value: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| "truncated TZif integer".to_string())?
        .try_into()
        .map_err(|_| "truncated TZif integer".to_string())?;
    Ok(i64::from_be_bytes(value))
}

pub fn timezone_offset(timezone: &str, instant: OffsetDateTime) -> Result<UtcOffset, String> {
    TimeZone::load(timezone)?.offset_at(instant)
}

pub fn next_after(
    expr: &ScheduleExpr,
    after: OffsetDateTime,
    timezone: &str,
) -> Result<Option<OffsetDateTime>, String> {
    next_after_anchored(expr, after, timezone, after)
}

pub fn next_after_anchored(
    expr: &ScheduleExpr,
    after: OffsetDateTime,
    timezone: &str,
    rate_anchor: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, String> {
    let timezone = TimeZone::load(timezone)?;
    match expr {
        ScheduleExpr::At(local) => {
            let instant = timezone.local_to_utc(*local)?;
            Ok((instant > after).then_some(instant))
        }
        ScheduleExpr::Rate(duration) => {
            if after < rate_anchor {
                return Ok(Some(rate_anchor));
            }
            let interval = duration.whole_seconds();
            if interval <= 0 {
                return Err("rate duration must be positive".into());
            }
            let elapsed = (after - rate_anchor).whole_seconds();
            let steps = elapsed.div_euclid(interval).saturating_add(1);
            let seconds = interval
                .checked_mul(steps)
                .ok_or_else(|| "next rate occurrence is outside the supported range".to_string())?;
            Ok(rate_anchor.checked_add(Duration::seconds(seconds)))
        }
        ScheduleExpr::Cron(cron) => {
            let mut candidate = after
                .replace_second(0)
                .map_err(|_| "invalid time")?
                .replace_nanosecond(0)
                .map_err(|_| "invalid time")?
                + Duration::minutes(1);
            for _ in 0..(60 * 24 * 366 * 8) {
                let offset = timezone.offset_at(candidate)?;
                let local = PrimitiveDateTime::new(
                    candidate.to_offset(offset).date(),
                    candidate.to_offset(offset).time(),
                );
                if cron.matches(local) {
                    return Ok(Some(candidate));
                }
                candidate += Duration::minutes(1);
            }
            Ok(None)
        }
    }
}

pub async fn sleep_until(clock: &dyn Clock, due: OffsetDateTime) {
    clock.sleep_until(due).await;
}

pub fn system_time(value: SystemTime) -> OffsetDateTime {
    let duration = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rate_at_and_six_field_cron() {
        assert_eq!(
            parse("rate(1 minute)", true).unwrap(),
            ScheduleExpr::Rate(Duration::minutes(1))
        );
        assert!(matches!(
            parse("at(2025-01-02T03:04:05)", true),
            Ok(ScheduleExpr::At(_))
        ));
        assert!(matches!(
            parse("cron(0 12 ? * MON-FRI *)", true),
            Ok(ScheduleExpr::Cron(_))
        ));
        assert!(parse("rate(1 minutes)", true).is_err());
        assert!(parse("cron(0 0 * * * *)", true).is_err());
        assert!(parse("cron(0 0 ? * ? *)", true).is_err());
        assert!(parse("cron(0 0 ? MON MON *)", true).is_err());
        assert!(parse("cron(0 0 L * ? *)", true).is_ok());
        assert!(parse("cron(0 0 ? * MON#2 *)", true).is_ok());
    }

    #[test]
    fn non_utc_at_is_converted_to_utc() {
        let expr = parse("at(2025-01-15T09:00:00)", true).unwrap();
        let before = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let due = next_after(&expr, before, "America/New_York")
            .unwrap()
            .unwrap();
        assert_eq!(due.hour(), 14);
    }

    #[test]
    fn arbitrary_iana_timezone_is_loaded_from_tzdb() {
        let expr = parse("at(2025-01-15T09:00:00)", true).unwrap();
        let before = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let due = next_after(&expr, before, "Australia/Adelaide")
            .unwrap()
            .unwrap();
        assert_eq!((due.hour(), due.minute()), (22, 30));
    }

    #[test]
    fn posix_footer_keeps_future_dst_rules() {
        let winter = Date::from_calendar_date(2100, Month::January, 15)
            .unwrap()
            .with_hms(12, 0, 0)
            .unwrap()
            .assume_utc();
        let summer = Date::from_calendar_date(2100, Month::July, 15)
            .unwrap()
            .with_hms(12, 0, 0)
            .unwrap()
            .assume_utc();
        assert_eq!(
            timezone_offset("America/New_York", winter)
                .unwrap()
                .whole_hours(),
            -5
        );
        assert_eq!(
            timezone_offset("America/New_York", summer)
                .unwrap()
                .whole_hours(),
            -4
        );
    }

    #[test]
    fn cron_finds_expected_utc_minute() {
        let expr = parse("cron(30 10 ? * * 2025)", true).unwrap();
        let after = PrimitiveDateTime::new(
            Date::from_calendar_date(2025, Month::January, 1).unwrap(),
            Time::from_hms(10, 29, 0).unwrap(),
        )
        .assume_utc();
        let due = next_after(&expr, after, "UTC").unwrap().unwrap();
        assert_eq!((due.hour(), due.minute()), (10, 30));
    }

    #[test]
    fn rate_is_anchored_and_jumps_directly_to_a_future_start() {
        let expr = parse("rate(5 minutes)", true).unwrap();
        let anchor = OffsetDateTime::from_unix_timestamp(10_000).unwrap();
        let before = anchor - Duration::days(365);
        assert_eq!(
            next_after_anchored(&expr, before, "UTC", anchor).unwrap(),
            Some(anchor)
        );
        assert_eq!(
            next_after_anchored(&expr, anchor + Duration::minutes(12), "UTC", anchor).unwrap(),
            Some(anchor + Duration::minutes(15))
        );
    }

    #[tokio::test]
    async fn clock_controls_sleep_for_deterministic_workers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct ImmediateClock {
            now: OffsetDateTime,
            sleeps: AtomicUsize,
        }
        impl Clock for ImmediateClock {
            fn now(&self) -> OffsetDateTime {
                self.now
            }

            fn sleep_until<'a>(
                &'a self,
                _due: OffsetDateTime,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
                Box::pin(async move {
                    self.sleeps.fetch_add(1, Ordering::SeqCst);
                })
            }
        }

        let clock = ImmediateClock {
            now: OffsetDateTime::UNIX_EPOCH,
            sleeps: AtomicUsize::new(0),
        };
        sleep_until(&clock, OffsetDateTime::UNIX_EPOCH + Duration::days(1)).await;
        assert_eq!(clock.sleeps.load(Ordering::SeqCst), 1);
    }
}
