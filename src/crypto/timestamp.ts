/**
 * Strict RFC 3339 timestamp parsing for INK.
 *
 * INK timestamps (message `timestamp`, key `validFrom` / `validUntil`) are
 * compared across implementations, so they must have one grammar and one
 * precision everywhere. JavaScript's `Date.parse` accepts a much broader set
 * than RFC 3339 (date-only, missing zone, space instead of `T`) and silently
 * normalizes out-of-range calendar values (`2026-02-29` becomes March 1), which
 * would let a sender pass values an independent implementation rejects. This
 * parser accepts only a full, in-range RFC 3339 date-time and returns the
 * instant floored to whole milliseconds, the precision JavaScript `Date` is
 * native to, so the value matches a millisecond-normalized parse elsewhere.
 */

// Full RFC 3339 date-time with captured components: a date, an uppercase `T`, a
// time with seconds, optional dot-separated fractional seconds, and either `Z`
// or a numeric `±HH:MM` offset. A comma fractional separator is not accepted.
const RFC3339_DATETIME =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/** The maximum accepted timestamp length, matching the cap used elsewhere in
 *  INK. A full RFC 3339 timestamp with sub-second precision and an offset fits
 *  well under this; the cap bounds work before the regex and parser run. */
export const MAX_TIMESTAMP_LENGTH = 64;

// Called only after `month` is range-validated to 1..12.
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  return DAYS_IN_MONTH[month - 1] ?? 31;
}

/**
 * Parse a strict RFC 3339 date-time to whole milliseconds since the Unix epoch,
 * or return `null` if it is not a well-formed, in-range RFC 3339 timestamp.
 * Sub-millisecond precision is floored to the containing millisecond so the
 * value matches a millisecond-normalized parse in another implementation.
 */
export function parseInkTimestampMs(value: unknown): number | null {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_TIMESTAMP_LENGTH) {
    return null;
  }
  const m = RFC3339_DATETIME.exec(value);
  if (m === null) {
    return null;
  }
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  const frac = m[7];
  const offsetSign = m[8];
  const offsetHour = m[9];
  const offsetMinute = m[10];

  // Validate calendar components explicitly. Date.parse / Date.UTC would
  // silently roll an out-of-range value over to the next valid instant.
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > daysInMonth(year, month)) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;
  let offsetMinutes = 0;
  if (offsetSign !== undefined) {
    const oh = Number(offsetHour);
    const om = Number(offsetMinute);
    if (oh > 23 || om > 59) return null;
    offsetMinutes = (offsetSign === "+" ? 1 : -1) * (oh * 60 + om);
  }

  // Compute the instant directly from validated components so no normalization
  // can occur. The first three fractional digits are the millisecond part
  // (floor); further digits are dropped. String slicing keeps this exact and
  // identical across implementations rather than relying on float rounding.
  const fracMs = frac ? Number(`${frac}000`.slice(0, 3)) : 0;
  // setUTCFullYear, not Date.UTC(year, ...), because Date.UTC maps a year of
  // 0..99 to 1900..1999, which would disagree with an implementation that uses
  // the literal year for a four-digit year below 0100.
  const d = new Date(Date.UTC(2000, month - 1, day, hour, minute, second));
  d.setUTCFullYear(year);
  const utcMs = d.getTime() + fracMs - offsetMinutes * 60_000;
  if (!Number.isFinite(utcMs)) {
    return null;
  }
  return utcMs;
}

/** Whether a value is a well-formed strict RFC 3339 INK timestamp. */
export function isInkTimestamp(value: unknown): boolean {
  return parseInkTimestampMs(value) !== null;
}
