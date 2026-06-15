package ink

import (
	"regexp"
	"strconv"
	"time"
)

// maxTimestampLength bounds work before the parser runs and matches the cap the
// reference applies. A full RFC 3339 timestamp with sub-second precision and an
// offset fits well under this.
const maxTimestampLength = 64

// rfc3339DateTime captures the components of a full RFC 3339 date-time: a date,
// an uppercase T, a time with seconds, optional dot-separated fractional
// seconds, and either Z or a numeric ±HH:MM offset. A comma fractional
// separator (which Go's time.Parse would otherwise accept) is not matched.
var rfc3339DateTime = regexp.MustCompile(
	`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|([+-])(\d{2}):(\d{2}))$`)

func daysInMonth(year, month int) int {
	if month == 2 {
		leap := (year%4 == 0 && year%100 != 0) || year%400 == 0
		if leap {
			return 29
		}
		return 28
	}
	return []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[month-1]
}

// ParseInkTimestampMs parses a strict RFC 3339 date-time to whole milliseconds
// since the Unix epoch. The second return is false when the value is not a
// well-formed, in-range RFC 3339 timestamp. INK timestamps are compared across
// implementations, so the grammar (a full date-time with a T and a Z or numeric
// offset; no date-only, zone-less, space-separated, or comma-fraction forms),
// the calendar-range validation, and the precision (sub-millisecond floored to
// the containing millisecond) all match the reference exactly. Components are
// validated explicitly and the instant is computed directly so neither Go's
// time.Parse leniency nor any normalization can let the two implementations
// disagree.
func ParseInkTimestampMs(value string) (int64, bool) {
	if len(value) == 0 || len(value) > maxTimestampLength {
		return 0, false
	}
	m := rfc3339DateTime.FindStringSubmatch(value)
	if m == nil {
		return 0, false
	}
	year, _ := strconv.Atoi(m[1])
	month, _ := strconv.Atoi(m[2])
	day, _ := strconv.Atoi(m[3])
	hour, _ := strconv.Atoi(m[4])
	minute, _ := strconv.Atoi(m[5])
	second, _ := strconv.Atoi(m[6])

	if month < 1 || month > 12 {
		return 0, false
	}
	if day < 1 || day > daysInMonth(year, month) {
		return 0, false
	}
	if hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}
	offsetMinutes := 0
	if m[8] != "" {
		oh, _ := strconv.Atoi(m[9])
		om, _ := strconv.Atoi(m[10])
		if oh > 23 || om > 59 {
			return 0, false
		}
		offsetMinutes = oh*60 + om
		if m[8] == "-" {
			offsetMinutes = -offsetMinutes
		}
	}

	// The first three fractional digits are the millisecond part (floor);
	// further digits are dropped. String slicing keeps this exact and identical
	// to the reference rather than relying on float rounding.
	fracMs := 0
	if frac := m[7]; frac != "" {
		fracMs, _ = strconv.Atoi((frac + "000")[:3])
	}

	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	return t.UnixMilli() + int64(fracMs) - int64(offsetMinutes)*60_000, true
}
