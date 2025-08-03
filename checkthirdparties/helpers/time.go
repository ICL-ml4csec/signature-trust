package helpers

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseTimePeriod converts human-readable time periods to time.Time
func ParseTimePeriod(period string) (*time.Time, error) {
	if period == "" {
		return nil, nil
	}

	period = strings.ToLower(strings.TrimSpace(period))
	now := time.Now()

	switch period {
	// Months
	case "1 month", "1month", "1m":
		result := now.AddDate(0, -1, 0)
		return &result, nil
	case "2 months", "2months", "2m":
		result := now.AddDate(0, -2, 0)
		return &result, nil
	case "3 months", "3months", "3m":
		result := now.AddDate(0, -3, 0)
		return &result, nil
	case "6 months", "6months", "6m":
		result := now.AddDate(0, -6, 0)
		return &result, nil

	// Years
	case "1 year", "1year", "1y":
		result := now.AddDate(-1, 0, 0)
		return &result, nil
	case "2 years", "2years", "2y":
		result := now.AddDate(-2, 0, 0)
		return &result, nil
	case "3 years", "3years", "3y":
		result := now.AddDate(-3, 0, 0)
		return &result, nil
	case "5 years", "5years", "5y":
		result := now.AddDate(-5, 0, 0)
		return &result, nil

	// Weeks
	case "1 week", "1week", "1w":
		result := now.AddDate(0, 0, -7)
		return &result, nil
	case "2 weeks", "2weeks", "2w":
		result := now.AddDate(0, 0, -14)
		return &result, nil
	case "4 weeks", "4weeks", "4w":
		result := now.AddDate(0, 0, -28)
		return &result, nil

	// Days
	case "1 day", "1day", "1d":
		result := now.AddDate(0, 0, -1)
		return &result, nil
	case "7 days", "7days", "7d":
		result := now.AddDate(0, 0, -7)
		return &result, nil
	case "30 days", "30days", "30d":
		result := now.AddDate(0, 0, -30)
		return &result, nil
	case "90 days", "90days", "90d":
		result := now.AddDate(0, 0, -90)
		return &result, nil

	default:
		return parseFlexibleTimePeriod(period)
	}
}

// parseFlexibleTimePeriod handles formats like "2 months", "5 years", "10 days"
func parseFlexibleTimePeriod(period string) (*time.Time, error) {
	parts := strings.Fields(period)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid time period format: %s (expected format: '3 months', '1 year', etc.)", period)
	}

	numStr := parts[0]
	unit := strings.ToLower(parts[1])

	unit = strings.TrimSuffix(unit, "s")

	num, err := strconv.Atoi(numStr)
	if err != nil {
		return nil, fmt.Errorf("invalid number in time period: %s", numStr)
	}

	now := time.Now()

	switch unit {
	case "day", "d":
		result := now.AddDate(0, 0, -num)
		return &result, nil
	case "week", "w":
		result := now.AddDate(0, 0, -num*7)
		return &result, nil
	case "month", "m":
		result := now.AddDate(0, -num, 0)
		return &result, nil
	case "year", "y":
		result := now.AddDate(-num, 0, 0)
		return &result, nil
	default:
		return nil, fmt.Errorf("unsupported time unit: %s (supported: day, week, month, year)", unit)
	}
}

// FormatTimePeriod converts a time.Time back to a human-readable period
func FormatTimePeriod(cutoff *time.Time) string {
	if cutoff == nil {
		return "no limit"
	}

	duration := time.Since(*cutoff)
	days := int(duration.Hours() / 24)

	switch {
	case days < 7:
		return fmt.Sprintf("%d days", days)
	case days < 30:
		weeks := days / 7
		return fmt.Sprintf("%d weeks", weeks)
	case days < 365:
		months := days / 30
		return fmt.Sprintf("~%d months", months)
	default:
		years := days / 365
		return fmt.Sprintf("~%d years", years)
	}
}

// ValidateTimePeriod checks if a time period string is valid
func ValidateTimePeriod(period string) error {
	_, err := ParseTimePeriod(period)
	return err
}

// GetSupportedTimePeriods returns a list of supported time period formats
func GetSupportedTimePeriods() []string {
	return []string{
		"1 day, 7 days, 30 days, 90 days",
		"1 week, 2 weeks, 4 weeks",
		"1 month, 2 months, 3 months, 6 months",
		"1 year, 2 years, 3 years, 5 years",
		"Flexible format: '5 days', '10 months', '2 years'",
		"Short format: 1d, 1w, 1m, 1y",
	}
}
