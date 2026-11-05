// Package policy encodes CA/Browser Forum ballot SC-081: the maximum lifetime of
// publicly trusted TLS certificates, by the date they are issued.
package policy

import "time"

// Step is a maximum lifetime that applies to certificates issued from From onwards.
type Step struct {
	From    time.Time
	MaxDays int
}

var steps = []Step{
	{From: time.Time{}, MaxDays: 398},
	{From: date(2026, time.March, 15), MaxDays: 200},
	{From: date(2027, time.March, 15), MaxDays: 100},
	{From: date(2029, time.March, 15), MaxDays: 47},
}

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// Current is the step in force at t.
func Current(t time.Time) Step {
	current := steps[0]
	for _, s := range steps[1:] {
		if !t.Before(s.From) {
			current = s
		}
	}
	return current
}

// Next is the first step that starts after t, if there is one.
func Next(t time.Time) (Step, bool) {
	for _, s := range steps {
		if s.From.After(t) {
			return s, true
		}
	}
	return Step{}, false
}

// Outlook is the step in force at t followed by every later step.
func Outlook(t time.Time) []Step {
	out := []Step{Current(t)}
	for _, s := range steps {
		if s.From.After(t) {
			out = append(out, s)
		}
	}
	return out
}

// RenewalsPerYear is how often a certificate must be replaced when it can live at most maxDays.
func RenewalsPerYear(maxDays int) int {
	return (365 + maxDays - 1) / maxDays
}
