package policy

import (
	"testing"
	"time"
)

func TestCurrent(t *testing.T) {
	tests := []struct {
		at   time.Time
		want int
	}{
		{date(2025, time.June, 1), 398},
		{date(2026, time.March, 14), 398},
		{date(2026, time.March, 15), 200},
		{date(2026, time.November, 1), 200},
		{date(2027, time.March, 15), 100},
		{date(2029, time.March, 15), 47},
		{date(2035, time.January, 1), 47},
	}
	for _, tt := range tests {
		if got := Current(tt.at).MaxDays; got != tt.want {
			t.Errorf("Current(%s) = %d days, want %d", tt.at.Format(time.DateOnly), got, tt.want)
		}
	}
}

func TestNext(t *testing.T) {
	next, ok := Next(date(2026, time.November, 1))
	if !ok || next.MaxDays != 100 || !next.From.Equal(date(2027, time.March, 15)) {
		t.Errorf("Next(2026-11-01) = %+v, %v; want 100 days from 2027-03-15", next, ok)
	}
	if _, ok := Next(date(2030, time.January, 1)); ok {
		t.Error("Next(2030-01-01) found a step, want none")
	}
}

func TestOutlook(t *testing.T) {
	var got []int
	for _, s := range Outlook(date(2026, time.November, 1)) {
		got = append(got, s.MaxDays)
	}
	if len(got) != 3 || got[0] != 200 || got[1] != 100 || got[2] != 47 {
		t.Errorf("Outlook(2026-11-01) = %v, want [200 100 47]", got)
	}
}

func TestRenewalsPerYear(t *testing.T) {
	for days, want := range map[int]int{398: 1, 200: 2, 100: 4, 47: 8} {
		if got := RenewalsPerYear(days); got != want {
			t.Errorf("RenewalsPerYear(%d) = %d, want %d", days, got, want)
		}
	}
}
