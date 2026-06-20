package archivecoverage

import (
	"testing"
	"time"
)

func TestOldWindowRequiresImportOnlyBeforeHotCutoff(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	hotCutoff := now.Add(-90 * 24 * time.Hour)

	start, end, required := oldWindow(hotCutoff.Add(-24*time.Hour), now, hotCutoff)
	if !required {
		t.Fatal("old window should require archive import when range starts before hot cutoff")
	}
	if !start.Equal(hotCutoff.Add(-24*time.Hour)) || !end.Equal(hotCutoff) {
		t.Fatalf("old window = %s..%s, want %s..%s", start, end, hotCutoff.Add(-24*time.Hour), hotCutoff)
	}

	_, _, required = oldWindow(hotCutoff, now, hotCutoff)
	if required {
		t.Fatal("range starting at hot cutoff should not require archive import")
	}
}

func TestSelectArchivesPrefersCoarserCoverageAndFillsGaps(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(14 * 24 * time.Hour)
	day := 24 * time.Hour
	archives := []Archive{
		{ID: "daily-1", Granularity: "daily", RangeStart: start, RangeEnd: start.Add(day), CompressedBytes: 10},
		{ID: "daily-2", Granularity: "daily", RangeStart: start.Add(day), RangeEnd: start.Add(2 * day), CompressedBytes: 10},
		{ID: "weekly-1", Granularity: "weekly", RangeStart: start, RangeEnd: start.Add(7 * day), CompressedBytes: 50},
		{ID: "daily-gap", Granularity: "daily", RangeStart: start.Add(7 * day), RangeEnd: start.Add(8 * day), CompressedBytes: 10},
		{ID: "outside", Granularity: "weekly", RangeStart: end, RangeEnd: end.Add(7 * day), CompressedBytes: 50},
	}

	selected := selectArchives(archives, start, end)
	if len(selected) != 2 {
		t.Fatalf("selected %d archives, want 2: %#v", len(selected), selected)
	}
	if selected[0].ID != "weekly-1" || selected[1].ID != "daily-gap" {
		t.Fatalf("selected archive IDs = %q, %q; want weekly-1, daily-gap", selected[0].ID, selected[1].ID)
	}

	intervals := make([]interval, 0, len(selected))
	for _, item := range selected {
		intervals = append(intervals, interval{start: item.RangeStart, end: item.RangeEnd})
	}
	if got, want := coveredSeconds(intervals, start, end), int64((8 * day).Seconds()); got != want {
		t.Fatalf("covered seconds = %d, want %d", got, want)
	}
}

func TestCoveredSecondsMergesOverlappingIntervals(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(6 * time.Hour)
	items := []interval{
		{start: start.Add(-time.Hour), end: start.Add(2 * time.Hour)},
		{start: start.Add(time.Hour), end: start.Add(4 * time.Hour)},
		{start: start.Add(5 * time.Hour), end: start.Add(8 * time.Hour)},
	}

	got := coveredSeconds(items, start, end)
	want := int64((5 * time.Hour).Seconds())
	if got != want {
		t.Fatalf("covered seconds = %d, want %d", got, want)
	}
}
