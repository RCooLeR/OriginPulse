package investigation

import (
	"testing"
	"time"
)

func TestTimelineBucketSecondsCoversConfiguredRanges(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     int
	}{
		{name: "thirty minutes", duration: 30 * time.Minute, want: 60},
		{name: "three hours", duration: 3 * time.Hour, want: 60},
		{name: "seven days", duration: 7 * 24 * time.Hour, want: 60 * 60},
		{name: "ninety days", duration: 90 * 24 * time.Hour, want: 24 * 60 * 60},
		{name: "one year", duration: 365 * 24 * time.Hour, want: 3 * 24 * 60 * 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := timelineBucketSeconds(tt.duration); got != tt.want {
				t.Fatalf("timelineBucketSeconds(%s) = %d, want %d", tt.duration, got, tt.want)
			}
		})
	}
}
