package analytics

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestOverviewLatestEventAtUsesOmitZero(t *testing.T) {
	encoded, err := json.Marshal(Overview{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"latest_event_at"`)) {
		t.Fatalf("zero latest_event_at was serialized: %s", encoded)
	}

	encoded, err = json.Marshal(Overview{LatestEventAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"latest_event_at"`)) {
		t.Fatalf("non-zero latest_event_at was omitted: %s", encoded)
	}
}
