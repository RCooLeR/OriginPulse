package jobs

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSchedulerSummaryOmitsZeroTimestamps(t *testing.T) {
	encoded, err := json.Marshal(SchedulerSummary{})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"last_cycle_started_at", "last_cycle_finished_at", "latest_pipeline_at"} {
		if bytes.Contains(encoded, []byte(`"`+field+`"`)) {
			t.Fatalf("zero %s was serialized: %s", field, encoded)
		}
	}
}
