package ipintel

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestOptionalIntelTimesUseOmitZero(t *testing.T) {
	tests := []struct {
		name   string
		value  any
		fields []string
	}{
		{name: "refreshed", value: RefreshedIP{}, fields: []string{"provider_refreshed_at"}},
		{name: "traffic", value: TrafficSummary{}, fields: []string{"first_seen", "last_seen"}},
		{name: "stored", value: StoredIntel{}, fields: []string{"provider_refreshed_at", "refreshed_at"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range tt.fields {
				if bytes.Contains(encoded, []byte(`"`+field+`"`)) {
					t.Fatalf("zero %s was serialized: %s", field, encoded)
				}
			}
		})
	}
}
