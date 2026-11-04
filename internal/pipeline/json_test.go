package pipeline

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPipelineTimesUseOmitZero(t *testing.T) {
	for name, value := range map[string]any{
		"options": Options{},
		"result":  Result{},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(`"from"`)) || bytes.Contains(encoded, []byte(`"to"`)) {
				t.Fatalf("zero pipeline timestamps were serialized: %s", encoded)
			}
		})
	}
}
