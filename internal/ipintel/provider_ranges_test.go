package ipintel

import (
	"reflect"
	"testing"
)

func TestParseProviderJSONRanges(t *testing.T) {
	body := []byte(`{
		"prefixes": [
			{"ipv4Prefix": "66.249.72.32/27"},
			{"ipv6Prefix": "2001:4860:4801:10::/64"},
			{"ignored": "not-a-range"}
		]
	}`)
	got := parseProviderJSONRanges(body)
	want := []string{"2001:4860:4801:10::/64", "66.249.72.32/27"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseProviderJSONRanges() = %#v, want %#v", got, want)
	}
}

func TestParseProviderTextRanges(t *testing.T) {
	body := []byte(`Allow 50.19.247.197 and 52.45.51.99/32 for AddSearchBot.`)
	got := parseProviderTextRanges(body)
	want := []string{"50.19.247.197/32", "52.45.51.99/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseProviderTextRanges() = %#v, want %#v", got, want)
	}
}
