package reports

import (
	"strings"
	"testing"
	"time"

	"originpulse/internal/alerts"
)

func TestBuildPromptEvidenceNormalizesReportSize(t *testing.T) {
	longText := strings.Repeat("segment-", 80)
	points := make([]ReportDatum, 40)
	for i := range points {
		points[i] = ReportDatum{
			Label:     longText,
			Timestamp: time.Unix(int64(i*60), 0).UTC(),
			Value:     float64(i),
			Meta:      longText,
		}
	}
	drillItems := make([]DrilldownItem, 20)
	for i := range drillItems {
		drillItems[i] = DrilldownItem{
			Kind:       "path",
			Label:      longText,
			Path:       "/" + longText,
			Query:      longText,
			Meta:       longText,
			Requests:   int64(100 + i),
			Status4xx:  int64(i),
			FirstSeen:  time.Unix(0, 0).UTC(),
			LastSeen:   time.Unix(int64(i*60), 0).UTC(),
			ActorValue: longText,
		}
	}
	openAlerts := make([]alerts.Alert, 20)
	for i := range openAlerts {
		openAlerts[i] = alerts.Alert{
			ID:          "alert-" + longText,
			RuleKey:     "ip_4xx_scan",
			Title:       longText,
			Severity:    "high",
			Status:      "open",
			ActorType:   "ip",
			ActorValue:  longText,
			Summary:     longText,
			FirstSeenAt: time.Unix(0, 0).UTC(),
			LastSeenAt:  time.Unix(int64(i*60), 0).UTC(),
		}
	}

	evidence := buildPromptEvidence(
		map[string]any{"range": "24h", "site_id": "example", "generated_at": time.Unix(0, 0).UTC(), "open_alerts": openAlerts},
		&ReportSummary{Range: "24h", Requests: 1000000},
		[]ReportChart{{Key: "traffic_timeline", Title: longText, Kind: "line", Unit: "requests", Data: points}},
		[]Drilldown{{Key: "top_paths", Title: longText, Items: drillItems}},
	)

	charts, ok := evidence["charts"].([]promptChart)
	if !ok || len(charts) != 1 {
		t.Fatalf("charts = %#v, want one prompt chart", evidence["charts"])
	}
	if got := len(charts[0].Data); got != promptChartPointsLimit {
		t.Fatalf("chart points = %d, want %d", got, promptChartPointsLimit)
	}
	if charts[0].Data[0].Timestamp != points[0].Timestamp || charts[0].Data[len(charts[0].Data)-1].Timestamp != points[len(points)-1].Timestamp {
		t.Fatalf("timeline was not sampled across full range")
	}
	if len([]rune(charts[0].Data[0].Label)) > promptStringLimit {
		t.Fatalf("chart label was not truncated")
	}

	drilldowns, ok := evidence["drilldowns"].([]promptDrilldown)
	if !ok || len(drilldowns) != 1 {
		t.Fatalf("drilldowns = %#v, want one prompt drilldown", evidence["drilldowns"])
	}
	if got := len(drilldowns[0].Items); got != promptDrilldownLimit {
		t.Fatalf("drilldown rows = %d, want %d", got, promptDrilldownLimit)
	}
	if len([]rune(drilldowns[0].Items[0].Path)) > promptStringLimit {
		t.Fatalf("drilldown path was not truncated")
	}

	alertRows, ok := evidence["open_alerts"].([]promptAlert)
	if !ok {
		t.Fatalf("open_alerts = %#v, want prompt alerts", evidence["open_alerts"])
	}
	if got := len(alertRows); got != promptAlertLimit {
		t.Fatalf("alert rows = %d, want %d", got, promptAlertLimit)
	}
	if len([]rune(alertRows[0].Summary)) > promptMetaLimit {
		t.Fatalf("alert summary was not truncated")
	}
}
