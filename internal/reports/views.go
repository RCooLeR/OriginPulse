package reports

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"originpulse/internal/accessanalysis"
	"originpulse/internal/alerts"
	"originpulse/internal/analytics"
	"originpulse/internal/investigation"
)

type ReportSummary struct {
	Range                  string    `json:"range"`
	SiteID                 string    `json:"site_id,omitempty"`
	GeneratedAt            time.Time `json:"generated_at"`
	Requests               int64     `json:"requests"`
	UniqueIPs              int64     `json:"unique_ips"`
	UniqueUserAgents       int64     `json:"unique_user_agents"`
	Status4xx              int64     `json:"status_4xx"`
	Status5xx              int64     `json:"status_5xx"`
	Status4xxRate          float64   `json:"status_4xx_rate"`
	Status5xxRate          float64   `json:"status_5xx_rate"`
	SlowRequests           int64     `json:"slow_requests"`
	SlowRequestsRate       float64   `json:"slow_requests_rate"`
	BytesSent              int64     `json:"bytes_sent"`
	IssueCount             int       `json:"issue_count"`
	CriticalIssues         int       `json:"critical_issues"`
	HighIssues             int       `json:"high_issues"`
	MediumIssues           int       `json:"medium_issues"`
	LowIssues              int       `json:"low_issues"`
	OpenAlerts             int       `json:"open_alerts"`
	AdminProbeRows         int       `json:"admin_probe_rows"`
	AdminProbeRequests     int64     `json:"admin_probe_requests"`
	InjectionProbeRows     int       `json:"injection_probe_rows"`
	InjectionProbeRequests int64     `json:"injection_probe_requests"`
	TorSourceRows          int       `json:"tor_source_rows"`
	TorRequests            int64     `json:"tor_requests"`
	TopSite                string    `json:"top_site,omitempty"`
	TopPath                string    `json:"top_path,omitempty"`
	TopSourceIP            string    `json:"top_source_ip,omitempty"`
	TopUserAgent           string    `json:"top_user_agent,omitempty"`
}

type ReportChart struct {
	Key   string        `json:"key"`
	Title string        `json:"title"`
	Kind  string        `json:"kind"`
	Unit  string        `json:"unit,omitempty"`
	Data  []ReportDatum `json:"data"`
}

type ReportDatum struct {
	Label     string    `json:"label"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Value     float64   `json:"value"`
	Secondary float64   `json:"secondary,omitempty"`
	Tertiary  float64   `json:"tertiary,omitempty"`
	Color     string    `json:"color,omitempty"`
	Meta      string    `json:"meta,omitempty"`
}

type Drilldown struct {
	Key   string          `json:"key"`
	Title string          `json:"title"`
	Items []DrilldownItem `json:"items"`
}

type DrilldownItem struct {
	Kind             string         `json:"kind"`
	Label            string         `json:"label"`
	Meta             string         `json:"meta,omitempty"`
	IP               string         `json:"ip,omitempty"`
	SiteID           string         `json:"site_id,omitempty"`
	Env              string         `json:"env,omitempty"`
	Method           string         `json:"method,omitempty"`
	Path             string         `json:"path,omitempty"`
	Query            string         `json:"query,omitempty"`
	Category         string         `json:"category,omitempty"`
	MatchReason      string         `json:"match_reason,omitempty"`
	Severity         string         `json:"severity,omitempty"`
	ActorType        string         `json:"actor_type,omitempty"`
	ActorValue       string         `json:"actor_value,omitempty"`
	Status           int            `json:"status,omitempty"`
	Score            int            `json:"score,omitempty"`
	RiskScore        int            `json:"risk_score,omitempty"`
	Requests         int64          `json:"requests,omitempty"`
	Events           int64          `json:"events,omitempty"`
	TotalIPHits      int64          `json:"total_ip_hits,omitempty"`
	Status4xx        int64          `json:"status_4xx,omitempty"`
	Status5xx        int64          `json:"status_5xx,omitempty"`
	BytesSent        int64          `json:"bytes_sent,omitempty"`
	AvgRequestTimeMS float64        `json:"avg_request_time_ms,omitempty"`
	P95RequestTimeMS float64        `json:"p95_request_time_ms,omitempty"`
	FirstSeen        time.Time      `json:"first_seen,omitempty"`
	LastSeen         time.Time      `json:"last_seen,omitempty"`
	Timestamp        time.Time      `json:"timestamp,omitempty"`
	VerifiedSource   bool           `json:"verified_source,omitempty"`
	KnownActor       string         `json:"known_actor,omitempty"`
	ReverseDNS       string         `json:"reverse_dns,omitempty"`
	Details          map[string]any `json:"details,omitempty"`
}

const (
	promptChartPointsLimit = 12
	promptDrilldownLimit   = 6
	promptAlertLimit       = 8
	promptStringLimit      = 180
	promptMetaLimit        = 240
)

type promptEvidenceBudget struct {
	ChartPoints        int `json:"chart_points"`
	DrilldownRows      int `json:"drilldown_rows"`
	OpenAlerts         int `json:"open_alerts"`
	MaxStringChars     int `json:"max_string_chars"`
	MaxMetaStringChars int `json:"max_meta_string_chars"`
}

type promptChart struct {
	Key   string        `json:"key"`
	Title string        `json:"title"`
	Kind  string        `json:"kind"`
	Unit  string        `json:"unit,omitempty"`
	Data  []ReportDatum `json:"data"`
}

type promptDrilldown struct {
	Key   string                `json:"key"`
	Title string                `json:"title"`
	Items []promptDrilldownItem `json:"items"`
}

type promptDrilldownItem struct {
	Kind             string    `json:"kind,omitempty"`
	Label            string    `json:"label,omitempty"`
	Meta             string    `json:"meta,omitempty"`
	IP               string    `json:"ip,omitempty"`
	SiteID           string    `json:"site_id,omitempty"`
	Env              string    `json:"env,omitempty"`
	Method           string    `json:"method,omitempty"`
	Path             string    `json:"path,omitempty"`
	Query            string    `json:"query,omitempty"`
	Category         string    `json:"category,omitempty"`
	Severity         string    `json:"severity,omitempty"`
	ActorType        string    `json:"actor_type,omitempty"`
	ActorValue       string    `json:"actor_value,omitempty"`
	Status           int       `json:"status,omitempty"`
	Score            int       `json:"score,omitempty"`
	RiskScore        int       `json:"risk_score,omitempty"`
	Requests         int64     `json:"requests,omitempty"`
	Events           int64     `json:"events,omitempty"`
	TotalIPHits      int64     `json:"total_ip_hits,omitempty"`
	Status4xx        int64     `json:"status_4xx,omitempty"`
	Status5xx        int64     `json:"status_5xx,omitempty"`
	BytesSent        int64     `json:"bytes_sent,omitempty"`
	AvgRequestTimeMS float64   `json:"avg_request_time_ms,omitempty"`
	P95RequestTimeMS float64   `json:"p95_request_time_ms,omitempty"`
	FirstSeen        time.Time `json:"first_seen,omitempty"`
	LastSeen         time.Time `json:"last_seen,omitempty"`
	Timestamp        time.Time `json:"timestamp,omitempty"`
	VerifiedSource   bool      `json:"verified_source,omitempty"`
	KnownActor       string    `json:"known_actor,omitempty"`
	ReverseDNS       string    `json:"reverse_dns,omitempty"`
}

type promptAlert struct {
	ID          string    `json:"id"`
	RuleKey     string    `json:"rule_key"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	SiteID      string    `json:"site_id,omitempty"`
	Env         string    `json:"env,omitempty"`
	ActorType   string    `json:"actor_type,omitempty"`
	ActorValue  string    `json:"actor_value,omitempty"`
	Score       int       `json:"score,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

func buildReportViews(input map[string]any) (*ReportSummary, []ReportChart, []Drilldown) {
	overview, _ := input["overview"].(analytics.Overview)
	analysis, _ := input["access_analysis"].(accessanalysis.Report)
	traffic, _ := input["traffic"].(investigation.Traffic)
	openAlerts, _ := input["open_alerts"].([]alerts.Alert)

	summary := &ReportSummary{
		Range:         stringFromInput(input, "range"),
		SiteID:        stringFromInput(input, "site_id"),
		GeneratedAt:   timeFromInput(input, "generated_at"),
		Requests:      analysis.Totals.Requests,
		UniqueIPs:     analysis.Totals.UniqueIPs,
		Status4xx:     analysis.Totals.Status4xx,
		Status5xx:     analysis.Totals.Status5xx,
		BytesSent:     analysis.Totals.BytesSent,
		OpenAlerts:    len(openAlerts),
		IssueCount:    len(analysis.Issues),
		TorSourceRows: len(analysis.TorSources),
	}
	if summary.GeneratedAt.IsZero() {
		summary.GeneratedAt = time.Now().UTC()
	}
	if summary.Requests == 0 {
		summary.Requests = overview.Requests
	}
	if summary.UniqueIPs == 0 {
		summary.UniqueIPs = overview.UniqueIPs
	}
	summary.UniqueUserAgents = analysis.Totals.UniqueUserAgents
	summary.Status4xxRate = analysis.Totals.Status4xxRate
	summary.Status5xxRate = analysis.Totals.Status5xxRate
	if summary.Status4xxRate == 0 {
		summary.Status4xxRate = overview.Status4xxRate
	}
	if summary.Status5xxRate == 0 {
		summary.Status5xxRate = overview.Status5xxRate
	}
	summary.SlowRequests = analysis.Totals.SlowRequests
	summary.SlowRequestsRate = analysis.Totals.SlowRequestsRate
	for _, issue := range analysis.Issues {
		switch strings.ToLower(issue.Severity) {
		case "critical":
			summary.CriticalIssues++
		case "high":
			summary.HighIssues++
		case "medium":
			summary.MediumIssues++
		default:
			summary.LowIssues++
		}
	}
	for _, probe := range analysis.AdminProbes {
		summary.AdminProbeRequests += probe.Requests
	}
	for _, probe := range analysis.InjectionProbes {
		summary.InjectionProbeRequests += probe.Requests
	}
	for _, source := range analysis.TorSources {
		summary.TorRequests += source.Requests
	}
	summary.AdminProbeRows = len(analysis.AdminProbes)
	summary.InjectionProbeRows = len(analysis.InjectionProbes)
	if len(analysis.Sites) > 0 {
		summary.TopSite = fmt.Sprintf("%s/%s", analysis.Sites[0].SiteID, analysis.Sites[0].Env)
	}
	if len(traffic.TopPaths) > 0 {
		summary.TopPath = traffic.TopPaths[0].Path
	}
	if len(analysis.SourceIPs) > 0 {
		summary.TopSourceIP = analysis.SourceIPs[0].IP
	}
	if len(analysis.UserAgents) > 0 {
		summary.TopUserAgent = analysis.UserAgents[0].Family
	}

	charts := []ReportChart{
		trafficTimelineChart(traffic.Timeline),
		statusMixChart(analysis.StatusBreakdown),
		siteTrafficChart(analysis.Sites),
		sourceIPChart(analysis.SourceIPs),
		userAgentClassChart(analysis.UserAgents),
		securitySignalsChart(analysis, summary),
		slowPathChart(analysis.SlowPaths),
	}
	drilldowns := []Drilldown{
		{Key: "source_ips", Title: "Source IPs", Items: sourceIPDrilldown(analysis.SourceIPs, 30)},
		{Key: "issues", Title: "Detected issues", Items: issueDrilldown(analysis.Issues, 30)},
		{Key: "admin_probes", Title: "Admin probes", Items: probeDrilldown("admin_probe", analysis.AdminProbes, 30)},
		{Key: "injection_probes", Title: "Injection probes", Items: probeDrilldown("injection_probe", analysis.InjectionProbes, 30)},
		{Key: "tor_sources", Title: "Tor sources", Items: torDrilldown(analysis.TorSources, 30)},
		{Key: "top_paths", Title: "Top paths", Items: pathDrilldown(traffic.TopPaths, 30)},
		{Key: "slow_paths", Title: "Slow paths", Items: slowPathDrilldown(analysis.SlowPaths, 30)},
		{Key: "user_agents", Title: "User agents", Items: userAgentDrilldown(analysis.UserAgents, 30)},
		{Key: "recent_errors", Title: "Recent errors", Items: recentErrorDrilldown(traffic.RecentErrors, 30)},
	}

	return summary, charts, drilldowns
}

func populateReportViewsFromInput(report *Report) {
	if report.Input == nil {
		return
	}
	var summary ReportSummary
	if decodeInputValue(report.Input["report_summary"], &summary) == nil {
		report.Summary = &summary
	}
	var charts []ReportChart
	if decodeInputValue(report.Input["report_charts"], &charts) == nil {
		report.Charts = charts
	}
	var drilldowns []Drilldown
	if decodeInputValue(report.Input["report_drilldowns"], &drilldowns) == nil {
		report.Drilldowns = drilldowns
	}
}

func buildPromptEvidence(input map[string]any, summary *ReportSummary, charts []ReportChart, drilldowns []Drilldown) map[string]any {
	evidence := map[string]any{
		"range":           stringFromInput(input, "range"),
		"site_id":         stringFromInput(input, "site_id"),
		"generated_at":    timeFromInput(input, "generated_at"),
		"evidence_budget": promptEvidenceBudget{ChartPoints: promptChartPointsLimit, DrilldownRows: promptDrilldownLimit, OpenAlerts: promptAlertLimit, MaxStringChars: promptStringLimit, MaxMetaStringChars: promptMetaLimit},
		"summary":         summary,
		"charts":          compactCharts(charts, promptChartPointsLimit),
		"drilldowns":      compactDrilldowns(drilldowns, promptDrilldownLimit),
	}
	if alerts, ok := input["open_alerts"].([]alerts.Alert); ok {
		evidence["open_alerts"] = compactAlerts(alerts, promptAlertLimit)
	}
	return evidence
}

func compactCharts(charts []ReportChart, limit int) []promptChart {
	out := make([]promptChart, 0, len(charts))
	for _, chart := range charts {
		data := limitSlice(chart.Data, limit)
		if chart.Key == "traffic_timeline" {
			data = sampleReportData(chart.Data, limit)
		}
		out = append(out, promptChart{
			Key:   chart.Key,
			Title: truncatePromptString(chart.Title, promptStringLimit),
			Kind:  chart.Kind,
			Unit:  chart.Unit,
			Data:  compactChartData(data),
		})
	}
	return out
}

func compactChartData(data []ReportDatum) []ReportDatum {
	out := make([]ReportDatum, 0, len(data))
	for _, datum := range data {
		datum.Label = truncatePromptString(datum.Label, promptStringLimit)
		datum.Meta = truncatePromptString(datum.Meta, promptMetaLimit)
		out = append(out, datum)
	}
	return out
}

func compactDrilldowns(drilldowns []Drilldown, limit int) []promptDrilldown {
	out := make([]promptDrilldown, 0, len(drilldowns))
	for _, drilldown := range drilldowns {
		out = append(out, promptDrilldown{
			Key:   drilldown.Key,
			Title: truncatePromptString(drilldown.Title, promptStringLimit),
			Items: compactDrilldownItems(drilldown.Items, limit),
		})
	}
	return out
}

func compactDrilldownItems(items []DrilldownItem, limit int) []promptDrilldownItem {
	out := make([]promptDrilldownItem, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		out = append(out, promptDrilldownItem{
			Kind:             item.Kind,
			Label:            truncatePromptString(item.Label, promptStringLimit),
			Meta:             truncatePromptString(item.Meta, promptMetaLimit),
			IP:               item.IP,
			SiteID:           item.SiteID,
			Env:              item.Env,
			Method:           item.Method,
			Path:             truncatePromptString(item.Path, promptStringLimit),
			Query:            truncatePromptString(item.Query, promptStringLimit),
			Category:         item.Category,
			Severity:         item.Severity,
			ActorType:        item.ActorType,
			ActorValue:       truncatePromptString(item.ActorValue, promptStringLimit),
			Status:           item.Status,
			Score:            item.Score,
			RiskScore:        item.RiskScore,
			Requests:         item.Requests,
			Events:           item.Events,
			TotalIPHits:      item.TotalIPHits,
			Status4xx:        item.Status4xx,
			Status5xx:        item.Status5xx,
			BytesSent:        item.BytesSent,
			AvgRequestTimeMS: item.AvgRequestTimeMS,
			P95RequestTimeMS: item.P95RequestTimeMS,
			FirstSeen:        item.FirstSeen,
			LastSeen:         item.LastSeen,
			Timestamp:        item.Timestamp,
			VerifiedSource:   item.VerifiedSource,
			KnownActor:       truncatePromptString(item.KnownActor, promptStringLimit),
			ReverseDNS:       truncatePromptString(item.ReverseDNS, promptStringLimit),
		})
	}
	return out
}

func compactAlerts(items []alerts.Alert, limit int) []promptAlert {
	out := make([]promptAlert, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		out = append(out, promptAlert{
			ID:          truncatePromptString(item.ID, 16),
			RuleKey:     item.RuleKey,
			Title:       truncatePromptString(item.Title, promptStringLimit),
			Severity:    item.Severity,
			Status:      item.Status,
			SiteID:      item.SiteID,
			Env:         item.Env,
			ActorType:   item.ActorType,
			ActorValue:  truncatePromptString(item.ActorValue, promptStringLimit),
			Score:       item.Score,
			Summary:     truncatePromptString(item.Summary, promptMetaLimit),
			FirstSeenAt: item.FirstSeenAt,
			LastSeenAt:  item.LastSeenAt,
		})
	}
	return out
}

func sampleReportData(data []ReportDatum, limit int) []ReportDatum {
	if limit <= 0 || len(data) <= limit {
		return data
	}
	out := make([]ReportDatum, 0, limit)
	last := len(data) - 1
	for index := 0; index < limit; index++ {
		sourceIndex := 0
		if limit > 1 {
			sourceIndex = index * last / (limit - 1)
		}
		out = append(out, data[sourceIndex])
	}
	return out
}

func trafficTimelineChart(timeline []investigation.TimelineBucket) ReportChart {
	rows := append([]investigation.TimelineBucket(nil), timeline...)
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].BucketTS.Before(rows[j].BucketTS)
	})
	if len(rows) > 120 {
		rows = rows[len(rows)-120:]
	}
	data := make([]ReportDatum, 0, len(rows))
	for _, item := range rows {
		data = append(data, ReportDatum{
			Label:     item.BucketTS.Format("Jan 2 15:04"),
			Timestamp: item.BucketTS,
			Value:     float64(item.Requests),
			Secondary: float64(item.Status4xx + item.Status5xx),
			Meta:      "requests / errors",
		})
	}
	return ReportChart{Key: "traffic_timeline", Title: "Traffic timeline", Kind: "line", Unit: "requests", Data: data}
}

func statusMixChart(statuses []accessanalysis.StatusSummary) ReportChart {
	data := []ReportDatum{
		{Label: "2xx", Value: float64(sumAccessStatuses(statuses, 200, 299)), Color: "#178a5f"},
		{Label: "3xx", Value: float64(sumAccessStatuses(statuses, 300, 399)), Color: "#2364aa"},
		{Label: "4xx", Value: float64(sumAccessStatuses(statuses, 400, 499)), Color: "#a96216"},
		{Label: "5xx", Value: float64(sumAccessStatuses(statuses, 500, 599)), Color: "#b93232"},
	}
	return ReportChart{Key: "status_mix", Title: "Status mix", Kind: "bar", Unit: "responses", Data: data}
}

func siteTrafficChart(sites []accessanalysis.SiteSummary) ReportChart {
	data := make([]ReportDatum, 0, minInt(len(sites), 12))
	for _, item := range limitSlice(sites, 12) {
		color := "#178a5f"
		if item.Status5xxRate >= 0.02 {
			color = "#b93232"
		}
		data = append(data, ReportDatum{
			Label:     fmt.Sprintf("%s/%s", item.SiteID, item.Env),
			Value:     float64(item.Requests),
			Secondary: float64(item.Status5xx),
			Color:     color,
			Meta:      "requests / 5xx",
		})
	}
	return ReportChart{Key: "site_traffic", Title: "Site traffic", Kind: "bar", Unit: "requests", Data: data}
}

func sourceIPChart(ips []accessanalysis.SourceIPSummary) ReportChart {
	data := make([]ReportDatum, 0, minInt(len(ips), 12))
	for _, item := range limitSlice(ips, 12) {
		color := "#2364aa"
		if item.VerifiedSource {
			color = "#178a5f"
		}
		if item.Status5xx > 0 {
			color = "#b93232"
		}
		data = append(data, ReportDatum{
			Label:     item.IP,
			Value:     float64(item.Requests),
			Secondary: float64(item.Status4xx + item.Status5xx),
			Color:     color,
			Meta:      "requests / errors",
		})
	}
	return ReportChart{Key: "source_ips", Title: "Source IP concentration", Kind: "bar", Unit: "requests", Data: data}
}

func userAgentClassChart(agents []accessanalysis.UserAgentSummary) ReportChart {
	groups := map[string]float64{}
	for _, item := range agents {
		key := item.ActorType
		if key == "" {
			key = "unknown"
		}
		groups[key] += float64(item.Requests)
	}
	rows := make([]ReportDatum, 0, len(groups))
	for key, value := range groups {
		rows = append(rows, ReportDatum{Label: key, Value: value, Color: actorColor(key)})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Value > rows[j].Value
	})
	if len(rows) > 10 {
		rows = rows[:10]
	}
	return ReportChart{Key: "user_agent_classes", Title: "User-agent classes", Kind: "bar", Unit: "requests", Data: rows}
}

func securitySignalsChart(analysis accessanalysis.Report, summary *ReportSummary) ReportChart {
	data := []ReportDatum{
		{Label: "Admin probes", Value: float64(summary.AdminProbeRequests), Secondary: float64(summary.AdminProbeRows), Color: "#a96216"},
		{Label: "Injection probes", Value: float64(summary.InjectionProbeRequests), Secondary: float64(summary.InjectionProbeRows), Color: "#b93232"},
		{Label: "Tor requests", Value: float64(summary.TorRequests), Secondary: float64(summary.TorSourceRows), Color: "#64707d"},
		{Label: "Issues", Value: float64(len(analysis.Issues)), Secondary: float64(summary.CriticalIssues + summary.HighIssues), Color: "#2364aa"},
	}
	return ReportChart{Key: "security_signals", Title: "Security signals", Kind: "bar", Unit: "events", Data: data}
}

func slowPathChart(paths []accessanalysis.SlowPathSummary) ReportChart {
	data := make([]ReportDatum, 0, minInt(len(paths), 12))
	for _, item := range limitSlice(paths, 12) {
		data = append(data, ReportDatum{
			Label:     item.Path,
			Value:     item.P95RequestTimeMS,
			Secondary: float64(item.Requests),
			Color:     "#0f766e",
			Meta:      "p95 ms / requests",
		})
	}
	return ReportChart{Key: "slow_paths", Title: "Slow paths by p95", Kind: "bar", Unit: "ms", Data: data}
}

func sourceIPDrilldown(items []accessanalysis.SourceIPSummary, limit int) []DrilldownItem {
	out := make([]DrilldownItem, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		riskScore := 0
		if item.RiskScore != nil {
			riskScore = *item.RiskScore
		}
		out = append(out, DrilldownItem{
			Kind:           "source_ip",
			Label:          item.IP,
			Meta:           sourceMeta(item.KnownActor, item.ActorType, item.ReverseDNS),
			IP:             item.IP,
			Requests:       item.Requests,
			Status4xx:      item.Status4xx,
			Status5xx:      item.Status5xx,
			BytesSent:      item.BytesSent,
			RiskScore:      riskScore,
			FirstSeen:      item.FirstSeen,
			LastSeen:       item.LastSeen,
			VerifiedSource: item.VerifiedSource,
			KnownActor:     item.KnownActor,
			ReverseDNS:     item.ReverseDNS,
		})
	}
	return out
}

func issueDrilldown(items []accessanalysis.Issue, limit int) []DrilldownItem {
	out := make([]DrilldownItem, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		out = append(out, DrilldownItem{
			Kind:       "issue",
			Label:      item.Title,
			Meta:       item.Summary,
			SiteID:     item.SiteID,
			Env:        item.Env,
			Severity:   item.Severity,
			ActorType:  item.ActorType,
			ActorValue: item.ActorValue,
			Score:      item.Score,
			Requests:   item.Requests,
			Events:     item.Events,
			FirstSeen:  item.FirstSeen,
			LastSeen:   item.LastSeen,
			Details:    item.Evidence,
		})
	}
	return out
}

func probeDrilldown(kind string, items []accessanalysis.AccessProbeSummary, limit int) []DrilldownItem {
	out := make([]DrilldownItem, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		out = append(out, DrilldownItem{
			Kind:        kind,
			Label:       fmt.Sprintf("%s %s", blankDefault(item.Method, "GET"), blankDefault(item.Path, "/")),
			Meta:        item.SampleQuery,
			IP:          item.IP,
			SiteID:      item.SiteID,
			Env:         item.Env,
			Method:      item.Method,
			Path:        item.Path,
			Query:       item.SampleQuery,
			Category:    item.Category,
			MatchReason: item.MatchReason,
			Requests:    item.Requests,
			TotalIPHits: item.TotalIPHits,
			Status4xx:   item.Status4xx,
			Status5xx:   item.Status5xx,
			RiskScore:   item.RiskScore,
			FirstSeen:   item.FirstSeen,
			LastSeen:    item.LastSeen,
			Details:     item.Evidence,
		})
	}
	return out
}

func torDrilldown(items []accessanalysis.TorSourceSummary, limit int) []DrilldownItem {
	out := make([]DrilldownItem, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		out = append(out, DrilldownItem{
			Kind:           "tor_source",
			Label:          item.IP,
			Meta:           fmt.Sprintf("%s / %s", blankDefault(item.KnownActor, "Tor exit"), item.SiteID),
			IP:             item.IP,
			SiteID:         item.SiteID,
			Env:            item.Env,
			Requests:       item.Requests,
			Events:         item.AdminRequests,
			Status4xx:      item.Status4xx,
			Status5xx:      item.Status5xx,
			RiskScore:      item.RiskScore,
			FirstSeen:      item.FirstSeen,
			LastSeen:       item.LastSeen,
			VerifiedSource: item.VerifiedSource,
			KnownActor:     item.KnownActor,
			ReverseDNS:     item.ReverseDNS,
		})
	}
	return out
}

func pathDrilldown(items []investigation.PathSummary, limit int) []DrilldownItem {
	out := make([]DrilldownItem, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		out = append(out, DrilldownItem{
			Kind:      "path",
			Label:     blankDefault(item.Path, "/"),
			Path:      item.Path,
			Requests:  item.Requests,
			Status4xx: item.Status4xx,
			Status5xx: item.Status5xx,
			BytesSent: item.BytesSent,
		})
	}
	return out
}

func slowPathDrilldown(items []accessanalysis.SlowPathSummary, limit int) []DrilldownItem {
	out := make([]DrilldownItem, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		out = append(out, DrilldownItem{
			Kind:             "slow_path",
			Label:            blankDefault(item.Path, "/"),
			SiteID:           item.SiteID,
			Env:              item.Env,
			Path:             item.Path,
			Requests:         item.Requests,
			Status5xx:        item.Status5xx,
			AvgRequestTimeMS: item.AvgRequestTimeMS,
			P95RequestTimeMS: item.P95RequestTimeMS,
			FirstSeen:        item.FirstSeen,
			LastSeen:         item.LastSeen,
		})
	}
	return out
}

func userAgentDrilldown(items []accessanalysis.UserAgentSummary, limit int) []DrilldownItem {
	out := make([]DrilldownItem, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		out = append(out, DrilldownItem{
			Kind:           "user_agent",
			Label:          blankDefault(item.Family, "unknown"),
			Meta:           item.Sample,
			Category:       item.ActorType,
			KnownActor:     item.KnownActor,
			Requests:       item.Requests,
			Events:         item.UniqueIPs,
			Status4xx:      item.Status4xx,
			Status5xx:      item.Status5xx,
			RiskScore:      item.RiskScore,
			FirstSeen:      item.FirstSeen,
			LastSeen:       item.LastSeen,
			VerifiedSource: item.VerifiedSource,
		})
	}
	return out
}

func recentErrorDrilldown(items []investigation.EventSummary, limit int) []DrilldownItem {
	out := make([]DrilldownItem, 0, minInt(len(items), limit))
	for _, item := range limitSlice(items, limit) {
		out = append(out, DrilldownItem{
			Kind:      "recent_error",
			Label:     fmt.Sprintf("%s %s", blankDefault(item.Method, "GET"), blankDefault(item.Path, "/")),
			Meta:      item.UserAgent,
			IP:        item.ClientIP,
			SiteID:    item.SiteID,
			Env:       item.Env,
			Method:    item.Method,
			Path:      item.Path,
			Query:     item.Query,
			Status:    item.Status,
			BytesSent: item.BytesSent,
			Timestamp: item.TS,
		})
	}
	return out
}

func sumAccessStatuses(rows []accessanalysis.StatusSummary, low int, high int) int64 {
	var total int64
	for _, row := range rows {
		if row.Status >= low && row.Status <= high {
			total += row.Requests
		}
	}
	return total
}

func actorColor(actorType string) string {
	switch actorType {
	case "browser":
		return "#178a5f"
	case "crawler":
		return "#2364aa"
	case "tool":
		return "#a96216"
	case "monitor":
		return "#0f766e"
	case "missing":
		return "#b93232"
	default:
		return "#64707d"
	}
}

func sourceMeta(parts ...string) string {
	kept := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " / ")
}

func blankDefault(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func truncatePromptString(value string, limit int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if limit <= 0 || len([]rune(value)) <= limit {
		return value
	}
	runes := []rune(value)
	if limit <= 3 {
		return string(runes[:limit])
	}
	return strings.TrimSpace(string(runes[:limit-3])) + "..."
}

func stringFromInput(input map[string]any, key string) string {
	if value, ok := input[key].(string); ok {
		return value
	}
	return ""
}

func timeFromInput(input map[string]any, key string) time.Time {
	if value, ok := input[key].(time.Time); ok {
		return value
	}
	return time.Time{}
}

func decodeInputValue(value any, target any) error {
	if value == nil {
		return fmt.Errorf("missing value")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, target)
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func limitSlice[T any](items []T, limit int) []T {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}
