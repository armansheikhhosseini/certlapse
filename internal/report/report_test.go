package report

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

func testReport() Report {
	now := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)
	findings := []model.Finding{
		{Certificate: model.Certificate{DNSNames: []string{"ok.example.com"}, Renewal: model.RenewalAuto, NotAfter: now.AddDate(0, 0, 60)}, Severity: model.SeverityOK, DaysLeft: 60},
		{Certificate: model.Certificate{DNSNames: []string{"late.example.com"}, Renewal: model.RenewalManual, PubliclyTrusted: true, NotAfter: now.AddDate(0, 0, 90)}, Severity: model.SeverityWarning, DaysLeft: 90},
		{Certificate: model.Certificate{DNSNames: []string{"soon.example.com"}, Renewal: model.RenewalManual, PubliclyTrusted: true, NotAfter: now.AddDate(0, 0, 10),
			Location: "prod:web/soon-tls", Fixes: []model.Fix{{Title: "Let cert-manager renew it", Lang: "yaml", Text: "kind: Certificate\nspec:\n  secretName: soon-tls\n"}}},
			Severity: model.SeverityWarning, DaysLeft: 10},
		// Manual but unused, so it doesn't count towards the renewal workload.
		{Certificate: model.Certificate{DNSNames: []string{"spare.example.com"}, Renewal: model.RenewalManual, PubliclyTrusted: true, Unused: true, NotAfter: now.AddDate(0, 0, 120)}, Severity: model.SeverityInfo, DaysLeft: 120},
		{Certificate: model.Certificate{Subject: "old", Renewal: model.RenewalUnknown, NotAfter: now.AddDate(0, 0, -3)}, Severity: model.SeverityCritical, DaysLeft: -3},
	}
	errs := []model.ScanError{{Source: model.SourceEndpoint, Location: "down.example.com:443", Err: "connection refused"}}
	return New(findings, errs, now)
}

func TestNewSortsBySeverityThenExpiry(t *testing.T) {
	r := testReport()
	var got []string
	for _, f := range r.Findings {
		got = append(got, f.Name())
	}
	want := "old soon.example.com late.example.com spare.example.com ok.example.com"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
	if r.Highest() != model.SeverityCritical {
		t.Errorf("Highest = %s, want critical", r.Highest())
	}
	if r.Summary.Total != 5 || r.Summary.ByRenewal[model.RenewalManual] != 3 {
		t.Errorf("summary = %+v", r.Summary)
	}
}

func TestOutlook(t *testing.T) {
	s := testReport().Summary
	if s.ManualPublic != 2 {
		t.Fatalf("ManualPublic = %d, want 2", s.ManualPublic)
	}
	var got []int
	for _, o := range s.Outlook {
		got = append(got, o.RenewalsPerYear)
	}
	// 2 certificates × 2, 4 and 8 renewals a year at 200, 100 and 47 days.
	if len(got) != 3 || got[0] != 4 || got[1] != 8 || got[2] != 16 {
		t.Errorf("renewals a year = %v, want [4 8 16]", got)
	}
}

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, testReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"# Certificate inventory", "| 15 Mar 2027 | 100 days | about 8 |", "| critical | old |", "## Couldn't scan",
		"## How to fix\n\n### soon.example.com (prod:web/soon-tls)\n\nLet cert-manager renew it:\n\n```yaml\nkind: Certificate\nspec:\n  secretName: soon-tls\n```\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown is missing %q:\n%s", want, out)
		}
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, testReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"SEVERITY", "(expired)", "(10d)", "5 certificates", "2 public certificate(s) in use are renewed by hand",
		"from 15 Mar 2027", "about 8", "down.example.com:443",
		"How to fix:\n\nsoon.example.com · prod:web/soon-tls: Let cert-manager renew it\n    kind: Certificate\n    spec:\n      secretName: soon-tls\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output is missing %q:\n%s", want, out)
		}
	}
}

func TestHideOK(t *testing.T) {
	r := testReport()
	r.HideOK = true
	for name, write := range map[string]func(io.Writer, Report) error{"table": WriteTable, "markdown": WriteMarkdown} {
		var buf bytes.Buffer
		if err := write(&buf, r); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if strings.Contains(out, "ok.example.com") || !strings.Contains(out, "soon.example.com") ||
			!strings.Contains(out, "5 certificates") || !strings.Contains(out, "1 healthy certificate(s) not listed; --all lists them.") {
			t.Errorf("%s with HideOK:\n%s", name, out)
		}
	}
}

func TestWrap(t *testing.T) {
	got := wrap("one two three four five", 9)
	if strings.Join(got, "|") != "one two|three|four five" {
		t.Errorf("wrap = %q", got)
	}
	if got := wrap("averyveryverylongword x", 5); strings.Join(got, "|") != "averyveryverylongword|x" {
		t.Errorf("wrap = %q", got)
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, testReport()); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
		Summary struct {
			BySeverity map[string]int `json:"bySeverity"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Findings[0].Severity != "critical" || decoded.Summary.BySeverity["warning"] != 2 || !strings.Contains(buf.String(), `"manualPublic": 2`) {
		t.Errorf("unexpected JSON: %s", buf.String())
	}
}
