// Package report sorts findings and writes them as a table, JSON or Markdown.
package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/armansheikhhosseini/certlapse/internal/arnutil"
	"github.com/armansheikhhosseini/certlapse/internal/model"
	"github.com/armansheikhhosseini/certlapse/internal/policy"
)

// Report is the result of one scan.
type Report struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	Findings    []model.Finding   `json:"findings"`
	Errors      []model.ScanError `json:"errors,omitempty"`
	Summary     Summary           `json:"summary"`
	// HideOK leaves healthy certificates out of the table and Markdown. The summary
	// still counts them, and JSON always has every finding.
	HideOK bool `json:"-"`
}

// Summary counts findings by renewal status and severity.
type Summary struct {
	Total      int                    `json:"total"`
	ByRenewal  map[model.Renewal]int  `json:"byRenewal"`
	BySeverity map[model.Severity]int `json:"bySeverity"`
	// ManualPublic counts publicly trusted certificates in use that are renewed by
	// hand: the ones shorter lifetimes turn into recurring work.
	ManualPublic int `json:"manualPublic"`
	// Outlook is how many manual renewals a year ManualPublic means now and after
	// each upcoming lifetime cut.
	Outlook []OutlookStep `json:"outlook"`
}

// OutlookStep is the manual renewal workload while one maximum lifetime applies.
type OutlookStep struct {
	From            time.Time `json:"from"`
	MaxDays         int       `json:"maxDays"`
	RenewalsPerYear int       `json:"renewalsPerYear"`
}

// New builds a report, most urgent findings first.
func New(findings []model.Finding, errs []model.ScanError, now time.Time) Report {
	sorted := slices.Clone(findings)
	slices.SortStableFunc(sorted, func(a, b model.Finding) int {
		if c := cmp.Compare(b.Severity, a.Severity); c != 0 {
			return c
		}
		return a.NotAfter.Compare(b.NotAfter)
	})
	s := Summary{Total: len(sorted), ByRenewal: map[model.Renewal]int{}, BySeverity: map[model.Severity]int{}}
	for _, f := range sorted {
		s.ByRenewal[f.Renewal]++
		s.BySeverity[f.Severity]++
		if f.Renewal == model.RenewalManual && f.PubliclyTrusted && !f.Unused && f.DaysLeft >= 0 {
			s.ManualPublic++
		}
	}
	for _, step := range policy.Outlook(now) {
		s.Outlook = append(s.Outlook, OutlookStep{
			From:            step.From,
			MaxDays:         step.MaxDays,
			RenewalsPerYear: s.ManualPublic * policy.RenewalsPerYear(step.MaxDays),
		})
	}
	return Report{GeneratedAt: now, Findings: sorted, Errors: errs, Summary: s}
}

// outlookLines describes the manual renewal workload, one line per lifetime step.
func outlookLines(s Summary) []string {
	if s.ManualPublic == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("%d public certificate(s) in use are renewed by hand. Manual renewals a year:", s.ManualPublic)}
	for i, o := range s.Outlook {
		when := "now"
		if i > 0 {
			when = "from " + o.From.Format("2 Jan 2006")
		}
		lines = append(lines, fmt.Sprintf("  %-18s %3d days max  →  about %d", when, o.MaxDays, o.RenewalsPerYear))
	}
	return lines
}

// Highest is the most urgent severity in the report.
func (r Report) Highest() model.Severity {
	highest := model.SeverityOK
	for _, f := range r.Findings {
		highest = max(highest, f.Severity)
	}
	return highest
}

// listed returns the findings to list, and how many healthy ones are left out.
func (r Report) listed() ([]model.Finding, int) {
	if !r.HideOK {
		return r.Findings, 0
	}
	var out []model.Finding
	for _, f := range r.Findings {
		if f.Severity != model.SeverityOK {
			out = append(out, f)
		}
	}
	return out, len(r.Findings) - len(out)
}

func hiddenLine(n int) string {
	return fmt.Sprintf("%d healthy certificate(s) not listed; --all lists them.", n)
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteTable writes the report for people to read.
func WriteTable(w io.Writer, r Report) error {
	findings, hidden := r.listed()
	if len(findings) > 0 {
		writeRows(w, findings)
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, summaryLine(r.Summary))
	if hidden > 0 {
		fmt.Fprintln(w, hiddenLine(hidden))
	}
	if lines := outlookLines(r.Summary); len(lines) > 0 {
		fmt.Fprintln(w, strings.Join(lines, "\n"))
	} else {
		fmt.Fprintln(w, policyLine(r.GeneratedAt))
	}

	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "\nCouldn't scan %d location(s):\n", len(r.Errors))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, e := range r.Errors {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", e.Source, e.Location, e.Err)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if withFixes := fixable(r.Findings); len(withFixes) > 0 {
		fmt.Fprintln(w, "\nHow to fix:")
		for _, f := range withFixes {
			for _, fix := range f.Fixes {
				fmt.Fprintf(w, "\n%s · %s: %s\n", f.Name(), arnutil.Short(f.Location), fix.Title)
				for _, line := range strings.Split(strings.TrimRight(fix.Text, "\n"), "\n") {
					fmt.Fprintln(w, "    "+line)
				}
			}
		}
	}
	return nil
}

// writeRows writes one aligned row per finding, with its action on the line below so
// the table stays narrow enough for a terminal.
func writeRows(w io.Writer, findings []model.Finding) {
	rows := [][]string{{"SEVERITY", "NAME", "SOURCE", "LOCATION", "USED BY", "RENEWAL", "EXPIRES"}}
	for _, f := range findings {
		rows = append(rows, []string{f.Severity.String(), f.Name(), f.Source, arnutil.Short(f.Location), usedBy(f), string(f.Renewal), expires(f)})
	}
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, c := range row {
			widths[i] = max(widths[i], utf8.RuneCountInString(c))
		}
	}
	for i, row := range rows {
		var b strings.Builder
		for j, c := range row {
			b.WriteString(c)
			if j < len(row)-1 {
				b.WriteString(strings.Repeat(" ", widths[j]-utf8.RuneCountInString(c)+2))
			}
		}
		fmt.Fprintln(w, b.String())
		if i > 0 && findings[i-1].Action != "" {
			indent := strings.Repeat(" ", widths[0]+2)
			for j, line := range wrap(findings[i-1].Action, actionWidth) {
				marker := "  "
				if j == 0 {
					marker = "↳ "
				}
				fmt.Fprintln(w, indent+marker+line)
			}
		}
	}
}

// actionWidth is where actions wrap, so they read well in an ordinary terminal.
const actionWidth = 100

// wrap breaks text into lines of at most width characters, at spaces. Longer words stay whole.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	return append(lines, line)
}

// fixable returns the findings that come with fixes, in report order.
func fixable(findings []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if len(f.Fixes) > 0 {
			out = append(out, f)
		}
	}
	return out
}

// WriteMarkdown writes the report as Markdown, to paste into a ticket, a pull request or an email.
func WriteMarkdown(w io.Writer, r Report) error {
	fmt.Fprintf(w, "# Certificate inventory\n\nScanned %s.\n\n", r.GeneratedAt.UTC().Format("2 Jan 2006 15:04 MST"))
	fmt.Fprintf(w, "%s\n\n", summaryLine(r.Summary))
	if s := r.Summary; s.ManualPublic > 0 {
		fmt.Fprintf(w, "## Shorter certificate lifetimes\n\n%d public certificate(s) in use are renewed by hand.\n\n", s.ManualPublic)
		fmt.Fprintln(w, "| From | Maximum lifetime | Manual renewals a year |\n|---|---|---|")
		for i, o := range s.Outlook {
			when := "Now"
			if i > 0 {
				when = o.From.Format("2 Jan 2006")
			}
			fmt.Fprintf(w, "| %s | %d days | about %d |\n", when, o.MaxDays, o.RenewalsPerYear)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "%s\n\n", policyLine(r.GeneratedAt))
	}

	findings, hidden := r.listed()
	if hidden > 0 {
		fmt.Fprintf(w, "%s\n\n", hiddenLine(hidden))
	}
	if len(findings) > 0 {
		fmt.Fprintln(w, "## Certificates\n\n| Severity | Name | Source | Location | Used by | Renewal | Expires | Action |\n|---|---|---|---|---|---|---|---|")
		for _, f := range findings {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				f.Severity, cell(f.Name()), f.Source, cell(arnutil.Short(f.Location)), cell(usedBy(f)), f.Renewal, expires(f), cell(f.Action))
		}
		fmt.Fprintln(w)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintln(w, "## Couldn't scan\n\n| Source | Location | Error |\n|---|---|---|")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "| %s | %s | %s |\n", e.Source, cell(e.Location), cell(e.Err))
		}
		fmt.Fprintln(w)
	}
	if withFixes := fixable(r.Findings); len(withFixes) > 0 {
		fmt.Fprintln(w, "## How to fix")
		for _, f := range withFixes {
			fmt.Fprintf(w, "\n### %s (%s)\n", f.Name(), arnutil.Short(f.Location))
			for _, fix := range f.Fixes {
				fmt.Fprintf(w, "\n%s:\n\n```%s\n%s```\n", fix.Title, fix.Lang, fix.Text)
			}
		}
	}
	return nil
}

// cell makes text safe inside a Markdown table cell.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}

func summaryLine(s Summary) string {
	return fmt.Sprintf("%d certificates · renewal: %d auto, %d manual, %d failing, %d unknown · %d critical, %d high, %d warning, %d info",
		s.Total,
		s.ByRenewal[model.RenewalAuto], s.ByRenewal[model.RenewalManual], s.ByRenewal[model.RenewalAutoFailing], s.ByRenewal[model.RenewalUnknown],
		s.BySeverity[model.SeverityCritical], s.BySeverity[model.SeverityHigh], s.BySeverity[model.SeverityWarning], s.BySeverity[model.SeverityInfo])
}

// usedBy lists up to two users of the certificate, shortened.
func usedBy(f model.Finding) string {
	if len(f.UsedBy) == 0 {
		return "-"
	}
	names := make([]string, 0, 2)
	for _, u := range f.UsedBy[:min(2, len(f.UsedBy))] {
		names = append(names, arnutil.Short(u))
	}
	s := strings.Join(names, ", ")
	if extra := len(f.UsedBy) - len(names); extra > 0 {
		s += fmt.Sprintf(" +%d", extra)
	}
	return s
}

func expires(f model.Finding) string {
	if f.NotIssued {
		return "never issued"
	}
	date := f.NotAfter.Format(time.DateOnly)
	if f.DaysLeft < 0 {
		return date + " (expired)"
	}
	return fmt.Sprintf("%s (%dd)", date, f.DaysLeft)
}

func policyLine(now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Public certificates issued now last at most %d days", policy.Current(now).MaxDays)
	if next, ok := policy.Next(now); ok {
		fmt.Fprintf(&b, "; from %s, %d days", next.From.Format("2 Jan 2006"), next.MaxDays)
	}
	b.WriteString(".")
	return b.String()
}
