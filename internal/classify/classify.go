// Package classify turns a certificate into a finding: how urgent it is and what to do.
package classify

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/armansheikhhosseini/certlapse/internal/model"
	"github.com/armansheikhhosseini/certlapse/internal/policy"
)

// Thresholds, in days before expiry.
const (
	manualUrgentDays  = 30 // a hand-renewed certificate needs attention now
	autoOverdueDays   = 14 // automatic renewal should already have happened (ACM renews 60 days ahead, cert-manager at 2/3 of the lifetime)
	unknownUrgentDays = 14
)

// Classify gives one certificate a severity and a suggested action.
func Classify(c model.Certificate, now time.Time) model.Finding {
	if c.NotIssued {
		f := model.Finding{Certificate: c, Severity: model.SeverityHigh, Action: "never issued: " + c.RenewalNote}
		if len(c.UsedBy) > 0 {
			f.Severity = model.SeverityCritical
			f.Action += "; HTTPS for the hosts that use it is broken"
		}
		if len(c.Problems) > 0 {
			f.Action += "; " + strings.Join(c.Problems, "; ")
		}
		return f
	}
	f := model.Finding{Certificate: c, DaysLeft: daysLeft(c.NotAfter, now)}
	f.Severity, f.Action = verdict(c, f.DaysLeft, now)
	if len(c.Problems) > 0 {
		f.Severity = max(f.Severity, model.SeverityHigh)
		f.Action = joinActions(strings.Join(c.Problems, "; "), f.Action)
	}
	return f
}

// ClassifyAll classifies every certificate.
func ClassifyAll(certs []model.Certificate, now time.Time) []model.Finding {
	findings := make([]model.Finding, 0, len(certs))
	for _, c := range certs {
		findings = append(findings, Classify(c, now))
	}
	return findings
}

func verdict(c model.Certificate, days int, now time.Time) (model.Severity, string) {
	if c.Unused {
		if days < 0 {
			return model.SeverityInfo, "expired and not used by anything: delete it"
		}
		return model.SeverityInfo, "not used by anything: delete it if it's no longer needed"
	}
	if days < 0 {
		return model.SeverityCritical, "expired on " + c.NotAfter.Format(time.DateOnly) + ": replace it now"
	}
	switch c.Renewal {
	case model.RenewalAutoFailing:
		return model.SeverityCritical, fmt.Sprintf("automatic renewal is failing (%s): fix it within %d days", c.RenewalNote, days)
	case model.RenewalManual:
		why := "renewed by hand"
		if c.RenewalNote != "" {
			why = c.RenewalNote
		}
		if days <= manualUrgentDays {
			return model.SeverityHigh, fmt.Sprintf("%s, and it expires in %d days: renew it now, then %s", why, days, automateHint(c.Source))
		}
		if !c.PubliclyTrusted {
			return model.SeverityInfo, why + "; private CA, so the public lifetime limits don't apply"
		}
		return model.SeverityWarning, fmt.Sprintf("%s: %s (%s)", why, automateHint(c.Source), lifetimeNote(now))
	case model.RenewalAuto:
		if days <= autoOverdueDays {
			return model.SeverityHigh, fmt.Sprintf("set to renew automatically but expires in %d days: check why it hasn't renewed", days)
		}
		return model.SeverityOK, ""
	default:
		if days <= unknownUrgentDays {
			return model.SeverityHigh, fmt.Sprintf("expires in %d days and nothing found renews it", days)
		}
		if c.RenewalNote != "" {
			return model.SeverityInfo, "renewal owner unknown (" + c.RenewalNote + "): scan the AWS accounts and clusters that serve it"
		}
		return model.SeverityInfo, "renewal owner unknown: scan the AWS accounts and clusters that serve it"
	}
}

func automateHint(source string) string {
	switch source {
	case model.SourceKubernetes:
		return "manage it with a cert-manager Certificate"
	case model.SourceACM:
		return "replace the imported certificate with an ACM-issued one"
	case model.SourceIAM:
		return "move it to ACM (IAM server certificates never renew)"
	default:
		return "automate it with ACME (cert-manager, certbot) or ACM"
	}
}

// lifetimeNote explains how often a hand-renewed public certificate will need replacing.
func lifetimeNote(now time.Time) string {
	if next, ok := policy.Next(now); ok {
		return fmt.Sprintf("from %s public certificates last at most %d days, about %d renewals a year",
			next.From.Format("2 Jan 2006"), next.MaxDays, policy.RenewalsPerYear(next.MaxDays))
	}
	cur := policy.Current(now)
	return fmt.Sprintf("public certificates last at most %d days, about %d renewals a year",
		cur.MaxDays, policy.RenewalsPerYear(cur.MaxDays))
}

func daysLeft(notAfter, now time.Time) int {
	return int(math.Floor(notAfter.Sub(now).Hours() / 24))
}

func joinActions(a, b string) string {
	if b == "" {
		return a
	}
	return a + "; " + b
}
