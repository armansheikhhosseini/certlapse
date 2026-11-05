package classify

import (
	"strings"
	"testing"
	"time"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

func TestClassify(t *testing.T) {
	now := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	in := func(days int) time.Time { return now.Add(time.Duration(days) * 24 * time.Hour) }

	tests := []struct {
		name       string
		cert       model.Certificate
		want       model.Severity
		wantAction string
	}{
		{"expired", model.Certificate{Renewal: model.RenewalAuto, NotAfter: in(-1)},
			model.SeverityCritical, "expired on"},
		{"auto-renewal failing", model.Certificate{Renewal: model.RenewalAutoFailing, RenewalNote: "DNS challenge failing", NotAfter: in(40)},
			model.SeverityCritical, "DNS challenge failing"},
		{"manual, expiring soon", model.Certificate{Source: model.SourceKubernetes, Renewal: model.RenewalManual, PubliclyTrusted: true, NotAfter: in(20)},
			model.SeverityHigh, "cert-manager"},
		{"manual, public", model.Certificate{Source: model.SourceACM, Renewal: model.RenewalManual, PubliclyTrusted: true, NotAfter: in(200)},
			model.SeverityWarning, "100 days"},
		{"manual, private CA", model.Certificate{Renewal: model.RenewalManual, NotAfter: in(200)},
			model.SeverityInfo, "private CA"},
		{"auto, healthy", model.Certificate{Renewal: model.RenewalAuto, NotAfter: in(80)},
			model.SeverityOK, ""},
		{"auto, overdue", model.Certificate{Renewal: model.RenewalAuto, NotAfter: in(10)},
			model.SeverityHigh, "hasn't renewed"},
		{"unknown", model.Certificate{Renewal: model.RenewalUnknown, NotAfter: in(90)},
			model.SeverityInfo, "unknown"},
		{"unknown, expiring soon", model.Certificate{Renewal: model.RenewalUnknown, NotAfter: in(5)},
			model.SeverityHigh, "expires in 5 days"},
		{"unused", model.Certificate{Renewal: model.RenewalManual, Unused: true, NotAfter: in(90)},
			model.SeverityInfo, "not used by anything"},
		{"expired and unused", model.Certificate{Renewal: model.RenewalAuto, Unused: true, NotAfter: in(-30)},
			model.SeverityInfo, "expired and not used"},
		{"never issued", model.Certificate{Renewal: model.RenewalAutoFailing, NotIssued: true, RenewalNote: "issuer isn't ready"},
			model.SeverityHigh, "never issued: issuer isn't ready"},
		{"never issued, but in use", model.Certificate{Renewal: model.RenewalAutoFailing, NotIssued: true, UsedBy: []string{"ingress/web/shop"}},
			model.SeverityCritical, "HTTPS for the hosts that use it is broken"},
		{"problem raises severity", model.Certificate{Renewal: model.RenewalAuto, NotAfter: in(80), Problems: []string{"certificate doesn't cover x"}},
			model.SeverityHigh, "doesn't cover x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Classify(tt.cert, now)
			if f.Severity != tt.want {
				t.Errorf("severity = %s, want %s (action %q)", f.Severity, tt.want, f.Action)
			}
			if !strings.Contains(f.Action, tt.wantAction) {
				t.Errorf("action = %q, want it to contain %q", f.Action, tt.wantAction)
			}
		})
	}
}

func TestDaysLeft(t *testing.T) {
	now := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	if got := daysLeft(now.Add(36*time.Hour), now); got != 1 {
		t.Errorf("daysLeft(+36h) = %d, want 1", got)
	}
	if got := daysLeft(now.Add(-time.Hour), now); got != -1 {
		t.Errorf("daysLeft(-1h) = %d, want -1", got)
	}
}
