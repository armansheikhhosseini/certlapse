package preflight

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/armansheikhhosseini/certlapse/internal/ca"
	"github.com/armansheikhhosseini/certlapse/internal/model"
)

// zone answers lookups from records in zone file syntax. Names in fail return an error.
func zone(t *testing.T, records []string, fail ...string) Lookup {
	t.Helper()
	var rrs []dns.RR
	for _, r := range records {
		rr, err := dns.NewRR(r)
		if err != nil {
			t.Fatalf("record %q: %v", r, err)
		}
		rrs = append(rrs, rr)
	}
	return func(_ context.Context, name string, qtype uint16) ([]dns.RR, error) {
		for _, f := range fail {
			if sameName(f, name) {
				return nil, errors.New("SERVFAIL")
			}
		}
		var out []dns.RR
		for _, rr := range rrs {
			if sameName(rr.Header().Name, name) && rr.Header().Rrtype == qtype {
				out = append(out, rr)
			}
		}
		return out, nil
	}
}

var now = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func check(t *testing.T, lookup Lookup, c model.Certificate) ([]string, []model.ScanError) {
	t.Helper()
	out, errs := checkOne(t, lookup, c)
	return out.Problems, errs
}

func checkOne(t *testing.T, lookup Lookup, c model.Certificate) (model.Certificate, []model.ScanError) {
	t.Helper()
	if c.NotAfter.IsZero() {
		c.NotAfter = now.AddDate(0, 3, 0)
	}
	out, errs := Checker{Lookup: lookup}.Check(context.Background(), []model.Certificate{c}, now)
	return out[0], errs
}

func TestCAA(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		dnsName []string
		want    string // substring of the only problem; empty for none
	}{
		{
			name:    "other CA only",
			records: []string{`example.com. CAA 0 issue "letsencrypt.org"`},
			dnsName: []string{"example.com", "www.example.com"},
			want:    "Amazon can't issue for example.com, www.example.com (CAA on example.com only allows letsencrypt.org)",
		},
		{
			name:    "allowed",
			records: []string{`example.com. CAA 0 issue "letsencrypt.org"`, `example.com. CAA 0 issue "amazon.com"`},
			dnsName: []string{"example.com"},
		},
		{
			name:    "allowed with parameters",
			records: []string{`example.com. CAA 0 issue "amazontrust.com; validationmethods=dns-01"`},
			dnsName: []string{"example.com"},
		},
		{
			name:    "inherited from the parent",
			records: []string{`example.com. CAA 0 issue "pki.goog"`},
			dnsName: []string{"a.b.example.com"},
			want:    "CAA on example.com only allows pki.goog",
		},
		{
			name:    "own records override the parent's",
			records: []string{`example.com. CAA 0 issue "pki.goog"`, `api.example.com. CAA 0 issue "amazon.com"`},
			dnsName: []string{"api.example.com"},
		},
		{
			name:    "no CAA anywhere",
			dnsName: []string{"example.com"},
		},
		{
			name:    "no issue properties",
			records: []string{`example.com. CAA 0 iodef "mailto:security@example.com"`},
			dnsName: []string{"example.com"},
		},
		{
			name:    "issuewild forbids wildcards",
			records: []string{`example.com. CAA 0 issue "amazon.com"`, `example.com. CAA 0 issuewild ";"`},
			dnsName: []string{"example.com", "*.example.com"},
			want:    "Amazon can't issue for *.example.com (CAA on example.com allows no CA to issue)",
		},
		{
			name:    "issue covers wildcards without issuewild",
			records: []string{`example.com. CAA 0 issue "amazon.com"`},
			dnsName: []string{"*.example.com"},
		},
		{
			name:    "issuewild names another CA",
			records: []string{`example.com. CAA 0 issue "amazon.com"`, `example.com. CAA 0 issuewild "letsencrypt.org"`},
			dnsName: []string{"*.example.com"},
			want:    "only allows letsencrypt.org for wildcards",
		},
		{
			name:    "unknown critical property",
			records: []string{`example.com. CAA 0 issue "amazon.com"`, `example.com. CAA 128 tbs "unknown"`},
			dnsName: []string{"example.com"},
			want:    `has a critical "tbs" property no CA understands`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems, errs := check(t, zone(t, tt.records), model.Certificate{DNSNames: tt.dnsName, RenewingCA: ca.Amazon})
			if len(errs) > 0 {
				t.Fatalf("errors: %v", errs)
			}
			switch {
			case tt.want == "" && len(problems) > 0:
				t.Errorf("problems = %q, want none", problems)
			case tt.want != "" && (len(problems) != 1 || !strings.Contains(problems[0], tt.want)):
				t.Errorf("problems = %q, want one containing %q", problems, tt.want)
			}
		})
	}
}

func TestValidationCNAMEs(t *testing.T) {
	rec := model.CNAME{Name: "_a1.example.com.", Value: "_b2.acm-validations.aws."}
	tests := []struct {
		name    string
		records []string
		want    string
	}{
		{"present", []string{`_a1.example.com. CNAME _B2.acm-validations.aws.`}, ""},
		{"missing", nil, "ACM's validation record _a1.example.com is missing from DNS (add it back: CNAME _b2.acm-validations.aws)"},
		{"changed", []string{`_a1.example.com. CNAME _old.acm-validations.aws.`}, "points to _old.acm-validations.aws, not _b2.acm-validations.aws"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems, _ := check(t, zone(t, tt.records), model.Certificate{DNSNames: []string{"example.com"}, ValidationCNAMEs: []model.CNAME{rec}})
			switch {
			case tt.want == "" && len(problems) > 0:
				t.Errorf("problems = %q, want none", problems)
			case tt.want != "" && (len(problems) != 1 || !strings.Contains(problems[0], tt.want)):
				t.Errorf("problems = %q, want one containing %q", problems, tt.want)
			}
		})
	}
}

func TestFixes(t *testing.T) {
	lookup := zone(t, []string{
		`example.com. CAA 0 issue "letsencrypt.org"`,
		`example.com. CAA 0 issuewild ";"`,
	})
	c, _ := checkOne(t, lookup, model.Certificate{
		DNSNames: []string{"example.com", "www.example.com", "*.example.com"}, RenewingCA: ca.Amazon,
		ValidationCNAMEs: []model.CNAME{{Name: "_a1.example.com.", Value: "_b2.acm-validations.aws."}},
	})
	var texts []string
	for _, f := range c.Fixes {
		texts = append(texts, f.Text)
	}
	got := strings.Join(texts, "")
	for _, want := range []string{
		"_a1.example.com. CNAME _b2.acm-validations.aws.\n",
		`example.com. CAA 0 issue "amazon.com"` + "\n",
		`example.com. CAA 0 issuewild "amazon.com"` + "\n",
	} {
		if strings.Count(got, want) != 1 {
			t.Errorf("fixes should contain %q once:\n%s", want, got)
		}
	}
	if len(c.Fixes) != 2 {
		t.Errorf("got %d fixes, want 2 (validation records, CAA)", len(c.Fixes))
	}

	critical := zone(t, []string{`example.com. CAA 128 tbs "x"`})
	if c, _ := checkOne(t, critical, model.Certificate{DNSNames: []string{"example.com"}, RenewingCA: ca.Amazon}); len(c.Problems) != 1 || len(c.Fixes) != 0 {
		t.Errorf("critical property: problems %q, fixes %+v; want a problem and no record to add", c.Problems, c.Fixes)
	}
}

func TestCheckSkipsCertificatesNothingWillRenew(t *testing.T) {
	lookup := zone(t, []string{`example.com. CAA 0 issue "letsencrypt.org"`})
	for name, c := range map[string]model.Certificate{
		"expired": {NotAfter: now.AddDate(0, 0, -1)},
		"unused":  {Unused: true},
		"no CA":   {},
	} {
		c.DNSNames = []string{"example.com"}
		if c.Unused || name == "expired" {
			c.RenewingCA = ca.Amazon
		}
		if problems, _ := check(t, lookup, c); len(problems) > 0 {
			t.Errorf("%s: problems = %q, want none", name, problems)
		}
	}
}

func TestCheckReportsFailedLookupsOnce(t *testing.T) {
	lookup := zone(t, nil, "example.com")
	c := model.Certificate{DNSNames: []string{"example.com"}, RenewingCA: ca.Amazon, NotAfter: now.AddDate(0, 3, 0)}
	out, errs := Checker{Lookup: lookup}.Check(context.Background(), []model.Certificate{c, c}, now)
	if len(out[0].Problems) > 0 || len(out[1].Problems) > 0 {
		t.Errorf("problems = %q, %q; want none when DNS fails", out[0].Problems, out[1].Problems)
	}
	if len(errs) != 1 || errs[0].Location != "CAA example.com" {
		t.Errorf("errors = %v, want one for CAA example.com", errs)
	}
}

func TestNewResolver(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "example.com." && r.Question[0].Qtype == dns.TypeCAA {
			rr, _ := dns.NewRR(`example.com. 300 CAA 0 issue "letsencrypt.org"`)
			m.Answer = append(m.Answer, rr)
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	lookup, err := NewResolver(pc.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	problems, errs := check(t, lookup, model.Certificate{DNSNames: []string{"www.example.com"}, RenewingCA: ca.Amazon})
	if len(errs) > 0 || len(problems) != 1 || !strings.Contains(problems[0], "only allows letsencrypt.org") {
		t.Errorf("problems = %q, errors = %v; want one naming letsencrypt.org", problems, errs)
	}
}
