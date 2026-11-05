package correlate

import (
	"slices"
	"testing"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

func TestLink(t *testing.T) {
	in := []model.Certificate{
		{Source: model.SourceACM, Location: "acm-cert", Fingerprint: "aa", Renewal: model.RenewalAuto, UsedBy: []string{"cloudfront/E1"}},
		{Source: model.SourceIAM, Location: "iam-cert", Fingerprint: "bb", Renewal: model.RenewalManual, Unused: true},
		{Source: model.SourceEndpoint, Location: "www.example.com:443", Fingerprint: "aa", Renewal: model.RenewalUnknown},
		{Source: model.SourceEndpoint, Location: "legacy.example.com:8443", Fingerprint: "bb", Problems: []string{"certificate doesn't cover legacy.example.com"}},
		{Source: model.SourceEndpoint, Location: "elsewhere.example.com:443", Fingerprint: "cc", Renewal: model.RenewalUnknown},
	}
	original := slices.Clone(in[0].UsedBy)

	out := Link(in)

	if len(out) != 3 {
		t.Fatalf("got %d certificates, want 3: %+v", len(out), out)
	}
	acm, iam, other := out[0], out[1], out[2]
	if !slices.Equal(acm.UsedBy, []string{"cloudfront/E1", "https://www.example.com"}) {
		t.Errorf("ACM used by %v", acm.UsedBy)
	}
	if iam.Unused || !slices.Equal(iam.UsedBy, []string{"https://legacy.example.com:8443"}) || len(iam.Problems) != 1 {
		t.Errorf("IAM certificate: %+v", iam)
	}
	if other.Location != "elsewhere.example.com:443" || other.Renewal != model.RenewalUnknown ||
		!slices.Equal(other.UsedBy, []string{"https://elsewhere.example.com"}) {
		t.Errorf("unmatched endpoint: %+v", other)
	}
	if !slices.Equal(in[0].UsedBy, original) {
		t.Errorf("input changed: %v", in[0].UsedBy)
	}
}

func TestLinkGroupsEndpointsServingTheSameCertificate(t *testing.T) {
	in := []model.Certificate{
		{Source: model.SourceEndpoint, Location: "a.example.com:443", Fingerprint: "ff"},
		{Source: model.SourceEndpoint, Location: "b.example.com:443", Fingerprint: "ff", Problems: []string{"certificate doesn't cover b.example.com"}},
		{Source: model.SourceEndpoint, Location: "c.example.com:443", Fingerprint: "ee"},
		{Source: model.SourceEndpoint, Location: "d.example.com:443", Fingerprint: "ff"},
	}
	out := Link(in)
	if len(out) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(out), out)
	}
	if g := out[0]; g.Location != "a.example.com:443" || len(g.Problems) != 1 ||
		!slices.Equal(g.UsedBy, []string{"https://a.example.com", "https://b.example.com", "https://d.example.com"}) {
		t.Errorf("group = %+v", g)
	}
}
