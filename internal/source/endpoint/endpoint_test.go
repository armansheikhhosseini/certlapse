package endpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in   string
		want Target
	}{
		{"example.com", Target{"example.com", "443"}},
		{" example.com:8443 ", Target{"example.com", "8443"}},
		{"https://example.com/path", Target{"example.com", "443"}},
		{"https://example.com:9443", Target{"example.com", "9443"}},
		{"[::1]:8443", Target{"::1", "8443"}},
		{"::1", Target{"::1", "443"}},
	}
	for _, tt := range tests {
		got, err := ParseTarget(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseTarget(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}
	for _, bad := range []string{"", "http://example.com", "https://"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) succeeded, want an error", bad)
		}
	}
}

func TestScan(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	ok, err := ParseTarget(addr)
	if err != nil {
		t.Fatal(err)
	}
	// The httptest certificate covers 127.0.0.1 and example.com, but not localhost.
	wrongName := Target{Host: "localhost", Port: ok.Port}
	closed := Target{Host: "127.0.0.1", Port: "1"}

	certs, errs := Scanner{Timeout: 2 * time.Second, Concurrency: 2}.Scan(context.Background(), []Target{ok, wrongName, closed})

	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want 2 (errors: %+v)", len(certs), errs)
	}
	c := certs[0]
	if c.Source != model.SourceEndpoint || c.Location != ok.Address() {
		t.Errorf("source/location = %s %s, want endpoint %s", c.Source, c.Location, ok.Address())
	}
	if c.PubliclyTrusted {
		t.Error("httptest certificate reported as publicly trusted")
	}
	if c.Renewal != model.RenewalUnknown {
		t.Errorf("renewal = %s, want unknown", c.Renewal)
	}
	if len(c.Problems) != 0 {
		t.Errorf("problems = %v, want none", c.Problems)
	}
	if p := certs[1].Problems; len(p) != 1 || !strings.Contains(p[0], "localhost") {
		t.Errorf("problems for %s = %v, want a hostname mismatch", wrongName.Address(), p)
	}
	if len(errs) != 1 || errs[0].Location != closed.Address() {
		t.Errorf("errors = %+v, want one for %s", errs, closed.Address())
	}
}
