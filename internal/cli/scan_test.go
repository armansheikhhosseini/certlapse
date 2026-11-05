package cli

import (
	"strings"
	"testing"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

func TestSummarizeUnreachable(t *testing.T) {
	errs := []model.ScanError{
		{Source: model.SourceEndpoint, Location: "listed.example.com:443", Err: "connection refused"},
		{Source: model.SourceEndpoint, Location: "old1.example.com:443", Err: "no such host"},
		{Source: model.SourceEndpoint, Location: "old2.example.com:443", Err: "i/o timeout"},
	}
	discovered := map[string]bool{"old1.example.com:443": true, "old2.example.com:443": true}

	got := summarizeUnreachable(errs, discovered)

	if len(got) != 2 || got[0].Location != "listed.example.com:443" {
		t.Fatalf("got %+v, want the listed endpoint's error kept and one summary", got)
	}
	if s := got[1]; s.Location != "2 discovered hostname(s)" || !strings.Contains(s.Err, "old1.example.com, old2.example.com") {
		t.Errorf("summary = %+v", s)
	}
}
