//go:build e2e

// Package e2e runs the real binary against a kind cluster prepared by setup.sh.
//
//	KUBE_CONTEXT=kind-<name> make e2e
package e2e

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type finding struct {
	Location    string   `json:"location"`
	Renewal     string   `json:"renewal"`
	RenewalNote string   `json:"renewalNote"`
	Severity    string   `json:"severity"`
	UsedBy      []string `json:"usedBy"`
	Action      string   `json:"action"`
	NotIssued   bool     `json:"notIssued"`
}

func TestKubernetesScan(t *testing.T) {
	kubeContext := os.Getenv("KUBE_CONTEXT")
	if !strings.HasPrefix(kubeContext, "kind-") {
		t.Skip("set KUBE_CONTEXT to a kind cluster prepared by test/e2e/setup.sh")
	}
	bin := filepath.Join(t.TempDir(), "certlapse")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/certlapse").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, "scan", "--kube-context", kubeContext, "-n", "demo", "-o", "json", "--fail-on", "critical")
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("exit = %v, want code 2 (a critical finding)\n%s", err, out)
	}

	var report struct {
		Findings []finding `json:"findings"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("parse report: %v\n%s", err, out)
	}
	bySecret := map[string]finding{}
	for _, f := range report.Findings {
		bySecret[f.Location[strings.LastIndex(f.Location, "/")+1:]] = f
	}

	tests := []struct {
		secret, renewal, note, usedBy string
	}{
		{"web-tls", "auto", "Certificate web (ClusterIssuer/selfsigned)", "ingress/demo/web"},
		{"stale-tls", "auto-failing", "Issuer/missing-ca, which isn't ready", ""},
		{"orphan-tls", "manual", "Certificate temp no longer exists", ""},
		{"manual-tls", "manual", "plain TLS secret", "gateway/demo/public"},
	}
	for _, tt := range tests {
		f, ok := bySecret[tt.secret]
		switch {
		case !ok:
			t.Errorf("%s: not in the report", tt.secret)
		case f.Renewal != tt.renewal || !strings.Contains(f.RenewalNote, tt.note):
			t.Errorf("%s: renewal %s (%q), want %s (%q)", tt.secret, f.Renewal, f.RenewalNote, tt.renewal, tt.note)
		case tt.usedBy != "" && !slices.Contains(f.UsedBy, tt.usedBy):
			t.Errorf("%s: used by %v, want %s", tt.secret, f.UsedBy, tt.usedBy)
		}
	}

	if f := bySecret["broken-tls"]; !f.NotIssued || f.Severity != "high" || !strings.Contains(f.RenewalNote, "isn't ready") {
		t.Errorf("broken-tls: %+v, want a high never-issued finding", f)
	}
}
