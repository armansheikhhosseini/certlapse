// Package model defines the records every scanner produces and the report consumes.
package model

import (
	"fmt"
	"strings"
	"time"
)

// Sources a certificate can be found in.
const (
	SourceEndpoint   = "endpoint"
	SourceKubernetes = "kubernetes"
	SourceACM        = "acm"
	SourceIAM        = "iam"
)

// Renewal says whether a certificate gets replaced without a human.
type Renewal string

const (
	RenewalAuto        Renewal = "auto"
	RenewalAutoFailing Renewal = "auto-failing"
	RenewalManual      Renewal = "manual"
	RenewalUnknown     Renewal = "unknown"
)

// Certificate is one certificate found in one place.
type Certificate struct {
	Source          string    `json:"source"`
	Location        string    `json:"location"`
	Subject         string    `json:"subject"`
	DNSNames        []string  `json:"dnsNames,omitempty"`
	Issuer          string    `json:"issuer"`
	Serial          string    `json:"serial"`
	Fingerprint     string    `json:"sha256"`
	NotBefore       time.Time `json:"notBefore"`
	NotAfter        time.Time `json:"notAfter"`
	KeyAlgorithm    string    `json:"keyAlgorithm"`
	PubliclyTrusted bool      `json:"publiclyTrusted"`
	Renewal         Renewal   `json:"renewal"`
	RenewalNote     string    `json:"renewalNote,omitempty"`
	UsedBy          []string  `json:"usedBy,omitempty"`
	// Unused is set only by sources that can tell nothing uses the certificate (ACM, IAM).
	Unused bool `json:"unused,omitempty"`
	// NotIssued marks a certificate that was requested but never issued, so it has no
	// validity dates (a cert-manager Certificate without a secret).
	NotIssued bool     `json:"notIssued,omitempty"`
	Problems  []string `json:"problems,omitempty"`
	// Fixes are ready-made changes that make the certificate renew, or keep it renewing.
	Fixes []Fix `json:"fixes,omitempty"`

	// What the next issuance depends on, for the checks that predict a failing renewal.
	// RenewingCA is the CA expected to issue the replacement: the one configured to renew
	// it, or else the one that issued it. ValidationCNAMEs are DNS records the CA looks up
	// to revalidate the domains (ACM DNS validation).
	RenewingCA       *CA     `json:"-"`
	ValidationCNAMEs []CNAME `json:"-"`
}

// Fix is a change to make: a manifest, commands or DNS records.
type Fix struct {
	Title string `json:"title"`
	Lang  string `json:"lang"` // yaml, sh or dns
	Text  string `json:"text"`
}

// CA is a public certificate authority and the domains that name it in CAA records.
type CA struct {
	Name       string
	CAADomains []string
}

// CNAME is a DNS record a certificate authority expects to find.
type CNAME struct {
	Name, Value string
}

// Name is the most recognisable name of the certificate: its first DNS name, or its subject.
func (c Certificate) Name() string {
	switch {
	case len(c.DNSNames) > 1:
		return fmt.Sprintf("%s (+%d)", c.DNSNames[0], len(c.DNSNames)-1)
	case len(c.DNSNames) == 1:
		return c.DNSNames[0]
	case c.Subject != "":
		return c.Subject
	default:
		return "(no name)"
	}
}

// Severity orders findings from harmless to urgent.
type Severity int

const (
	SeverityOK Severity = iota
	SeverityInfo
	SeverityWarning
	SeverityHigh
	SeverityCritical
)

var severityNames = []string{"ok", "info", "warning", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity reads a severity name, case-insensitively.
func ParseSeverity(name string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(name, n) {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want one of %s)", name, strings.Join(severityNames, ", "))
}

// Finding is a certificate plus the verdict on it.
type Finding struct {
	Certificate
	Severity Severity `json:"severity"`
	DaysLeft int      `json:"daysLeft"`
	Action   string   `json:"action,omitempty"`
}

// ScanError is a place that could not be scanned.
type ScanError struct {
	Source   string `json:"source"`
	Location string `json:"location"`
	Err      string `json:"error"`
}
