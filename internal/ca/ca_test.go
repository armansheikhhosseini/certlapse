package ca

import "testing"

func TestByOrganization(t *testing.T) {
	for org, want := range map[string]string{
		"Let's Encrypt":         "Let's Encrypt",
		"Amazon":                "Amazon",
		"Google Trust Services": "Google Trust Services",
		"ZeroSSL":               "ZeroSSL",
		"Sectigo Limited":       "Sectigo",
		"DigiCert Inc":          "DigiCert",
		"Example Private CA":    "",
	} {
		got := ByOrganization([]string{org})
		if (got == nil && want != "") || (got != nil && got.Name != want) {
			t.Errorf("ByOrganization(%q) = %v, want %q", org, got, want)
		}
	}
}

func TestByACMEServer(t *testing.T) {
	for server, want := range map[string]string{
		"https://acme-v02.api.letsencrypt.org/directory":         "Let's Encrypt",
		"https://acme-staging-v02.api.letsencrypt.org/directory": "Let's Encrypt",
		"https://dv.acme-v02.api.pki.goog/directory":             "Google Trust Services",
		"https://acme.zerossl.com/v2/DV90":                       "ZeroSSL",
		"https://step-ca.internal/acme/acme/directory":           "",
		"": "",
	} {
		got := ByACMEServer(server)
		if (got == nil && want != "") || (got != nil && got.Name != want) {
			t.Errorf("ByACMEServer(%q) = %v, want %q", server, got, want)
		}
	}
}
