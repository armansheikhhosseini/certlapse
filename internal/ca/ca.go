// Package ca identifies public certificate authorities and the domains that authorise
// them in CAA records.
package ca

import (
	"net/url"
	"strings"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

var (
	Amazon = &model.CA{Name: "Amazon", CAADomains: []string{"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"}}

	letsEncrypt = &model.CA{Name: "Let's Encrypt", CAADomains: []string{"letsencrypt.org"}}
	google      = &model.CA{Name: "Google Trust Services", CAADomains: []string{"pki.goog"}}
	zeroSSL     = &model.CA{Name: "ZeroSSL", CAADomains: []string{"sectigo.com", "zerossl.com"}}
	sectigo     = &model.CA{Name: "Sectigo", CAADomains: []string{"sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"}}
	digiCert    = &model.CA{Name: "DigiCert", CAADomains: []string{"digicert.com", "symantec.com", "geotrust.com", "rapidssl.com", "thawte.com", "digitalcertvalidation.com"}}
	globalSign  = &model.CA{Name: "GlobalSign", CAADomains: []string{"globalsign.com"}}
	goDaddy     = &model.CA{Name: "GoDaddy", CAADomains: []string{"godaddy.com", "starfieldtech.com"}}
	sslCom      = &model.CA{Name: "SSL.com", CAADomains: []string{"ssl.com"}}
)

// byOrganization matches a fragment of the issuer's organization name. ZeroSSL comes
// before Sectigo, which operates it.
var byOrganization = []struct {
	fragment string
	ca       *model.CA
}{
	{"let's encrypt", letsEncrypt},
	{"amazon", Amazon},
	{"google trust services", google},
	{"zerossl", zeroSSL},
	{"sectigo", sectigo},
	{"digicert", digiCert},
	{"globalsign", globalSign},
	{"godaddy", goDaddy},
	{"starfield", goDaddy},
	{"ssl corporation", sslCom},
}

// ByOrganization returns the CA an issuer's organization names, or nil if it's not one
// this package knows.
func ByOrganization(orgs []string) *model.CA {
	for _, org := range orgs {
		org = strings.ToLower(org)
		for _, o := range byOrganization {
			if strings.Contains(org, o.fragment) {
				return o.ca
			}
		}
	}
	return nil
}

var byACMEHost = map[string]*model.CA{
	"acme-v02.api.letsencrypt.org":         letsEncrypt,
	"acme-staging-v02.api.letsencrypt.org": letsEncrypt,
	"dv.acme-v02.api.pki.goog":             google,
	"dv.acme-v02.test-api.pki.goog":        google,
	"acme.zerossl.com":                     zeroSSL,
	"acme.sectigo.com":                     sectigo,
	"acme.digicert.com":                    digiCert,
	"acme.ssl.com":                         sslCom,
}

// ByACMEServer returns the CA behind an ACME directory URL, or nil if it's not one this
// package knows.
func ByACMEServer(server string) *model.CA {
	u, err := url.Parse(server)
	if err != nil {
		return nil
	}
	return byACMEHost[strings.ToLower(u.Hostname())]
}
