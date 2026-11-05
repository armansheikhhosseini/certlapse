// Package certinfo turns parsed X.509 certificates into inventory records.
package certinfo

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/armansheikhhosseini/certlapse/internal/ca"
	"github.com/armansheikhhosseini/certlapse/internal/model"
)

// Record describes leaf, found at location in source. intermediates is the rest of the
// chain as presented or stored, used to decide whether the leaf is publicly trusted.
func Record(source, location string, leaf *x509.Certificate, intermediates []*x509.Certificate) model.Certificate {
	sum := sha256.Sum256(leaf.Raw)
	c := model.Certificate{
		Source:          source,
		Location:        location,
		Subject:         leaf.Subject.CommonName,
		DNSNames:        leaf.DNSNames,
		Issuer:          issuerName(leaf),
		Serial:          leaf.SerialNumber.Text(16),
		Fingerprint:     hex.EncodeToString(sum[:]),
		NotBefore:       leaf.NotBefore,
		NotAfter:        leaf.NotAfter,
		KeyAlgorithm:    KeyAlgorithm(leaf),
		PubliclyTrusted: PubliclyTrusted(leaf, intermediates),
		Renewal:         model.RenewalUnknown,
	}
	if c.PubliclyTrusted {
		// Until a source knows better, the replacement is assumed to come from the same CA.
		c.RenewingCA = ca.ByOrganization(leaf.Issuer.Organization)
	}
	return c
}

// ParsePEMChain reads every certificate in PEM data, leaf first.
func ParsePEMChain(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, errors.New("no certificate in PEM data")
	}
	return chain, nil
}

// KeyAlgorithm names the public key type and size, e.g. RSA-2048 or ECDSA-P-256.
func KeyAlgorithm(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

var systemRoots = sync.OnceValues(x509.SystemCertPool)

// PubliclyTrusted reports whether leaf chains to a root the operating system trusts.
// Expiry is ignored on purpose: the chain is checked at the middle of the leaf's
// validity, so an expired public certificate still counts as public.
func PubliclyTrusted(leaf *x509.Certificate, intermediates []*x509.Certificate) bool {
	roots, err := systemRoots()
	if err != nil || roots == nil {
		return false
	}
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		CurrentTime:   leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// issuerName is the issuing CA's common name with its organisation, e.g. "R10 (Let's Encrypt)".
func issuerName(c *x509.Certificate) string {
	cn := c.Issuer.CommonName
	org := strings.Join(c.Issuer.Organization, ", ")
	switch {
	case cn == "":
		return org
	case org == "" || org == cn:
		return cn
	default:
		return cn + " (" + org + ")"
	}
}
