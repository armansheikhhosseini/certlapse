// Package endpoint reads the certificates that live TLS endpoints present.
package endpoint

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/armansheikhhosseini/certlapse/internal/certinfo"
	"github.com/armansheikhhosseini/certlapse/internal/model"
)

// Target is a host and port to connect to.
type Target struct {
	Host string
	Port string
}

func (t Target) Address() string { return net.JoinHostPort(t.Host, t.Port) }

// ParseTarget accepts "host", "host:port" or "https://host[:port][/path]". The port defaults to 443.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, errors.New("empty target")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return Target{}, fmt.Errorf("parse %q: %w", s, err)
		}
		if u.Scheme != "https" {
			return Target{}, fmt.Errorf("%q: only https:// URLs are supported", s)
		}
		if u.Hostname() == "" {
			return Target{}, fmt.Errorf("%q: no host", s)
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		return Target{Host: u.Hostname(), Port: port}, nil
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		return Target{Host: host, Port: port}, nil
	}
	return Target{Host: strings.Trim(s, "[]"), Port: "443"}, nil
}

// Scanner connects to endpoints in parallel.
type Scanner struct {
	Timeout     time.Duration
	Concurrency int
}

// Scan returns the certificate each target presents, in the order of targets, and the targets it couldn't read.
func (s Scanner) Scan(ctx context.Context, targets []Target) ([]model.Certificate, []model.ScanError) {
	type result struct {
		cert model.Certificate
		err  error
	}
	results := make([]result, len(targets))
	sem := make(chan struct{}, max(1, s.Concurrency))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i].cert, results[i].err = s.scanOne(ctx, t)
		}()
	}
	wg.Wait()

	var certs []model.Certificate
	var errs []model.ScanError
	for i, r := range results {
		if r.err != nil {
			errs = append(errs, model.ScanError{Source: model.SourceEndpoint, Location: targets[i].Address(), Err: r.err.Error()})
			continue
		}
		certs = append(certs, r.cert)
	}
	return certs, errs
}

func (s Scanner) scanOne(ctx context.Context, t Target) (model.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{
		ServerName: t.Host,
		// The handshake has to succeed for expired, self-signed and mismatched
		// certificates too, so they can be reported. Trust is checked separately.
		InsecureSkipVerify: true, //nolint:gosec // inspection only, no data is sent
	}}
	conn, err := d.DialContext(ctx, "tcp", t.Address())
	if err != nil {
		return model.Certificate{}, err
	}
	defer conn.Close()

	peers := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return model.Certificate{}, errors.New("no certificate presented")
	}
	leaf := peers[0]
	c := certinfo.Record(model.SourceEndpoint, t.Address(), leaf, peers[1:])
	if err := leaf.VerifyHostname(t.Host); err != nil {
		c.Problems = append(c.Problems, "certificate doesn't cover "+t.Host)
	}
	c.RenewalNote = issuerHint(c.Issuer)
	return c, nil
}

// issuerHint says what the issuer suggests about renewal. It is a hint only:
// the endpoint alone can't show who renews the certificate.
func issuerHint(issuer string) string {
	switch i := strings.ToLower(issuer); {
	case strings.Contains(i, "let's encrypt"), strings.Contains(i, "zerossl"),
		strings.Contains(i, "google trust services"), strings.Contains(i, "buypass"):
		return "ACME issuer, so probably renewed automatically"
	case strings.Contains(i, "amazon"):
		return "issued by ACM, so probably renewed automatically if it's an ACM-issued certificate in use"
	default:
		return ""
	}
}
