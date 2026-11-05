// Package preflight predicts renewal failures before they happen, by checking now the
// DNS records a certificate authority checks when it issues the replacement: CAA records,
// which say which CAs may issue for a domain, and ACM's DNS validation records.
package preflight

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

// Lookup returns the answer records of type qtype for name. A name that doesn't exist
// gives an empty answer, not an error.
type Lookup func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error)

// NewResolver returns a Lookup that asks server (host or host:port), or the first
// resolver in /etc/resolv.conf when server is empty.
func NewResolver(server string, timeout time.Duration) (Lookup, error) {
	if server == "" {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, fmt.Errorf("find the system DNS resolver: %w", err)
		}
		if len(conf.Servers) == 0 {
			return nil, fmt.Errorf("find the system DNS resolver: none in /etc/resolv.conf")
		}
		server = net.JoinHostPort(conf.Servers[0], conf.Port)
	} else if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	udp := &dns.Client{Timeout: timeout}
	tcp := &dns.Client{Net: "tcp", Timeout: timeout}
	return func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		m.SetEdns0(4096, false)
		r, _, err := udp.ExchangeContext(ctx, m, server)
		if err == nil && r.Truncated {
			r, _, err = tcp.ExchangeContext(ctx, m, server)
		}
		if err != nil {
			return nil, err
		}
		switch r.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			return r.Answer, nil
		}
		return nil, fmt.Errorf("%s lookup: %s", dns.TypeToString[qtype], dns.RcodeToString[r.Rcode])
	}, nil
}

// Checker runs the checks.
type Checker struct {
	Lookup      Lookup
	Concurrency int // certificates checked at the same time; 0 means 10
}

// Check adds a problem to every certificate whose next issuance DNS would block, and
// returns the lookups that failed. Expired and unused certificates aren't checked:
// nothing is going to renew them.
func (c Checker) Check(ctx context.Context, certs []model.Certificate, now time.Time) ([]model.Certificate, []model.ScanError) {
	cache := &cache{lookup: c.Lookup, answers: map[query]*answer{}}
	out := slices.Clone(certs)
	limit := c.Concurrency
	if limit <= 0 {
		limit = 10
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := range out {
		cert := &out[i]
		if cert.Unused || (!cert.NotIssued && cert.NotAfter.Before(now)) {
			continue
		}
		if cert.RenewingCA == nil && len(cert.ValidationCNAMEs) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			problems, fixes := cache.validationProblems(ctx, cert.ValidationCNAMEs)
			if cert.RenewingCA != nil {
				p, f := cache.caaProblems(ctx, cert.RenewingCA, names(*cert))
				problems, fixes = append(problems, p...), append(fixes, f...)
			}
			cert.Problems = append(slices.Clip(cert.Problems), problems...)
			cert.Fixes = append(slices.Clip(cert.Fixes), fixes...)
		}()
	}
	wg.Wait()
	return out, cache.errors()
}

func names(c model.Certificate) []string {
	if len(c.DNSNames) > 0 {
		return c.DNSNames
	}
	if c.Subject != "" && strings.Contains(c.Subject, ".") {
		return []string{c.Subject}
	}
	return nil
}

// validationProblems checks that each ACM validation CNAME still points where ACM
// expects, and gives the records to restore.
func (c *cache) validationProblems(ctx context.Context, records []model.CNAME) ([]string, []model.Fix) {
	var problems, restore []string
	for _, rec := range records {
		rrs, err := c.get(ctx, rec.Name, dns.TypeCNAME)
		if err != nil {
			continue
		}
		var target string
		for _, rr := range rrs {
			if cn, ok := rr.(*dns.CNAME); ok && sameName(cn.Hdr.Name, rec.Name) {
				target = cn.Target
				break
			}
		}
		if target != "" && sameName(target, rec.Value) {
			continue
		}
		restore = append(restore, fmt.Sprintf("%s CNAME %s", dns.Fqdn(rec.Name), dns.Fqdn(rec.Value)))
		if target == "" {
			problems = append(problems, fmt.Sprintf("renewal will fail: ACM's validation record %s is missing from DNS (add it back: CNAME %s)",
				trimDot(rec.Name), trimDot(rec.Value)))
		} else {
			problems = append(problems, fmt.Sprintf("renewal will fail: ACM's validation record %s points to %s, not %s",
				trimDot(rec.Name), trimDot(target), trimDot(rec.Value)))
		}
	}
	if len(restore) == 0 {
		return problems, nil
	}
	return problems, []model.Fix{{
		Title: "Restore ACM's validation records",
		Lang:  "dns",
		Text:  "; ACM looks these up at every renewal. Replace any record with the same name.\n" + strings.Join(restore, "\n") + "\n",
	}}
}

// caaProblems checks that CAA records let ca issue for every name, and gives the records
// that would. Names blocked by the same records are reported together.
func (c *cache) caaProblems(ctx context.Context, ca *model.CA, dnsNames []string) ([]string, []model.Fix) {
	var order, add []string
	blocked := map[string][]string{} // reason -> names
	for _, n := range dnsNames {
		wildcard := strings.HasPrefix(n, "*.")
		owner, set, err := c.relevantCAA(ctx, strings.TrimPrefix(n, "*."))
		if err != nil || len(set) == 0 {
			continue
		}
		reason, tag := refusal(set, ca, wildcard)
		if reason == "" {
			continue
		}
		if tag != "" {
			if rec := fmt.Sprintf("%s CAA 0 %s %q", dns.Fqdn(owner), tag, ca.CAADomains[0]); !slices.Contains(add, rec) {
				add = append(add, rec)
			}
		}
		reason = fmt.Sprintf("CAA on %s %s", owner, reason)
		if _, ok := blocked[reason]; !ok {
			order = append(order, reason)
		}
		blocked[reason] = append(blocked[reason], n)
	}
	problems := make([]string, 0, len(order))
	for _, reason := range order {
		problems = append(problems, fmt.Sprintf("renewal will fail: %s can't issue for %s (%s)",
			ca.Name, strings.Join(blocked[reason], ", "), reason))
	}
	if len(add) == 0 {
		return problems, nil
	}
	return problems, []model.Fix{{
		Title: "Allow " + ca.Name + " in CAA",
		Lang:  "dns",
		Text:  "; Add next to the existing CAA records; the CAs they allow stay allowed.\n" + strings.Join(add, "\n") + "\n",
	}}
}

// relevantCAA finds the CAA records that govern name: its own, or those of the closest
// parent that has any (RFC 8659). The resolver follows CNAMEs of the name it's asked.
func (c *cache) relevantCAA(ctx context.Context, name string) (string, []*dns.CAA, error) {
	labels := dns.SplitDomainName(name)
	for i := range labels {
		owner := strings.Join(labels[i:], ".")
		rrs, err := c.get(ctx, owner, dns.TypeCAA)
		if err != nil {
			return "", nil, err
		}
		var set []*dns.CAA
		for _, rr := range rrs {
			if caa, ok := rr.(*dns.CAA); ok {
				set = append(set, caa)
			}
		}
		if len(set) > 0 {
			return owner, set, nil
		}
	}
	return "", nil, nil
}

// knownTags are CAA properties CAs understand; an unknown one marked critical stops
// every CA from issuing.
var knownTags = []string{"issue", "issuewild", "iodef", "contactemail", "contactphone", "issuemail", "issuevmc"}

// refusal says why set doesn't let ca issue, or returns "" if it does. tag is the
// property a record allowing ca would need, or "" if no record would help.
func refusal(set []*dns.CAA, ca *model.CA, wildcard bool) (reason, tag string) {
	tag = "issue"
	for _, r := range set {
		t := strings.ToLower(r.Tag)
		if r.Flag&128 != 0 && !slices.Contains(knownTags, t) {
			return fmt.Sprintf("has a critical %q property no CA understands", r.Tag), ""
		}
		if wildcard && t == "issuewild" {
			tag = "issuewild" // for wildcard names, issuewild replaces issue
		}
	}
	var allowed []string
	present := false
	for _, r := range set {
		if strings.ToLower(r.Tag) != tag {
			continue
		}
		present = true
		domain, _, _ := strings.Cut(r.Value, ";")
		domain = strings.ToLower(strings.TrimSpace(domain))
		if slices.Contains(ca.CAADomains, domain) {
			return "", ""
		}
		if domain != "" && !slices.Contains(allowed, domain) {
			allowed = append(allowed, domain)
		}
	}
	switch {
	case !present:
		return "", "" // no issue properties: any CA may issue
	case len(allowed) == 0:
		return "allows no CA to issue", tag
	}
	kind := ""
	if tag == "issuewild" {
		kind = " for wildcards"
	}
	return fmt.Sprintf("only allows %s%s", strings.Join(allowed, ", "), kind), tag
}

type query struct {
	name  string
	qtype uint16
}

type answer struct {
	once sync.Once
	rrs  []dns.RR
	err  error
}

// cache makes each lookup once, however many certificates need it.
type cache struct {
	lookup  Lookup
	mu      sync.Mutex
	answers map[query]*answer
}

func (c *cache) get(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	q := query{strings.ToLower(dns.Fqdn(name)), qtype}
	c.mu.Lock()
	a := c.answers[q]
	if a == nil {
		a = &answer{}
		c.answers[q] = a
	}
	c.mu.Unlock()
	a.once.Do(func() { a.rrs, a.err = c.lookup(ctx, q.name, qtype) })
	return a.rrs, a.err
}

// errors returns one scan error per failed lookup, in a stable order.
func (c *cache) errors() []model.ScanError {
	c.mu.Lock()
	defer c.mu.Unlock()
	var errs []model.ScanError
	for q, a := range c.answers {
		if a.err != nil {
			errs = append(errs, model.ScanError{Source: "dns", Location: dns.TypeToString[q.qtype] + " " + trimDot(q.name), Err: a.err.Error()})
		}
	}
	slices.SortFunc(errs, func(a, b model.ScanError) int { return strings.Compare(a.Location, b.Location) })
	return errs
}

func sameName(a, b string) bool { return strings.EqualFold(dns.Fqdn(a), dns.Fqdn(b)) }

func trimDot(name string) string { return strings.TrimSuffix(name, ".") }
