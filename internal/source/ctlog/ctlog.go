// Package ctlog finds hostnames under a domain in Certificate Transparency logs, through
// crt.sh. Every publicly trusted certificate is logged, so this finds hosts nobody listed.
package ctlog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// DefaultBaseURL is crt.sh's search endpoint.
const DefaultBaseURL = "https://crt.sh/"

// UserAgent identifies the tool to crt.sh.
const UserAgent = "certlapse (+https://github.com/armansheikhhosseini/certlapse)"

// Client queries crt.sh. The zero value is ready to use.
type Client struct {
	BaseURL string        // defaults to DefaultBaseURL
	HTTP    *http.Client  // defaults to a client with a 90 s timeout; crt.sh can be slow
	Retries int           // extra attempts after a 5xx or network error; defaults to 2
	Backoff time.Duration // wait before the first retry, doubled after; defaults to 2 s
}

// Hostnames returns the hostnames under domain (and domain itself) that appear in a
// certificate that hasn't expired, sorted. Wildcard names can't be connected to and are
// left out; wildcards counts them.
func (c Client) Hostnames(ctx context.Context, domain string) (names []string, wildcards int, err error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" || strings.ContainsAny(domain, "%*/ ") {
		return nil, 0, fmt.Errorf("invalid domain %q", domain)
	}
	entries, err := c.search(ctx, "%."+domain)
	if err != nil {
		return nil, 0, err
	}

	seen := map[string]bool{domain: true}
	for _, e := range entries {
		for _, n := range strings.Split(e.NameValue, "\n") {
			n = strings.ToLower(strings.TrimSpace(n))
			switch {
			case n == "" || seen[n]:
			case n != domain && !strings.HasSuffix(n, "."+domain):
				// another domain listed on the same certificate
			case strings.HasPrefix(n, "*."):
				seen[n] = true
				wildcards++
			default:
				seen[n] = true
			}
		}
	}
	for n := range seen {
		if !strings.HasPrefix(n, "*.") {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names, wildcards, nil
}

type entry struct {
	NameValue string `json:"name_value"`
}

func (c Client) search(ctx context.Context, query string) ([]entry, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 90 * time.Second}
	}
	retries := c.Retries
	if retries == 0 {
		retries = 2
	}
	backoff := c.Backoff
	if backoff == 0 {
		backoff = 2 * time.Second
	}
	u := base + "?" + url.Values{"q": {query}, "output": {"json"}, "exclude": {"expired"}}.Encode()

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
		entries, retry, err := c.get(ctx, httpClient, u)
		if err == nil {
			return entries, nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	return nil, fmt.Errorf("crt.sh: %w", lastErr)
}

// get makes one request. retry says whether trying again could help.
func (c Client) get(ctx context.Context, httpClient *http.Client, u string) ([]entry, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	// crt.sh turns away Go's default User-Agent.
	req.Header.Set("User-Agent", UserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, ctx.Err() == nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests, fmt.Errorf("HTTP %s", resp.Status)
	}
	var entries []entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, true, fmt.Errorf("decode response: %w", err)
	}
	return entries, false, nil
}
