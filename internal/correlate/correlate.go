// Package correlate links certificates seen on endpoints to where they are stored.
package correlate

import (
	"net"
	"slices"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

// Link merges each endpoint certificate into every stored certificate (ACM, IAM,
// Kubernetes) with the same fingerprint: the endpoint becomes one of its users and its
// problems carry over, so the stored certificate's renewal status covers the endpoint.
// Endpoint certificates that match nothing are grouped: endpoints serving the same
// certificate become one entry that lists them all as users.
func Link(certs []model.Certificate) []model.Certificate {
	return groupEndpoints(linkStored(certs))
}

func linkStored(certs []model.Certificate) []model.Certificate {
	stored := map[string][]int{}
	for i, c := range certs {
		if c.Source != model.SourceEndpoint && c.Fingerprint != "" {
			stored[c.Fingerprint] = append(stored[c.Fingerprint], i)
		}
	}

	out := slices.Clone(certs)
	keep := make([]bool, len(certs))
	for i, c := range certs {
		matches := stored[c.Fingerprint]
		if c.Source != model.SourceEndpoint || len(matches) == 0 {
			keep[i] = true
			continue
		}
		for _, j := range matches {
			// Clip so appending never writes into a slice shared with the input.
			out[j].UsedBy = appendNew(slices.Clip(out[j].UsedBy), endpointName(c.Location))
			out[j].Problems = appendNew(slices.Clip(out[j].Problems), c.Problems...)
			out[j].Unused = false
		}
	}

	linked := out[:0]
	for i, c := range out {
		if keep[i] {
			linked = append(linked, c)
		}
	}
	return linked
}

// groupEndpoints merges endpoint certificates with the same fingerprint into the first
// one, which then lists every endpoint that serves it.
func groupEndpoints(certs []model.Certificate) []model.Certificate {
	first := map[string]int{} // fingerprint → index in out
	out := make([]model.Certificate, 0, len(certs))
	for _, c := range certs {
		if c.Source != model.SourceEndpoint || c.Fingerprint == "" {
			out = append(out, c)
			continue
		}
		i, ok := first[c.Fingerprint]
		if !ok {
			first[c.Fingerprint] = len(out)
			c.UsedBy = []string{endpointName(c.Location)}
			c.Problems = slices.Clone(c.Problems)
			out = append(out, c)
			continue
		}
		out[i].UsedBy = appendNew(out[i].UsedBy, endpointName(c.Location))
		out[i].Problems = appendNew(out[i].Problems, c.Problems...)
	}
	return out
}

// endpointName is "https://host", with the port only when it isn't 443.
func endpointName(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return "https://" + address
	}
	return "https://" + host
}

func appendNew(list []string, items ...string) []string {
	for _, it := range items {
		if !slices.Contains(list, it) {
			list = append(list, it)
		}
	}
	return list
}
