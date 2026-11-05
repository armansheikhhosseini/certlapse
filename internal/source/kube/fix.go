package kube

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

// certificateFix is a cert-manager Certificate that takes over renewing a TLS secret
// nothing renews. It is nil for certificates a public ACME CA can't replace.
func (s *Scanner) certificateFix(st certManagerState, sec corev1.Secret, c model.Certificate) *model.Fix {
	if !c.PubliclyTrusted || len(c.DNSNames) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# cert-manager issues a new certificate into %s/%s and renews it from then on.\n", sec.Namespace, sec.Name)
	b.WriteString("# The Ingresses and Gateways that use the secret keep working.\n")

	// No issuer has this name, so the Certificate can't issue until someone picks one.
	kind, issuer := "ClusterIssuer", "<your-acme-issuer>"
	key, is, found := st.suggestIssuer(sec.Namespace, c.RenewingCA)
	switch {
	case st.certificates == nil && st.known:
		b.WriteString("# cert-manager isn't installed in this cluster: install it first (https://cert-manager.io/docs/installation/),\n")
		b.WriteString("# then create an ACME issuer (https://cert-manager.io/docs/configuration/acme/) and put its name below.\n")
	case !found:
		b.WriteString("# No ready ACME issuer for a public CA was found: create one first\n")
		b.WriteString("# (https://cert-manager.io/docs/configuration/acme/) and put its name below.\n")
	default:
		parts := strings.Split(key, "/")
		kind, issuer = parts[0], parts[len(parts)-1]
		if !is.dns01 && slices.ContainsFunc(c.DNSNames, func(n string) bool { return strings.HasPrefix(n, "*.") }) {
			fmt.Fprintf(&b, "# Wildcard names need a DNS-01 solver, and %s has none: add one to it first.\n", key)
		}
	}

	name := sec.Annotations[certificateNameAnnotation] // recreate a deleted Certificate under its old name
	if name == "" {
		name = strings.TrimSuffix(sec.Name, "-tls")
		if st.certificateNamed(sec.Namespace, name) {
			name = sec.Name
		}
	}
	fmt.Fprintf(&b, "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  secretName: %s\n  dnsNames:\n",
		name, sec.Namespace, sec.Name)
	for _, n := range c.DNSNames {
		fmt.Fprintf(&b, "    - %s\n", strconv.Quote(n))
	}
	fmt.Fprintf(&b, "  issuerRef:\n    kind: %s\n    name: %s\n", kind, issuer)
	return &model.Fix{
		Title: fmt.Sprintf("Let cert-manager renew it: kubectl --context %s apply -f certificate.yaml", s.Cluster),
		Lang:  "yaml",
		Text:  b.String(),
	}
}

// suggestIssuer picks a ready issuer for a public CA that a Certificate in namespace can
// use: one for the CA that issued the current certificate if there is one, and a
// ClusterIssuer before a namespaced Issuer.
func (st certManagerState) suggestIssuer(namespace string, current *model.CA) (string, issuerState, bool) {
	var best string
	rank := func(key string) int {
		r := 0
		if st.issuers[key].ca == current {
			r += 2
		}
		if strings.HasPrefix(key, "ClusterIssuer/") {
			r++
		}
		return r
	}
	for _, key := range slices.Sorted(maps.Keys(st.issuers)) {
		is := st.issuers[key]
		if !is.ready || is.ca == nil || is.staging {
			continue
		}
		if !strings.HasPrefix(key, "ClusterIssuer/") && !strings.HasPrefix(key, "Issuer/"+namespace+"/") {
			continue
		}
		if best == "" || rank(key) > rank(best) {
			best = key
		}
	}
	return best, st.issuers[best], best != ""
}

func (st certManagerState) certificateNamed(namespace, name string) bool {
	for key, cm := range st.certificates {
		if cm.name == name && strings.HasPrefix(key, namespace+"/") {
			return true
		}
	}
	return false
}

// hasDNS01Solver reports whether an ACME issuer can solve DNS-01 challenges.
func hasDNS01Solver(u unstructured.Unstructured) bool {
	solvers, _, _ := unstructured.NestedSlice(u.Object, "spec", "acme", "solvers")
	for _, s := range solvers {
		if solver, ok := s.(map[string]any); ok && solver["dns01"] != nil {
			return true
		}
	}
	return false
}
