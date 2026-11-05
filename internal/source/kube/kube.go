// Package kube reads TLS certificates from Kubernetes secrets and links them to the
// cert-manager Certificates that renew them and the Ingresses and Gateways that use them.
// It only lists and reads.
package kube

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/armansheikhhosseini/certlapse/internal/ca"
	"github.com/armansheikhhosseini/certlapse/internal/certinfo"
	"github.com/armansheikhhosseini/certlapse/internal/model"
)

var (
	certificateGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	gatewayGVR     = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
)

// certificateNameAnnotation is set by cert-manager on the secrets it writes.
const certificateNameAnnotation = "cert-manager.io/certificate-name"

// Scanner reads one cluster.
type Scanner struct {
	Cluster   string // shown in locations, usually the kube context name
	Namespace string // empty for all namespaces
	core      kubernetes.Interface
	dynamic   dynamic.Interface
}

// New connects to the cluster of kubeContext in kubeconfig. Empty values mean the
// defaults kubectl would use; with no context given and none current, it fails rather
// than guess.
func New(kubeconfig, kubeContext, namespace string) (*Scanner, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: kubeContext})
	raw, err := cc.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig: %w", err)
	}
	name := kubeContext
	if name == "" {
		name = raw.CurrentContext
	}
	if name == "" {
		return nil, errors.New("no current kube context: use --kube-context")
	}
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kube context %s: %w", name, err)
	}
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Scanner{Cluster: name, Namespace: namespace, core: core, dynamic: dyn}, nil
}

// Scan returns the certificate in every TLS secret, and the places it couldn't read.
func (s *Scanner) Scan(ctx context.Context) ([]model.Certificate, []model.ScanError) {
	secrets, err := s.core.CoreV1().Secrets(s.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "type=" + string(corev1.SecretTypeTLS),
	})
	if err != nil {
		return nil, []model.ScanError{s.scanError(s.Cluster, fmt.Errorf("list TLS secrets: %w", err))}
	}

	cm, errs := s.certManager(ctx)
	users, userErrs := s.secretUsers(ctx)
	errs = append(errs, userErrs...)
	now := time.Now()

	certs := make([]model.Certificate, 0, len(secrets.Items))
	seen := map[string]bool{}
	for _, sec := range secrets.Items {
		if sec.Type != corev1.SecretTypeTLS {
			continue // in case the API server ignored the field selector
		}
		key := sec.Namespace + "/" + sec.Name
		seen[key] = true
		location := s.Cluster + ":" + key
		chain, err := certinfo.ParsePEMChain(sec.Data[corev1.TLSCertKey])
		if err != nil {
			errs = append(errs, s.scanError(location, fmt.Errorf("tls.crt: %w", err)))
			continue
		}
		c := certinfo.Record(model.SourceKubernetes, location, chain[0], chain[1:])
		c.Renewal, c.RenewalNote = cm.renewal(sec, now)
		c.UsedBy = users[key]
		if c.Renewal == model.RenewalManual {
			if fix := s.certificateFix(cm, sec, c); fix != nil {
				c.Fixes = append(c.Fixes, *fix)
			}
		}
		if renewer, ok := cm.renewingCA(cm.certificates[key]); ok {
			c.RenewingCA = renewer
		}
		certs = append(certs, c)
	}
	return append(certs, s.notIssued(cm, seen, users, now)...), errs
}

// notIssued reports cert-manager Certificates that have no secret because issuing them
// is stuck. Certificates whose first issuance may still be in progress are left out.
func (s *Scanner) notIssued(st certManagerState, seen map[string]bool, users map[string][]string, now time.Time) []model.Certificate {
	var out []model.Certificate
	for _, key := range slices.Sorted(maps.Keys(st.certificates)) {
		cm := st.certificates[key]
		if seen[key] {
			continue
		}
		problem, stuck := st.problem(cm, now)
		if !stuck {
			continue
		}
		c := model.Certificate{
			Source:      model.SourceKubernetes,
			Location:    s.Cluster + ":" + key,
			DNSNames:    cm.dnsNames,
			Renewal:     model.RenewalAutoFailing,
			RenewalNote: "cert-manager Certificate " + cm.name + " " + problem,
			NotIssued:   true,
			UsedBy:      users[key],
		}
		if len(cm.dnsNames) > 0 {
			c.Subject = cm.dnsNames[0]
		}
		c.RenewingCA, _ = st.renewingCA(cm)
		out = append(out, c)
	}
	return out
}

// certManagerState is what the cluster's cert-manager knows.
type certManagerState struct {
	// known is false when Certificates exist but couldn't be read. It is true when
	// cert-manager isn't installed.
	known        bool
	certificates map[string]*cmCertificate // by "namespace/secretName"
	// issuers maps "Issuer/namespace/name" and "ClusterIssuer/name" to their state.
	// It is nil when they couldn't be read, and then issuers aren't checked.
	issuers map[string]issuerState
}

// cmCertificate is what matters about a cert-manager Certificate.
type cmCertificate struct {
	name           string
	dnsNames       []string
	issuer         string // "Kind/name", for display
	issuerKey      string // key into certManagerState.issuers; empty for external issuers
	ready          bool
	readyMessage   string
	lastFailure    string
	failureMessage string
	issuingSince   time.Time // when the Issuing condition turned True; zero if not issuing
	renewalTime    time.Time // when cert-manager plans to renew; zero if unknown
}

type issuerState struct {
	ready   bool
	message string
	ca      *model.CA // the public CA behind an ACME issuer; nil for others
	staging bool      // the CA's test endpoint, which issues untrusted certificates
	dns01   bool      // has a DNS-01 solver, which wildcard names need
}

// renewingCA returns the CA the Certificate's issuer gets certificates from. ok is false
// when that isn't known, because the issuer is external or issuers couldn't be read.
func (st certManagerState) renewingCA(cm *cmCertificate) (*model.CA, bool) {
	if cm == nil || st.issuers == nil || cm.issuerKey == "" {
		return nil, false
	}
	return st.issuers[cm.issuerKey].ca, true
}

// How long a renewal may take before it counts as stuck.
const (
	renewalGrace = time.Hour
	issuingGrace = time.Hour
)

var (
	issuerGVR        = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "issuers"}
	clusterIssuerGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers"}
)

func (s *Scanner) certManager(ctx context.Context) (certManagerState, []model.ScanError) {
	list, err := s.dynamic.Resource(certificateGVR).Namespace(s.Namespace).List(ctx, metav1.ListOptions{})
	if apierrors.IsNotFound(err) {
		return certManagerState{known: true}, nil
	}
	if err != nil {
		return certManagerState{}, []model.ScanError{s.scanError(s.Cluster, fmt.Errorf("list cert-manager Certificates: %w", err))}
	}
	state := certManagerState{known: true, certificates: make(map[string]*cmCertificate, len(list.Items))}
	for _, u := range list.Items {
		secretName, _, _ := unstructured.NestedString(u.Object, "spec", "secretName")
		state.certificates[u.GetNamespace()+"/"+secretName] = parseCertificate(u)
	}

	var errs []model.ScanError
	issuers := map[string]issuerState{}
	for _, r := range []struct {
		gvr       schema.GroupVersionResource
		kind, ns  string
		namespace bool
	}{
		{issuerGVR, "Issuer", s.Namespace, true},
		{clusterIssuerGVR, "ClusterIssuer", "", false},
	} {
		l, err := s.dynamic.Resource(r.gvr).Namespace(r.ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			errs = append(errs, s.scanError(s.Cluster, fmt.Errorf("list cert-manager %ss: %w", r.kind, err)))
			return state, errs
		}
		for _, u := range l.Items {
			key := r.kind + "/" + u.GetName()
			if r.namespace {
				key = r.kind + "/" + u.GetNamespace() + "/" + u.GetName()
			}
			ready, msg := condition(u, "Ready")
			server, _, _ := unstructured.NestedString(u.Object, "spec", "acme", "server")
			issuers[key] = issuerState{
				ready: ready, message: msg, ca: ca.ByACMEServer(server),
				staging: strings.Contains(server, "staging") || strings.Contains(server, "test-api"),
				dns01:   hasDNS01Solver(u),
			}
		}
	}
	state.issuers = issuers
	return state, errs
}

func parseCertificate(u unstructured.Unstructured) *cmCertificate {
	c := &cmCertificate{name: u.GetName()}
	c.dnsNames, _, _ = unstructured.NestedStringSlice(u.Object, "spec", "dnsNames")
	if cn, _, _ := unstructured.NestedString(u.Object, "spec", "commonName"); cn != "" && !slices.Contains(c.dnsNames, cn) {
		c.dnsNames = append([]string{cn}, c.dnsNames...)
	}
	group, _, _ := unstructured.NestedString(u.Object, "spec", "issuerRef", "group")
	kind, _, _ := unstructured.NestedString(u.Object, "spec", "issuerRef", "kind")
	issuer, _, _ := unstructured.NestedString(u.Object, "spec", "issuerRef", "name")
	if kind == "" {
		kind = "Issuer"
	}
	c.issuer = kind + "/" + issuer
	// External issuers (another API group) have their own status format, so they aren't checked.
	if group == "" || group == "cert-manager.io" {
		if kind == "ClusterIssuer" {
			c.issuerKey = "ClusterIssuer/" + issuer
		} else {
			c.issuerKey = "Issuer/" + u.GetNamespace() + "/" + issuer
		}
	}
	c.lastFailure, _, _ = unstructured.NestedString(u.Object, "status", "lastFailureTime")
	if s, _, _ := unstructured.NestedString(u.Object, "status", "renewalTime"); s != "" {
		c.renewalTime, _ = time.Parse(time.RFC3339, s)
	}
	c.ready, c.readyMessage = condition(u, "Ready")
	if issuing, msg := condition(u, "Issuing"); issuing {
		c.issuingSince = conditionTime(u, "Issuing")
		c.failureMessage = msg
	} else if msg != "" {
		c.failureMessage = msg
	} else {
		c.failureMessage = c.readyMessage
	}
	return c
}

// condition reports whether condition typ is True, and its message.
func condition(u unstructured.Unstructured, typ string) (bool, string) {
	if cond := findCondition(u, typ); cond != nil {
		msg, _ := cond["message"].(string)
		return cond["status"] == "True", msg
	}
	return false, ""
}

func conditionTime(u unstructured.Unstructured, typ string) time.Time {
	if cond := findCondition(u, typ); cond != nil {
		s, _ := cond["lastTransitionTime"].(string)
		t, _ := time.Parse(time.RFC3339, s)
		return t
	}
	return time.Time{}
}

func findCondition(u unstructured.Unstructured, typ string) map[string]any {
	conditions, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, raw := range conditions {
		if cond, ok := raw.(map[string]any); ok && cond["type"] == typ {
			return cond
		}
	}
	return nil
}

func (st certManagerState) renewal(sec corev1.Secret, now time.Time) (model.Renewal, string) {
	if cm := st.certificates[sec.Namespace+"/"+sec.Name]; cm != nil {
		return st.certificateRenewal(cm, now)
	}
	if name := sec.Annotations[certificateNameAnnotation]; name != "" {
		if !st.known {
			return model.RenewalUnknown, "written by cert-manager Certificate " + name + ", but Certificates couldn't be read"
		}
		return model.RenewalManual, "cert-manager Certificate " + name + " no longer exists, so nothing renews it"
	}
	return model.RenewalManual, "plain TLS secret: nothing renews it"
}

// certificateRenewal checks a Certificate. Ready alone isn't enough: it stays True while
// the current certificate is valid, even when renewing it is failing or stuck.
func (st certManagerState) certificateRenewal(cm *cmCertificate, now time.Time) (model.Renewal, string) {
	failing := func(format string, args ...any) (model.Renewal, string) {
		return model.RenewalAutoFailing, fmt.Sprintf("cert-manager Certificate %s ", cm.name) + fmt.Sprintf(format, args...)
	}
	if problem, stuck := st.problem(cm, now); stuck {
		return failing("%s", problem)
	}
	switch {
	case !cm.ready:
		return failing("is not ready: %s", cm.readyMessage)
	case !cm.renewalTime.IsZero() && now.After(cm.renewalTime.Add(renewalGrace)):
		return failing("was due for renewal at %s and hasn't renewed", cm.renewalTime.UTC().Format(time.RFC3339))
	}
	return model.RenewalAuto, fmt.Sprintf("cert-manager Certificate %s (%s)", cm.name, cm.issuer)
}

// problem says what keeps a Certificate from being issued: a failed attempt, a missing
// or broken issuer, or issuing that has taken too long.
func (st certManagerState) problem(cm *cmCertificate, now time.Time) (string, bool) {
	if cm.lastFailure != "" {
		return fmt.Sprintf("last issuance failed at %s: %s", cm.lastFailure, cm.failureMessage), true
	}
	if st.issuers != nil && cm.issuerKey != "" {
		is, ok := st.issuers[cm.issuerKey]
		switch {
		case !ok:
			return fmt.Sprintf("uses %s, which doesn't exist", cm.issuer), true
		case !is.ready:
			return fmt.Sprintf("uses %s, which isn't ready: %s", cm.issuer, is.message), true
		}
	}
	if !cm.issuingSince.IsZero() && now.After(cm.issuingSince.Add(issuingGrace)) {
		return fmt.Sprintf("has been issuing since %s: %s", cm.issuingSince.UTC().Format(time.RFC3339), cm.failureMessage), true
	}
	return "", false
}

// secretUsers maps "namespace/secretName" to the Ingresses and Gateways that serve it.
func (s *Scanner) secretUsers(ctx context.Context) (map[string][]string, []model.ScanError) {
	users := map[string][]string{}
	var errs []model.ScanError

	ingresses, err := s.core.NetworkingV1().Ingresses(s.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		errs = append(errs, s.scanError(s.Cluster, fmt.Errorf("list Ingresses: %w", err)))
	} else {
		for _, ing := range ingresses.Items {
			for _, t := range ing.Spec.TLS {
				if t.SecretName != "" {
					key := ing.Namespace + "/" + t.SecretName
					users[key] = append(users[key], "ingress/"+ing.Namespace+"/"+ing.Name)
				}
			}
		}
	}

	gateways, err := s.dynamic.Resource(gatewayGVR).Namespace(s.Namespace).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err): // Gateway API not installed
	case err != nil:
		errs = append(errs, s.scanError(s.Cluster, fmt.Errorf("list Gateways: %w", err)))
	default:
		for _, gw := range gateways.Items {
			for key := range gatewaySecrets(gw) {
				users[key] = append(users[key], "gateway/"+gw.GetNamespace()+"/"+gw.GetName())
			}
		}
	}
	return users, errs
}

// gatewaySecrets is the set of "namespace/name" secrets a Gateway's listeners refer to.
func gatewaySecrets(gw unstructured.Unstructured) map[string]bool {
	keys := map[string]bool{}
	listeners, _, _ := unstructured.NestedSlice(gw.Object, "spec", "listeners")
	for _, l := range listeners {
		listener, ok := l.(map[string]any)
		if !ok {
			continue
		}
		refs, _, _ := unstructured.NestedSlice(listener, "tls", "certificateRefs")
		for _, r := range refs {
			ref, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if kind, _ := ref["kind"].(string); kind != "" && kind != "Secret" {
				continue
			}
			name, _ := ref["name"].(string)
			ns, _ := ref["namespace"].(string)
			if ns == "" {
				ns = gw.GetNamespace()
			}
			keys[ns+"/"+name] = true
		}
	}
	return keys
}

func (s *Scanner) scanError(location string, err error) model.ScanError {
	return model.ScanError{Source: model.SourceKubernetes, Location: location, Err: err.Error()}
}
