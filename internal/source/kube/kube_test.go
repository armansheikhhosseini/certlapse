package kube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

var listKinds = map[schema.GroupVersionResource]string{
	certificateGVR:   "CertificateList",
	issuerGVR:        "IssuerList",
	clusterIssuerGVR: "ClusterIssuerList",
	gatewayGVR:       "GatewayList",
}

func TestScan(t *testing.T) {
	core := fake.NewSimpleClientset(
		tlsSecret(t, "default", "managed-tls", "web"),
		tlsSecret(t, "default", "failing-tls", "api"),
		tlsSecret(t, "default", "orphan-tls", "deleted"),
		tlsSecret(t, "default", "plain-tls", ""),
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "opaque"}, Type: corev1.SecretTypeOpaque},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
			Spec:       networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "managed-tls"}}},
		},
	)
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds,
		certificate("default", "web", "managed-tls", "True", ""),
		certificate("default", "api", "failing-tls", "True", "2026-10-30T10:00:00Z"),
		// No secrets: one stuck on a deleted issuer, one still being issued for the first time.
		withIssuer(certificate("default", "pending", "pending-tls", "False", ""), "gone"),
		certificate("default", "new", "new-tls", "False", ""),
		clusterIssuer("letsencrypt", "True"),
	)
	// Added with its resource name: the fake would guess "gatewaies" from the kind.
	if err := dyn.Tracker().Create(gatewayGVR, gateway("default", "public", "plain-tls"), "default"); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{Cluster: "test", core: core, dynamic: dyn}

	certs, errs := s.Scan(context.Background())
	if len(errs) != 0 {
		t.Fatalf("errors: %+v", errs)
	}
	got := map[string]model.Certificate{}
	for _, c := range certs {
		got[strings.TrimPrefix(c.Location, "test:default/")] = c
	}
	if len(got) != 5 {
		t.Fatalf("got %d certificates, want 5 (the opaque secret and new Certificate are skipped): %v", len(got), got)
	}
	if c := got["pending-tls"]; !c.NotIssued || c.Renewal != model.RenewalAutoFailing ||
		!strings.Contains(c.RenewalNote, "ClusterIssuer/gone, which doesn't exist") || c.Subject != "pending-tls.example.com" {
		t.Errorf("pending-tls: %+v", c)
	}
	check := func(name string, renewal model.Renewal, note string, usedBy ...string) {
		t.Helper()
		c := got[name]
		if c.Renewal != renewal || !strings.Contains(c.RenewalNote, note) || strings.Join(c.UsedBy, ",") != strings.Join(usedBy, ",") {
			t.Errorf("%s: renewal %s (%q), used by %v; want %s (%q), used by %v", name, c.Renewal, c.RenewalNote, c.UsedBy, renewal, note, usedBy)
		}
	}
	check("managed-tls", model.RenewalAuto, "Certificate web (ClusterIssuer/letsencrypt)", "ingress/default/web")
	if c := got["managed-tls"]; c.RenewingCA == nil || c.RenewingCA.Name != "Let's Encrypt" {
		t.Errorf("managed-tls: renewing CA = %v, want Let's Encrypt from the ACME issuer", c.RenewingCA)
	}
	check("failing-tls", model.RenewalAutoFailing, "last issuance failed")
	check("orphan-tls", model.RenewalManual, "no longer exists")
	check("plain-tls", model.RenewalManual, "plain TLS secret", "gateway/default/public")
}

func TestScanWithoutCertManagerOrGatewayAPI(t *testing.T) {
	core := fake.NewSimpleClientset(tlsSecret(t, "default", "plain-tls", ""))
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	dyn.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(certificateGVR.GroupResource(), "")
	})
	s := &Scanner{Cluster: "test", core: core, dynamic: dyn}

	certs, errs := s.Scan(context.Background())
	if len(errs) != 0 || len(certs) != 1 || certs[0].Renewal != model.RenewalManual {
		t.Errorf("certs = %+v, errs = %+v; want one manual certificate and no errors", certs, errs)
	}
}

func TestRenewalWhenCertificatesCannotBeRead(t *testing.T) {
	sec := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{certificateNameAnnotation: "web"}}}
	if r, _ := (certManagerState{known: false}).renewal(sec, time.Now()); r != model.RenewalUnknown {
		t.Errorf("renewal = %s, want unknown", r)
	}
}

func TestCertificateRenewal(t *testing.T) {
	now := time.Date(2026, time.November, 20, 0, 0, 0, 0, time.UTC)
	healthy := func() *cmCertificate {
		return &cmCertificate{name: "web", issuer: "ClusterIssuer/le", issuerKey: "ClusterIssuer/le", ready: true, renewalTime: now.Add(48 * time.Hour)}
	}
	st := certManagerState{known: true, issuers: map[string]issuerState{
		"ClusterIssuer/le":       {ready: true},
		"Issuer/demo/missing-ca": {ready: false, message: `secrets "does-not-exist" not found`},
	}}
	tests := []struct {
		name   string
		change func(*cmCertificate)
		st     certManagerState
		want   model.Renewal
		note   string
	}{
		{"healthy", func(*cmCertificate) {}, st, model.RenewalAuto, "ClusterIssuer/le"},
		{"renewal overdue", func(c *cmCertificate) { c.renewalTime = now.Add(-48 * time.Hour) }, st, model.RenewalAutoFailing, "hasn't renewed"},
		{"issuing for too long", func(c *cmCertificate) { c.issuingSince = now.Add(-3 * time.Hour) }, st, model.RenewalAutoFailing, "has been issuing"},
		{"issuing just started", func(c *cmCertificate) { c.issuingSince = now.Add(-time.Minute) }, st, model.RenewalAuto, ""},
		{"issuer not ready", func(c *cmCertificate) { c.issuer, c.issuerKey = "Issuer/missing-ca", "Issuer/demo/missing-ca" }, st, model.RenewalAutoFailing, "does-not-exist"},
		{"issuer missing", func(c *cmCertificate) { c.issuer, c.issuerKey = "ClusterIssuer/gone", "ClusterIssuer/gone" }, st, model.RenewalAutoFailing, "doesn't exist"},
		{"external issuer not checked", func(c *cmCertificate) { c.issuerKey = "" }, st, model.RenewalAuto, ""},
		{"issuers unreadable", func(c *cmCertificate) { c.issuerKey = "ClusterIssuer/gone" }, certManagerState{known: true}, model.RenewalAuto, ""},
	}
	for _, tt := range tests {
		cm := healthy()
		tt.change(cm)
		if r, note := tt.st.certificateRenewal(cm, now); r != tt.want || !strings.Contains(note, tt.note) {
			t.Errorf("%s: renewal = %s (%q), want %s (%q)", tt.name, r, note, tt.want, tt.note)
		}
	}
}

func clusterIssuer(name, ready string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "ClusterIssuer",
		"metadata":   map[string]any{"name": name},
		"spec":       map[string]any{"acme": map[string]any{"server": "https://acme-v02.api.letsencrypt.org/directory"}},
		"status":     map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": ready}}},
	}}
}

func tlsSecret(t *testing.T, ns, name, certificateName string) *corev1.Secret {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name + ".example.com"},
		DNSNames:     []string{name + ".example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 3, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
	}
	if certificateName != "" {
		sec.Annotations = map[string]string{certificateNameAnnotation: certificateName}
	}
	return sec
}

func certificate(ns, name, secretName, ready, lastFailure string) *unstructured.Unstructured {
	status := map[string]any{
		"conditions": []any{
			map[string]any{"type": "Ready", "status": ready, "message": "Certificate is up to date"},
			map[string]any{"type": "Issuing", "status": "False", "message": "ACME challenge failed"},
		},
	}
	if lastFailure != "" {
		status["lastFailureTime"] = lastFailure
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"secretName": secretName,
			"dnsNames":   []any{secretName + ".example.com"},
			"issuerRef":  map[string]any{"kind": "ClusterIssuer", "name": "letsencrypt"},
		},
		"status": status,
	}}
}

func withIssuer(u *unstructured.Unstructured, clusterIssuer string) *unstructured.Unstructured {
	if err := unstructured.SetNestedField(u.Object, clusterIssuer, "spec", "issuerRef", "name"); err != nil {
		panic(err)
	}
	return u
}

func gateway(ns, name, secretName string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"listeners": []any{
				map[string]any{"name": "https", "tls": map[string]any{
					"certificateRefs": []any{map[string]any{"kind": "Secret", "name": secretName}},
				}},
			},
		},
	}}
}
