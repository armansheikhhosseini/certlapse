package kube

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/armansheikhhosseini/certlapse/internal/ca"
	"github.com/armansheikhhosseini/certlapse/internal/model"
)

func TestCertificateFix(t *testing.T) {
	letsEncrypt := ca.ByACMEServer("https://acme-v02.api.letsencrypt.org/directory")
	zeroSSL := ca.ByACMEServer("https://acme.zerossl.com/v2/DV90")
	st := certManagerState{known: true, certificates: map[string]*cmCertificate{}, issuers: map[string]issuerState{
		"ClusterIssuer/letsencrypt":         {ready: true, ca: letsEncrypt},
		"ClusterIssuer/letsencrypt-staging": {ready: true, ca: letsEncrypt, staging: true},
		"ClusterIssuer/broken":              {ready: false, ca: zeroSSL},
		"Issuer/web/zerossl":                {ready: true, ca: zeroSSL, dns01: true},
		"Issuer/other/zerossl":              {ready: true, ca: zeroSSL},
		"ClusterIssuer/internal-ca":         {ready: true},
	}}
	s := &Scanner{Cluster: "prod"}
	secret := func(ns, name, certificateName string) corev1.Secret {
		sec := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
		if certificateName != "" {
			sec.Annotations = map[string]string{certificateNameAnnotation: certificateName}
		}
		return sec
	}
	public := func(current *model.CA, names ...string) model.Certificate {
		return model.Certificate{PubliclyTrusted: true, DNSNames: names, RenewingCA: current}
	}

	tests := []struct {
		name string
		st   certManagerState
		sec  corev1.Secret
		cert model.Certificate
		want []string // substrings of the fix
	}{
		{"prefers an issuer for the current CA", st, secret("web", "shop-tls", ""), public(zeroSSL, "shop.example.com"),
			[]string{"name: shop\n", "namespace: web", "secretName: shop-tls", `- "shop.example.com"`, "kind: Issuer\n    name: zerossl"}},
		{"else a ClusterIssuer, never staging", st, secret("api", "api-tls", ""), public(nil, "api.example.com"),
			[]string{"kind: ClusterIssuer\n    name: letsencrypt\n"}},
		{"warns about wildcards without DNS-01", st, secret("api", "wild-tls", ""), public(letsEncrypt, "*.example.com"),
			[]string{"need a DNS-01 solver, and ClusterIssuer/letsencrypt has none", `- "*.example.com"`}},
		{"recreates a deleted Certificate", st, secret("web", "old-tls", "legacy"), public(zeroSSL, "old.example.com"),
			[]string{"name: legacy\n"}},
		{"without cert-manager", certManagerState{known: true}, secret("web", "a-tls", ""), public(nil, "a.example.com"),
			[]string{"cert-manager isn't installed", "name: <your-acme-issuer>\n"}},
		{"without a usable issuer", certManagerState{known: true, certificates: map[string]*cmCertificate{}}, secret("web", "a-tls", ""), public(nil, "a.example.com"),
			[]string{"No ready ACME issuer", "name: <your-acme-issuer>\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fix := s.certificateFix(tt.st, tt.sec, tt.cert)
			if fix == nil {
				t.Fatal("no fix")
			}
			if !strings.Contains(fix.Title, "kubectl --context prod apply") {
				t.Errorf("title = %q", fix.Title)
			}
			for _, w := range tt.want {
				if !strings.Contains(fix.Text, w) {
					t.Errorf("fix doesn't contain %q:\n%s", w, fix.Text)
				}
			}
		})
	}

	if fix := s.certificateFix(st, secret("web", "internal-tls", ""), model.Certificate{DNSNames: []string{"internal.example"}}); fix != nil {
		t.Errorf("private certificate got a fix:\n%s", fix.Text)
	}
}
