package awsscan

import (
	"slices"
	"strings"
	"testing"

	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/armansheikhhosseini/certlapse/internal/model"
)

func TestACMFix(t *testing.T) {
	const certARN = "arn:aws:acm:eu-west-1:111122223333:certificate/abc"
	cert := model.Certificate{
		Location: certARN, Subject: "example.com", DNSNames: []string{"example.com", "*.example.com"}, PubliclyTrusted: true,
		UsedBy: []string{"arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/web/1"},
	}
	imported := acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeImported}
	emailValidated := acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeAmazonIssued,
		DomainValidationOptions: []acmtypes.DomainValidation{{ValidationMethod: acmtypes.ValidationMethodEmail}}}

	fix := acmFix(cert, imported)
	if fix == nil {
		t.Fatal("imported certificate: no fix")
	}
	for _, want := range []string{
		"aws acm request-certificate --region eu-west-1 --validation-method DNS \\\n  --domain-name example.com",
		"--subject-alternative-names example.com '*.example.com'",
		"switch alb/web to the new certificate",
		"aws acm delete-certificate --region eu-west-1 --certificate-arn " + certARN,
	} {
		if !strings.Contains(fix.Text, want) {
			t.Errorf("fix doesn't contain %q:\n%s", want, fix.Text)
		}
	}
	if fix := acmFix(cert, emailValidated); fix == nil || !strings.Contains(fix.Title, "DNS-validated") {
		t.Errorf("email-validated certificate: fix = %+v", fix)
	}

	unused := cert
	unused.Unused = true
	private := cert
	private.PubliclyTrusted = false
	for name, c := range map[string]model.Certificate{"unused": unused, "private": private} {
		if fix := acmFix(c, imported); fix != nil {
			t.Errorf("%s: got a fix:\n%s", name, fix.Text)
		}
	}
	if fix := acmFix(cert, acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeAmazonIssued}); fix != nil {
		t.Errorf("DNS-validated ACM certificate got a fix:\n%s", fix.Text)
	}
}

func TestIAMFix(t *testing.T) {
	users := []string{
		"arn:aws:cloudfront::111122223333:distribution/E1",
		"arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/web/1",
		"elb/legacy",
	}
	regions := userRegions(users, map[string]string{"elb/legacy": "eu-central-1"})
	if !slices.Equal(regions, []string{"eu-central-1", "eu-west-1", "us-east-1"}) {
		t.Errorf("regions = %v", regions)
	}
	cert := model.Certificate{Subject: "legacy.example.com", PubliclyTrusted: true, UsedBy: users}
	fix := iamFix(cert, "legacy-2026", regions)
	if fix == nil {
		t.Fatal("no fix")
	}
	if n := strings.Count(fix.Text, "aws acm request-certificate"); n != 3 {
		t.Errorf("%d requests, want one per region:\n%s", n, fix.Text)
	}
	if !strings.Contains(fix.Text, "aws iam delete-server-certificate --server-certificate-name legacy-2026") {
		t.Errorf("fix doesn't delete the old certificate:\n%s", fix.Text)
	}
}
