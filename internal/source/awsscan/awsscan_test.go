package awsscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/armansheikhhosseini/certlapse/internal/ca"
	"github.com/armansheikhhosseini/certlapse/internal/model"
)

func TestACMRenewal(t *testing.T) {
	inUse := []string{"arn:aws:cloudfront::111122223333:distribution/E1"}
	tests := []struct {
		name string
		d    acmtypes.CertificateDetail
		want model.Renewal
	}{
		{"imported", acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeImported}, model.RenewalManual},
		{"issued, DNS-validated", acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeAmazonIssued, InUseBy: inUse,
			RenewalEligibility: acmtypes.RenewalEligibilityEligible}, model.RenewalAuto},
		{"email-validated", acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeAmazonIssued,
			DomainValidationOptions: []acmtypes.DomainValidation{{ValidationMethod: acmtypes.ValidationMethodEmail}}}, model.RenewalManual},
		{"renewal failed", acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeAmazonIssued,
			RenewalSummary: &acmtypes.RenewalSummary{RenewalStatus: acmtypes.RenewalStatusFailed}}, model.RenewalAutoFailing},
		{"renewal waiting for validation", acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeAmazonIssued,
			RenewalSummary: &acmtypes.RenewalSummary{RenewalStatus: acmtypes.RenewalStatusPendingValidation}}, model.RenewalAutoFailing},
		{"in use but ineligible", acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeAmazonIssued, InUseBy: inUse,
			RenewalEligibility: acmtypes.RenewalEligibilityIneligible}, model.RenewalAutoFailing},
		{"ACME key pair", acmtypes.CertificateDetail{Type: acmtypes.CertificateTypeAmazonIssued,
			CertificateKeyPairOrigin: acmtypes.CertificateKeyPairOriginAcme}, model.RenewalUnknown},
	}
	for _, tt := range tests {
		if got, note := acmRenewal(tt.d); got != tt.want {
			t.Errorf("%s: renewal = %s (%s), want %s", tt.name, got, note, tt.want)
		}
	}
}

func TestScan(t *testing.T) {
	now := time.Now()
	const (
		importedARN = "arn:aws:acm:eu-west-1:111122223333:certificate/imported"
		issuedARN   = "arn:aws:acm:eu-west-1:111122223333:certificate/issued"
		pendingARN  = "arn:aws:acm:eu-west-1:111122223333:certificate/pending"
		usedIAMARN  = "arn:aws:iam::111122223333:server-certificate/used"
		albARN      = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/web/1"
		distARN     = "arn:aws:cloudfront::111122223333:distribution/E1"
		// Load balancers in an AWS-owned account, as API Gateway custom domains use.
		apiGatewayLB1 = "arn:aws:elasticloadbalancing:eu-west-1:999988887777:loadbalancer/app/managed-a/1"
		apiGatewayLB2 = "arn:aws:elasticloadbalancing:eu-west-1:999988887777:loadbalancer/app/managed-b/2"
	)
	validationRecord := &acmtypes.ResourceRecord{Name: aws.String("_a1.www.example.com."), Type: acmtypes.RecordTypeCname, Value: aws.String("_b2.acm-validations.aws.")}
	fa := &fakeACM{
		details: map[string]acmtypes.CertificateDetail{
			importedARN: {CertificateArn: aws.String(importedARN), Type: acmtypes.CertificateTypeImported,
				DomainName: aws.String("old.example.com"), NotAfter: aws.Time(now.AddDate(0, 3, 0))},
			issuedARN: {CertificateArn: aws.String(issuedARN), Type: acmtypes.CertificateTypeAmazonIssued,
				DomainName: aws.String("www.example.com"), NotAfter: aws.Time(now.AddDate(0, 6, 0)),
				InUseBy: []string{distARN, apiGatewayLB1, apiGatewayLB2}, RenewalEligibility: acmtypes.RenewalEligibilityEligible,
				// The name and its wildcard share a validation record.
				DomainValidationOptions: []acmtypes.DomainValidation{
					{DomainName: aws.String("www.example.com"), ValidationMethod: acmtypes.ValidationMethodDns, ResourceRecord: validationRecord},
					{DomainName: aws.String("*.www.example.com"), ValidationMethod: acmtypes.ValidationMethodDns, ResourceRecord: validationRecord},
				}},
			pendingARN: {CertificateArn: aws.String(pendingARN), Type: acmtypes.CertificateTypeAmazonIssued},
		},
		bodies: map[string]string{importedARN: selfSigned(t, "old.example.com", now.AddDate(0, 3, 0))},
	}
	fi := &fakeIAM{
		metas: []iamtypes.ServerCertificateMetadata{
			{ServerCertificateName: aws.String("used"), Arn: aws.String(usedIAMARN), ServerCertificateId: aws.String("ID1"), Expiration: aws.Time(now.AddDate(0, 2, 0))},
			{ServerCertificateName: aws.String("unused"), Arn: aws.String("arn:aws:iam::111122223333:server-certificate/unused"), ServerCertificateId: aws.String("ID2"), Expiration: aws.Time(now.AddDate(0, 2, 0))},
		},
		bodies: map[string]string{"used": selfSigned(t, "legacy.example.com", now.AddDate(0, 2, 0))},
	}
	s := &Scanner{
		Regions:    []string{"eu-west-1"},
		acm:        func(string) acmAPI { return fa },
		elbv2:      func(string) elbv2API { return &fakeELBv2{lbARN: albARN, certARN: usedIAMARN} },
		elb:        func(string) elb.DescribeLoadBalancersAPIClient { return fakeELB{} },
		iam:        fi,
		cloudFront: fakeCloudFront{},
	}

	certs, errs := s.Scan(context.Background())
	if len(errs) != 0 {
		t.Fatalf("errors: %+v", errs)
	}
	got := map[string]model.Certificate{}
	for _, c := range certs {
		got[c.Location] = c
	}
	if len(got) != 4 {
		t.Fatalf("got %d certificates, want 4 (the pending request is skipped): %+v", len(got), certs)
	}

	if c := got[importedARN]; c.Renewal != model.RenewalManual || !c.Unused || c.Fingerprint == "" || c.PubliclyTrusted {
		t.Errorf("imported: %+v", c)
	}
	if c := got[issuedARN]; c.Renewal != model.RenewalAuto || c.Unused || !c.PubliclyTrusted ||
		len(c.UsedBy) != 2 || c.UsedBy[0] != distARN || c.UsedBy[1] != AWSManaged ||
		c.RenewingCA != ca.Amazon || len(c.ValidationCNAMEs) != 1 || c.ValidationCNAMEs[0].Value != "_b2.acm-validations.aws." {
		t.Errorf("issued: %+v", c)
	}
	if c := got[usedIAMARN]; c.Renewal != model.RenewalManual || c.Unused || len(c.UsedBy) != 1 || c.UsedBy[0] != albARN || c.Subject != "legacy.example.com" {
		t.Errorf("used IAM certificate: %+v", c)
	}
	if c := got["arn:aws:iam::111122223333:server-certificate/unused"]; !c.Unused {
		t.Errorf("unused IAM certificate: %+v", c)
	}
}

func TestScanDoesNotCallIAMCertificatesUnusedWhenUsageIsUnknown(t *testing.T) {
	s := &Scanner{
		Regions: []string{"eu-west-1"},
		acm:     func(string) acmAPI { return &fakeACM{} },
		elbv2:   func(string) elbv2API { return &fakeELBv2{err: errors.New("AccessDenied")} },
		elb:     func(string) elb.DescribeLoadBalancersAPIClient { return fakeELB{} },
		iam: &fakeIAM{metas: []iamtypes.ServerCertificateMetadata{
			{ServerCertificateName: aws.String("x"), Arn: aws.String("arn:aws:iam::111122223333:server-certificate/x"), ServerCertificateId: aws.String("ID"), Expiration: aws.Time(time.Now().AddDate(0, 1, 0))},
		}},
		cloudFront: fakeCloudFront{},
	}
	certs, errs := s.Scan(context.Background())
	if len(errs) == 0 {
		t.Error("expected the load balancer error to be reported")
	}
	if len(certs) != 1 || certs[0].Unused {
		t.Errorf("certs = %+v, want one certificate not marked unused", certs)
	}
}

func selfSigned(t *testing.T, cn string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    notAfter.AddDate(-1, 0, 0),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fakeACM struct {
	details map[string]acmtypes.CertificateDetail
	bodies  map[string]string
}

func (f *fakeACM) ListCertificates(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	out := &acm.ListCertificatesOutput{}
	for a := range f.details {
		out.CertificateSummaryList = append(out.CertificateSummaryList, acmtypes.CertificateSummary{CertificateArn: aws.String(a)})
	}
	return out, nil
}

func (f *fakeACM) DescribeCertificate(_ context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	d := f.details[aws.ToString(in.CertificateArn)]
	return &acm.DescribeCertificateOutput{Certificate: &d}, nil
}

func (f *fakeACM) GetCertificate(_ context.Context, in *acm.GetCertificateInput, _ ...func(*acm.Options)) (*acm.GetCertificateOutput, error) {
	body, ok := f.bodies[aws.ToString(in.CertificateArn)]
	if !ok {
		return nil, errors.New("RequestInProgressException")
	}
	return &acm.GetCertificateOutput{Certificate: aws.String(body)}, nil
}

type fakeIAM struct {
	metas  []iamtypes.ServerCertificateMetadata
	bodies map[string]string
}

func (f *fakeIAM) ListServerCertificates(context.Context, *iam.ListServerCertificatesInput, ...func(*iam.Options)) (*iam.ListServerCertificatesOutput, error) {
	return &iam.ListServerCertificatesOutput{ServerCertificateMetadataList: f.metas}, nil
}

func (f *fakeIAM) GetServerCertificate(_ context.Context, in *iam.GetServerCertificateInput, _ ...func(*iam.Options)) (*iam.GetServerCertificateOutput, error) {
	body, ok := f.bodies[aws.ToString(in.ServerCertificateName)]
	if !ok {
		return &iam.GetServerCertificateOutput{}, nil
	}
	return &iam.GetServerCertificateOutput{ServerCertificate: &iamtypes.ServerCertificate{CertificateBody: aws.String(body)}}, nil
}

type fakeELBv2 struct {
	lbARN, certARN string
	err            error
}

func (f *fakeELBv2) DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &elbv2.DescribeLoadBalancersOutput{LoadBalancers: []elbv2types.LoadBalancer{{LoadBalancerArn: aws.String(f.lbARN)}}}, nil
}

func (f *fakeELBv2) DescribeListeners(context.Context, *elbv2.DescribeListenersInput, ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error) {
	return &elbv2.DescribeListenersOutput{Listeners: []elbv2types.Listener{
		{ListenerArn: aws.String("https"), Protocol: elbv2types.ProtocolEnumHttps},
		{ListenerArn: aws.String("http"), Protocol: elbv2types.ProtocolEnumHttp},
	}}, nil
}

func (f *fakeELBv2) DescribeListenerCertificates(_ context.Context, in *elbv2.DescribeListenerCertificatesInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeListenerCertificatesOutput, error) {
	if aws.ToString(in.ListenerArn) != "https" {
		return nil, errors.New("certificates requested for a non-TLS listener")
	}
	return &elbv2.DescribeListenerCertificatesOutput{Certificates: []elbv2types.Certificate{{CertificateArn: aws.String(f.certARN)}}}, nil
}

type fakeELB struct{}

func (fakeELB) DescribeLoadBalancers(context.Context, *elb.DescribeLoadBalancersInput, ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error) {
	return &elb.DescribeLoadBalancersOutput{}, nil
}

type fakeCloudFront struct{}

func (fakeCloudFront) ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	return &cloudfront.ListDistributionsOutput{DistributionList: &cftypes.DistributionList{Items: []cftypes.DistributionSummary{
		{ARN: aws.String("arn:aws:cloudfront::111122223333:distribution/E9"), ViewerCertificate: &cftypes.ViewerCertificate{CloudFrontDefaultCertificate: aws.Bool(true)}},
	}}}, nil
}
