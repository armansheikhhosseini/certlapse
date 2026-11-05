// Package awsscan reads certificates from AWS: ACM in each region, and IAM server
// certificates. It only calls read APIs (List*, Describe*, Get*).
package awsscan

import (
	"context"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/armansheikhhosseini/certlapse/internal/ca"
	"github.com/armansheikhhosseini/certlapse/internal/certinfo"
	"github.com/armansheikhhosseini/certlapse/internal/model"
)

type acmAPI interface {
	acm.ListCertificatesAPIClient
	DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
	GetCertificate(context.Context, *acm.GetCertificateInput, ...func(*acm.Options)) (*acm.GetCertificateOutput, error)
}

type iamAPI interface {
	iam.ListServerCertificatesAPIClient
	GetServerCertificate(context.Context, *iam.GetServerCertificateInput, ...func(*iam.Options)) (*iam.GetServerCertificateOutput, error)
}

type elbv2API interface {
	elbv2.DescribeLoadBalancersAPIClient
	elbv2.DescribeListenersAPIClient
	elbv2.DescribeListenerCertificatesAPIClient
}

// Scanner reads certificates from one AWS account.
type Scanner struct {
	Regions    []string
	acm        func(region string) acmAPI
	elbv2      func(region string) elbv2API
	elb        func(region string) elb.DescribeLoadBalancersAPIClient
	iam        iamAPI
	cloudFront cloudfront.ListDistributionsAPIClient
}

// New creates a scanner for the account cfg points to. ACM and load balancers are
// scanned in each of regions; IAM and CloudFront are global.
func New(cfg aws.Config, regions []string) *Scanner {
	return &Scanner{
		Regions: regions,
		acm: func(r string) acmAPI {
			return acm.NewFromConfig(cfg, func(o *acm.Options) { o.Region = r })
		},
		elbv2: func(r string) elbv2API {
			return elbv2.NewFromConfig(cfg, func(o *elbv2.Options) { o.Region = r })
		},
		elb: func(r string) elb.DescribeLoadBalancersAPIClient {
			return elb.NewFromConfig(cfg, func(o *elb.Options) { o.Region = r })
		},
		iam:        iam.NewFromConfig(cfg),
		cloudFront: cloudfront.NewFromConfig(cfg),
	}
}

// Scan returns every certificate found, and the places it couldn't read.
func (s *Scanner) Scan(ctx context.Context) ([]model.Certificate, []model.ScanError) {
	var certs []model.Certificate
	var errs []model.ScanError
	for _, r := range s.Regions {
		c, e := s.scanACM(ctx, r)
		certs, errs = append(certs, c...), append(errs, e...)
	}
	c, e := s.scanIAM(ctx)
	return append(certs, c...), append(errs, e...)
}

func (s *Scanner) scanACM(ctx context.Context, region string) ([]model.Certificate, []model.ScanError) {
	client := s.acm(region)
	// Without a KeyTypes filter, ListCertificates returns only RSA_2048 certificates.
	in := &acm.ListCertificatesInput{Includes: &acmtypes.Filters{KeyTypes: acmtypes.KeyAlgorithm("").Values()}}
	var arns []string
	for p := acm.NewListCertificatesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, []model.ScanError{scanError(model.SourceACM, region, err)}
		}
		for _, sum := range page.CertificateSummaryList {
			arns = append(arns, aws.ToString(sum.CertificateArn))
		}
	}

	var certs []model.Certificate
	var errs []model.ScanError
	for _, a := range arns {
		out, err := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: aws.String(a)})
		if err != nil {
			errs = append(errs, scanError(model.SourceACM, a, err))
			continue
		}
		c, ok := fromACM(*out.Certificate)
		if !ok {
			continue
		}
		// The body gives the fingerprint and, for imported certificates, the chain to
		// check public trust. Expired certificates may not return one; that's fine.
		if body, err := client.GetCertificate(ctx, &acm.GetCertificateInput{CertificateArn: aws.String(a)}); err == nil {
			addChain(&c, aws.ToString(body.Certificate)+"\n"+aws.ToString(body.CertificateChain),
				out.Certificate.Type == acmtypes.CertificateTypeImported)
		}
		if fix := acmFix(c, *out.Certificate); fix != nil {
			c.Fixes = append(c.Fixes, *fix)
		}
		certs = append(certs, c)
	}
	return certs, errs
}

// fromACM describes an ACM certificate. ok is false for certificates that were never
// issued (pending, failed or timed-out requests).
func fromACM(d acmtypes.CertificateDetail) (c model.Certificate, ok bool) {
	if d.NotAfter == nil {
		return model.Certificate{}, false
	}
	c = model.Certificate{
		Source:          model.SourceACM,
		Location:        aws.ToString(d.CertificateArn),
		Subject:         aws.ToString(d.DomainName),
		DNSNames:        d.SubjectAlternativeNames,
		Issuer:          aws.ToString(d.Issuer),
		Serial:          strings.ReplaceAll(aws.ToString(d.Serial), ":", ""),
		NotBefore:       aws.ToTime(d.NotBefore),
		NotAfter:        aws.ToTime(d.NotAfter),
		KeyAlgorithm:    string(d.KeyAlgorithm),
		PubliclyTrusted: d.Type == acmtypes.CertificateTypeAmazonIssued,
		UsedBy:          readableUsers(aws.ToString(d.CertificateArn), d.InUseBy),
		Unused:          len(d.InUseBy) == 0,
	}
	c.Renewal, c.RenewalNote = acmRenewal(d)
	if d.Type == acmtypes.CertificateTypeAmazonIssued {
		c.RenewingCA = ca.Amazon
		c.ValidationCNAMEs = validationCNAMEs(d)
	}
	if d.Status == acmtypes.CertificateStatusRevoked {
		c.Problems = append(c.Problems, "revoked")
	}
	return c, true
}

// AWSManaged replaces load balancers that belong to AWS rather than to the account.
const AWSManaged = "aws-managed load balancer (likely API Gateway)"

// readableUsers collapses load balancers in other accounts into one AWSManaged entry.
// API Gateway regional custom domains, for one, run on load balancers in AWS-owned
// accounts that don't exist in the user's account.
func readableUsers(certARN string, users []string) []string {
	owner, err := arn.Parse(certARN)
	if err != nil {
		return users
	}
	var out []string
	managed := false
	for _, u := range users {
		if a, err := arn.Parse(u); err == nil && a.Service == "elasticloadbalancing" && a.AccountID != owner.AccountID {
			managed = true
			continue
		}
		out = append(out, u)
	}
	if managed {
		out = append(out, AWSManaged)
	}
	return out
}

func acmRenewal(d acmtypes.CertificateDetail) (model.Renewal, string) {
	switch {
	case d.Type == acmtypes.CertificateTypeImported:
		return model.RenewalManual, "imported into ACM, and ACM never renews imported certificates"
	case d.CertificateKeyPairOrigin == acmtypes.CertificateKeyPairOriginAcme:
		return model.RenewalUnknown, "issued through ACME, so the ACME client has to renew it"
	case usesEmailValidation(d):
		return model.RenewalManual, "email-validated, so someone has to approve every renewal email"
	}
	if r := d.RenewalSummary; r != nil {
		switch r.RenewalStatus {
		case acmtypes.RenewalStatusFailed:
			return model.RenewalAutoFailing, "ACM renewal failed: " + string(r.RenewalStatusReason)
		case acmtypes.RenewalStatusPendingValidation:
			return model.RenewalAutoFailing, "ACM is waiting to validate the domain for renewal; check the validation CNAME is still in DNS"
		}
	}
	if d.RenewalEligibility == acmtypes.RenewalEligibilityIneligible && len(d.InUseBy) > 0 {
		return model.RenewalAutoFailing, "in use, but ACM says it isn't eligible for renewal"
	}
	return model.RenewalAuto, ""
}

// validationCNAMEs returns the DNS validation records ACM looks up on renewal, once each:
// a name and its wildcard share one.
func validationCNAMEs(d acmtypes.CertificateDetail) []model.CNAME {
	var out []model.CNAME
	for _, v := range d.DomainValidationOptions {
		r := v.ResourceRecord
		if v.ValidationMethod != acmtypes.ValidationMethodDns || r == nil || r.Type != acmtypes.RecordTypeCname {
			continue
		}
		rec := model.CNAME{Name: aws.ToString(r.Name), Value: aws.ToString(r.Value)}
		if !slices.Contains(out, rec) {
			out = append(out, rec)
		}
	}
	return out
}

func usesEmailValidation(d acmtypes.CertificateDetail) bool {
	for _, v := range d.DomainValidationOptions {
		if v.ValidationMethod == acmtypes.ValidationMethodEmail {
			return true
		}
	}
	return false
}

// addChain fills in what only the certificate body gives: the fingerprint, a uniform
// key algorithm name, and (when checkTrust) whether the chain is publicly trusted.
func addChain(c *model.Certificate, pemData string, checkTrust bool) {
	chain, err := certinfo.ParsePEMChain([]byte(pemData))
	if err != nil {
		return
	}
	r := certinfo.Record(c.Source, c.Location, chain[0], chain[1:])
	c.Fingerprint, c.Serial, c.KeyAlgorithm = r.Fingerprint, r.Serial, r.KeyAlgorithm
	if checkTrust {
		c.PubliclyTrusted, c.RenewingCA = r.PubliclyTrusted, r.RenewingCA
	}
}

func (s *Scanner) scanIAM(ctx context.Context) ([]model.Certificate, []model.ScanError) {
	var metas []iamtypes.ServerCertificateMetadata
	for p := iam.NewListServerCertificatesPaginator(s.iam, &iam.ListServerCertificatesInput{}); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, []model.ScanError{scanError(model.SourceIAM, "server certificates", err)}
		}
		metas = append(metas, page.ServerCertificateMetadataList...)
	}
	if len(metas) == 0 {
		return nil, nil
	}

	users, regionOf, complete, errs := s.iamCertificateUsers(ctx)
	certs := make([]model.Certificate, 0, len(metas))
	for _, m := range metas {
		name, location := aws.ToString(m.ServerCertificateName), aws.ToString(m.Arn)
		c := model.Certificate{Source: model.SourceIAM, Location: location, Subject: name, NotAfter: aws.ToTime(m.Expiration)}
		out, err := s.iam.GetServerCertificate(ctx, &iam.GetServerCertificateInput{ServerCertificateName: aws.String(name)})
		if err != nil {
			errs = append(errs, scanError(model.SourceIAM, location, err))
		} else if sc := out.ServerCertificate; sc != nil {
			if chain, err := certinfo.ParsePEMChain([]byte(aws.ToString(sc.CertificateBody) + "\n" + aws.ToString(sc.CertificateChain))); err == nil {
				c = certinfo.Record(model.SourceIAM, location, chain[0], chain[1:])
			}
		}
		c.Renewal, c.RenewalNote = model.RenewalManual, "IAM server certificates never renew"
		// Load balancers refer to it by ARN, CloudFront by ID.
		c.UsedBy = append(users[location], users[aws.ToString(m.ServerCertificateId)]...)
		// Only call it unused if every place that could use it was read.
		c.Unused = complete && len(c.UsedBy) == 0
		if fix := iamFix(c, name, userRegions(c.UsedBy, regionOf)); fix != nil {
			c.Fixes = append(c.Fixes, *fix)
		}
		certs = append(certs, c)
	}
	return certs, errs
}

// iamCertificateUsers maps IAM server certificate ARNs (load balancers) and IDs
// (CloudFront) to what uses them, and classic load balancers to their regions. complete
// is false if any place couldn't be read.
func (s *Scanner) iamCertificateUsers(ctx context.Context) (users map[string][]string, regionOf map[string]string, complete bool, errs []model.ScanError) {
	users, regionOf = map[string][]string{}, map[string]string{}

	for _, r := range s.Regions {
		if err := s.addELBv2Users(ctx, r, users); err != nil {
			errs = append(errs, scanError("elbv2", r, err))
		}
		for p := elb.NewDescribeLoadBalancersPaginator(s.elb(r), &elb.DescribeLoadBalancersInput{}); p.HasMorePages(); {
			page, err := p.NextPage(ctx)
			if err != nil {
				errs = append(errs, scanError("elb", r, err))
				break
			}
			for _, lb := range page.LoadBalancerDescriptions {
				for _, ld := range lb.ListenerDescriptions {
					if ld.Listener != nil && ld.Listener.SSLCertificateId != nil {
						user := "elb/" + aws.ToString(lb.LoadBalancerName)
						addUser(users, aws.ToString(ld.Listener.SSLCertificateId), user)
						regionOf[user] = r
					}
				}
			}
		}
	}

	for p := cloudfront.NewListDistributionsPaginator(s.cloudFront, &cloudfront.ListDistributionsInput{}); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			errs = append(errs, scanError("cloudfront", "distributions", err))
			break
		}
		if page.DistributionList == nil {
			continue
		}
		for _, d := range page.DistributionList.Items {
			if vc := d.ViewerCertificate; vc != nil && vc.IAMCertificateId != nil {
				addUser(users, aws.ToString(vc.IAMCertificateId), aws.ToString(d.ARN))
			}
		}
	}
	return users, regionOf, len(errs) == 0, errs
}

func (s *Scanner) addELBv2Users(ctx context.Context, region string, users map[string][]string) error {
	client := s.elbv2(region)
	for lbs := elbv2.NewDescribeLoadBalancersPaginator(client, &elbv2.DescribeLoadBalancersInput{}); lbs.HasMorePages(); {
		page, err := lbs.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, lb := range page.LoadBalancers {
			for ls := elbv2.NewDescribeListenersPaginator(client, &elbv2.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn}); ls.HasMorePages(); {
				lpage, err := ls.NextPage(ctx)
				if err != nil {
					return err
				}
				for _, l := range lpage.Listeners {
					if l.Protocol != elbv2types.ProtocolEnumHttps && l.Protocol != elbv2types.ProtocolEnumTls {
						continue
					}
					for cs := elbv2.NewDescribeListenerCertificatesPaginator(client, &elbv2.DescribeListenerCertificatesInput{ListenerArn: l.ListenerArn}); cs.HasMorePages(); {
						cpage, err := cs.NextPage(ctx)
						if err != nil {
							return err
						}
						for _, c := range cpage.Certificates {
							addUser(users, aws.ToString(c.CertificateArn), aws.ToString(lb.LoadBalancerArn))
						}
					}
				}
			}
		}
	}
	return nil
}

// addUser records that user uses the certificate key, once.
func addUser(users map[string][]string, key, user string) {
	if !slices.Contains(users[key], user) {
		users[key] = append(users[key], user)
	}
}

func scanError(source, location string, err error) model.ScanError {
	return model.ScanError{Source: source, Location: location, Err: err.Error()}
}
