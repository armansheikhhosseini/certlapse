package awsscan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/armansheikhhosseini/certlapse/internal/arnutil"
	"github.com/armansheikhhosseini/certlapse/internal/model"
)

// acmFix replaces an ACM certificate someone renews by hand with one ACM renews.
func acmFix(c model.Certificate, d acmtypes.CertificateDetail) *model.Fix {
	if c.Unused || len(names(c)) == 0 {
		return nil
	}
	region := "<region>"
	if a, err := arn.Parse(c.Location); err == nil {
		region = a.Region
	}
	deleteOld := fmt.Sprintf("aws acm delete-certificate --region %s --certificate-arn %s", region, c.Location)
	switch {
	case d.Type == acmtypes.CertificateTypeImported && c.PubliclyTrusted:
		return requestFix("Replace it with an ACM-issued certificate, which ACM renews itself",
			"ACM renews certificates it issues, never imported ones.", c, []string{region}, deleteOld)
	case d.Type == acmtypes.CertificateTypeAmazonIssued && usesEmailValidation(d):
		return requestFix("Replace it with a DNS-validated certificate, which renews without anyone approving emails",
			"DNS validation needs a CNAME record once; after that ACM renews without emails.", c, []string{region}, deleteOld)
	}
	return nil
}

// iamFix moves an IAM server certificate to ACM, in every region that uses it.
func iamFix(c model.Certificate, name string, regions []string) *model.Fix {
	if !c.PubliclyTrusted || c.Unused || len(regions) == 0 || len(names(c)) == 0 {
		return nil
	}
	return requestFix("Move it to ACM, which renews it",
		"IAM server certificates never renew; ACM-issued ones do.", c, regions,
		"aws iam delete-server-certificate --server-certificate-name "+name)
}

// requestFix requests a DNS-validated ACM certificate for the same names in each region.
func requestFix(title, why string, c model.Certificate, regions []string, deleteOld string) *model.Fix {
	dnsNames := names(c)
	quoted := make([]string, len(dnsNames))
	for i, n := range dnsNames {
		quoted[i] = shellQuote(n)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", why)
	for _, r := range regions {
		fmt.Fprintf(&b, "aws acm request-certificate --region %s --validation-method DNS \\\n  --domain-name %s", r, quoted[0])
		if len(quoted) > 1 {
			fmt.Fprintf(&b, " \\\n  --subject-alternative-names %s", strings.Join(quoted, " "))
		}
		b.WriteString("\n")
	}
	b.WriteString("# Add the CNAME records ACM asks for to DNS. They stay valid for every renewal:\n")
	for _, r := range regions {
		fmt.Fprintf(&b, "aws acm describe-certificate --region %s --certificate-arn <new certificate ARN> \\\n", r)
		b.WriteString("  --query 'Certificate.DomainValidationOptions[].ResourceRecord'\n")
	}
	users := make([]string, len(c.UsedBy))
	for i, u := range c.UsedBy {
		users[i] = arnutil.Short(u)
	}
	fmt.Fprintf(&b, "# Once it's issued, switch %s to the new certificate, then delete the old one:\n# %s\n",
		strings.Join(users, ", "), deleteOld)
	return &model.Fix{Title: title, Lang: "sh", Text: b.String()}
}

// names are the DNS names to request, the subject first.
func names(c model.Certificate) []string {
	var out []string
	if c.Subject != "" && strings.Contains(c.Subject, ".") && !strings.Contains(c.Subject, " ") {
		out = append(out, c.Subject)
	}
	for _, n := range c.DNSNames {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// userRegions are the regions of what uses an IAM certificate. CloudFront needs ACM
// certificates in us-east-1; classic load balancers are looked up in regionOf.
func userRegions(users []string, regionOf map[string]string) []string {
	var regions []string
	for _, u := range users {
		r := regionOf[u]
		if a, err := arn.Parse(u); err == nil {
			r = a.Region
			if a.Service == "cloudfront" {
				r = "us-east-1"
			}
		}
		if r != "" && !slices.Contains(regions, r) {
			regions = append(regions, r)
		}
	}
	slices.Sort(regions)
	return regions
}

func shellQuote(s string) string {
	if strings.ContainsAny(s, "*?[]") {
		return "'" + s + "'"
	}
	return s
}
