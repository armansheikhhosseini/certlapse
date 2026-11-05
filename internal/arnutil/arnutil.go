// Package arnutil shortens AWS ARNs for display.
package arnutil

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// Short turns an ARN into a readable name, e.g. "alb/my-alb" or "cloudfront/E2ABC".
// Anything that isn't an ARN is returned unchanged.
func Short(s string) string {
	a, err := arn.Parse(s)
	if err != nil {
		return s
	}
	parts := strings.Split(strings.TrimPrefix(a.Resource, "/"), "/")
	last := parts[len(parts)-1]
	switch a.Service {
	case "elasticloadbalancing":
		// loadbalancer/app/<name>/<id>, loadbalancer/net/<name>/<id>, loadbalancer/<name> (classic)
		if len(parts) >= 3 && parts[0] == "loadbalancer" {
			kind := map[string]string{"app": "alb", "net": "nlb", "gwy": "gwlb"}[parts[1]]
			if kind != "" {
				return kind + "/" + parts[2]
			}
		}
		if len(parts) == 2 && parts[0] == "loadbalancer" {
			return "elb/" + parts[1]
		}
	case "cloudfront":
		return "cloudfront/" + last
	case "apigateway":
		// /domainnames/<name> or /restapis/<id>/...
		if len(parts) >= 2 && parts[0] == "domainnames" {
			return "apigateway/" + parts[1]
		}
	case "acm":
		if len(last) > 8 {
			last = last[:8]
		}
		return "acm/" + a.Region + "/" + last
	case "iam":
		return "iam/" + last
	}
	return a.Service + "/" + last
}
