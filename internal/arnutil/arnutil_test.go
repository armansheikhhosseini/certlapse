package arnutil

import "testing"

func TestShort(t *testing.T) {
	tests := map[string]string{
		"arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/my-alb/50dc6c495c0c9188": "alb/my-alb",
		"arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/net/my-nlb/50dc6c495c0c9188": "nlb/my-nlb",
		"arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/old-elb":                     "elb/old-elb",
		"arn:aws:cloudfront::111122223333:distribution/E2EXAMPLE":                                      "cloudfront/E2EXAMPLE",
		"arn:aws:apigateway:eu-west-1::/domainnames/api.example.com":                                   "apigateway/api.example.com",
		"arn:aws:acm:us-east-1:111122223333:certificate/12345678-aaaa-bbbb-cccc-1234567890ab":          "acm/us-east-1/12345678",
		"arn:aws:iam::111122223333:server-certificate/prod/legacy-cert":                                "iam/legacy-cert",
		"default/my-secret": "default/my-secret",
	}
	for in, want := range tests {
		if got := Short(in); got != want {
			t.Errorf("Short(%q) = %q, want %q", in, got, want)
		}
	}
}
