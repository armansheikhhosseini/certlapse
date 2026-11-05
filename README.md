# certlapse

Find every TLS certificate you run and whether it renews itself, before shorter certificate lifetimes turn hand-renewed certificates into outages.

> Status: early development. Endpoint, AWS and Kubernetes scanning work.

## Why

The CA/Browser Forum (ballot SC-081) is shortening the maximum lifetime of publicly trusted TLS certificates:

| Issued from | Maximum lifetime | Renewals a year |
|---|---|---|
| 15 Mar 2026 | 200 days | 2 |
| 15 Mar 2027 | 100 days | 4 |
| 15 Mar 2029 | 47 days | 8 |

Certificates that renew automatically (ACM-issued, cert-manager, other ACME clients) are fine. Certificates someone renews by hand become a recurring chore and, sooner or later, an outage. The hard part is finding them: they sit in ACM, IAM, load balancers, CloudFront, Kubernetes secrets and on servers nobody remembers.

`certlapse` finds them, tells you which ones need work, predicts renewals that are going to fail, and prints the fix.

![certlapse scanning a Kubernetes namespace](docs/demo.gif)

## Install

```sh
go install github.com/armansheikhhosseini/certlapse/cmd/certlapse@latest
```

## Usage

```sh
# Scan endpoints
certlapse scan example.com api.example.com:8443

# Scan a list of endpoints (one per line, # for comments)
certlapse scan --endpoints-file domains.txt

# Discover hostnames under a domain in Certificate Transparency logs, and scan them
certlapse scan --discover example.com

# Scan an AWS account: ACM in the profile's region and us-east-1, plus IAM server certificates
certlapse scan --aws-profile prod

# Choose the regions
certlapse scan --aws-profile prod --aws-region eu-west-1 --aws-region eu-central-1 --aws-region us-east-1

# Scan Kubernetes: the current context, or several
certlapse scan --kubernetes
certlapse scan --kube-context staging --kube-context production -n web

# Everything at once: endpoints are matched to the AWS or Kubernetes certificate they serve
certlapse scan --aws-profile prod --kube-context production --endpoints-file domains.txt

# JSON output, or Markdown for a ticket or an email
certlapse scan --endpoints-file domains.txt -o json
certlapse scan --aws-profile prod -o markdown > certificates.md

# In CI: exit with code 2 if anything is high or critical
certlapse scan --endpoints-file domains.txt --fail-on high

# List healthy certificates too (the summary always counts them)
certlapse scan --aws-profile prod --all
```

Example output:

```
SEVERITY  NAME               SOURCE    LOCATION                   USED BY                        RENEWAL  EXPIRES
high      *.badssl.com (+1)  endpoint  wrong.host.badssl.com:443  https://wrong.host.badssl.com  unknown  2026-12-28 (57d)
          ↳ certificate doesn't cover wrong.host.badssl.com; renewal owner unknown (ACME issuer, so probably
            renewed automatically): scan the AWS accounts and clusters that serve it
info      github.com (+1)    endpoint  github.com:443             https://github.com             unknown  2027-01-27 (87d)
          ↳ renewal owner unknown: scan the AWS accounts and clusters that serve it

2 certificates · renewal: 0 auto, 0 manual, 0 failing, 2 unknown · 0 critical, 1 high, 0 warning, 1 info
Public certificates issued now last at most 200 days; from 15 Mar 2027, 100 days.
```

When some public certificates in use are renewed by hand, the summary shows what shorter lifetimes will cost:

```
3 public certificate(s) in use are renewed by hand. Manual renewals a year:
  now                200 days max  →  about 6
  from 15 Mar 2027   100 days max  →  about 12
  from 15 Mar 2029    47 days max  →  about 24
```

### Discovery

`--discover example.com` asks [crt.sh](https://crt.sh) for every hostname under the domain that appears in a certificate that hasn't expired. Every publicly trusted certificate is recorded in Certificate Transparency logs, so this finds hosts nobody put on a list. The hostnames are scanned like any other endpoint, and endpoints that serve the same certificate are grouped into one entry.

The domain name is sent to crt.sh, a third-party service. Hostnames that no longer answer, often retired ones, are summarised in one line rather than listed as errors. crt.sh can be slow; `--discover-max` caps how many hostnames are scanned.

### Renewal pre-flight

A certificate that renews automatically today can still fail at its next renewal, because the CA checks DNS again every time it issues. Nothing warns you until the renewal fails, often weeks before expiry. `certlapse` checks those records now:

| Check | The renewal fails when |
|---|---|
| CAA records of every name, or of the closest parent that has them | they don't allow the CA that will issue the replacement, for example `example.com CAA 0 issue "letsencrypt.org"` with an ACM certificate, or `issuewild` blocks a wildcard |
| ACM DNS validation records | the `_xxxx.example.com` CNAME ACM validated with has been deleted or changed |

```
SEVERITY  NAME             SOURCE  LOCATION                USED BY                   RENEWAL  EXPIRES
high      pay.example.com  acm     acm/eu-west-1/3f2a91c0  alb/checkout              auto     2027-01-20 (80d)
          ↳ renewal will fail: Amazon can't issue for pay.example.com (CAA on example.com only allows
            letsencrypt.org)
high      www.example.com  acm     acm/us-east-1/8e9f0a1b  cloudfront/E2EXAMPLE1234  auto     2027-01-04 (64d)
          ↳ renewal will fail: ACM's validation record _a1b2.www.example.com is missing from DNS (add it back:
            CNAME _c3d4.acm-validations.aws)
```

The CA that will issue the replacement is the one set up to renew it: Amazon for ACM-issued certificates, and the CA behind a cert-manager ACME issuer (Let's Encrypt, Google Trust Services, ZeroSSL and others). For any other publicly trusted certificate it's the CA that issued the current one.

Lookups use the system resolver. If your network answers differently from public DNS (split-horizon DNS), use `--dns-server 8.8.8.8` to see what the CA sees. `--no-dns-checks` turns the checks off.

### How to fix

For each certificate that needs work, the report ends with the change that fixes it:

| Finding | Fix |
|---|---|
| Kubernetes TLS secret nothing renews (a plain secret, or its cert-manager Certificate was deleted) | A cert-manager `Certificate` for the same secret and names. It uses a ready ACME issuer from that cluster, preferring one for the CA that issued the current certificate |
| Imported or email-validated ACM certificate | `aws acm request-certificate` for a DNS-validated replacement, and what to switch to it |
| IAM server certificate | The same, in every region that uses it (us-east-1 for CloudFront) |
| CAA records block the CA that renews it | The CAA record to add |
| ACM validation record missing or changed | The record to restore |

```
How to fix:

pay.example.com · acm/eu-west-1/3f2a91c0: Allow Amazon in CAA
    ; Add next to the existing CAA records; the CAs they allow stay allowed.
    example.com. CAA 0 issue "amazon.com"

partner.example.com · production:web/partner-tls: Let cert-manager renew it: kubectl --context production apply -f certificate.yaml
    # cert-manager issues a new certificate into web/partner-tls and renews it from then on.
    # The Ingresses and Gateways that use the secret keep working.
    apiVersion: cert-manager.io/v1
    kind: Certificate
    metadata:
      name: partner
      namespace: web
    spec:
      secretName: partner-tls
      dnsNames:
        - "partner.example.com"
      issuerRef:
        kind: ClusterIssuer
        name: letsencrypt
```

Markdown reports put each fix in a code block, and JSON has them under `fixes`. Fixes are suggestions to review: `certlapse` never applies anything.

An AWS scan with `--all` looks like this:

```
SEVERITY  NAME             SOURCE  LOCATION                USED BY                                         RENEWAL  EXPIRES
warning   pay.example.com  acm     acm/eu-west-1/3f2a91c0  alb/checkout                                    manual   2027-05-02 (182d)
          ↳ imported into ACM, and ACM never renews imported certificates: replace the imported certificate with
            an ACM-issued one (from 15 Mar 2027 public certificates last at most 100 days, about 4 renewals a
            year)
info      old.example.com  acm     acm/eu-west-1/0c1d2e3f  -                                               auto     2025-08-09 (expired)
          ↳ expired and not used by anything: delete it
ok        api.example.com  acm     acm/eu-west-1/4a5b6c7d  aws-managed load balancer (likely API Gateway)  auto     2026-12-25 (54d)
ok        www.example.com  acm     acm/us-east-1/8e9f0a1b  cloudfront/E2EXAMPLE1234                        auto     2027-01-04 (64d)
```

What it checks in AWS:

| Where | How renewal is decided |
|---|---|
| ACM, imported | `manual`: ACM never renews imported certificates |
| ACM, issued, DNS-validated | `auto`, or `auto-failing` if ACM reports the renewal failed or can't validate the domain |
| ACM, issued, email-validated | `manual`: someone has to approve every renewal email |
| IAM server certificates | `manual`: they never renew. Load balancers (classic and v2) and CloudFront are read to see what uses them |

Certificates nothing uses are reported as `info` with a suggestion to delete them.

#### AWS permissions

Read-only. A policy with exactly what the scan calls:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "acm:ListCertificates", "acm:DescribeCertificate", "acm:GetCertificate",
      "iam:ListServerCertificates", "iam:GetServerCertificate",
      "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeListenerCertificates",
      "cloudfront:ListDistributions"
    ],
    "Resource": "*"
  }]
}
```

`acm:GetCertificate` returns the public certificate and chain, never the private key.

### Kubernetes

A Kubernetes scan reads every `kubernetes.io/tls` secret and links it to:

- the **cert-manager** Certificate that writes it, if any, and
- the **Ingresses** and **Gateway API Gateways** that serve it.

```
SEVERITY  NAME                 SOURCE      LOCATION                    USED BY             RENEWAL       EXPIRES
critical  shop.example.com     kubernetes  production:web/shop-tls     ingress/web/shop    auto-failing  2026-11-21 (19d)
          ↳ automatic renewal is failing (cert-manager Certificate shop uses Issuer/letsencrypt, which isn't
            ready: Failed to register ACME account: 403): fix it within 19 days
warning   partner.example.com  kubernetes  production:web/partner-tls  gateway/web/public  manual        2027-04-11 (160d)
          ↳ plain TLS secret: nothing renews it: manage it with a cert-manager Certificate (from 15 Mar 2027
            public certificates last at most 100 days, about 4 renewals a year)
ok        www.example.com      kubernetes  production:web/www-tls      ingress/web/www     auto          2027-01-30 (89d)
```

| Secret | Renewal |
|---|---|
| Written by a healthy cert-manager Certificate | `auto` |
| Certificate whose last issuance failed, whose Issuer is missing or not ready, that has been issuing for over an hour, or that is past its `renewalTime` | `auto-failing`, even while cert-manager still reports the Certificate as Ready |
| Written by a cert-manager Certificate that has since been deleted | `manual` |
| Any other TLS secret | `manual` |

#### Kubernetes permissions

Read-only:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: certlapse
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [list]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses]
    verbs: [list]
  - apiGroups: [cert-manager.io]
    resources: [certificates, issuers, clusterissuers]
    verbs: [list]
  - apiGroups: [gateway.networking.k8s.io]
    resources: [gateways]
    verbs: [list]
```

Listing secrets returns their private keys to the client, as with `kubectl get secrets`. `certlapse` only parses `tls.crt`, and never prints or stores keys.

### Renewal status

| Status | Meaning |
|---|---|
| `auto` | Renews without a human (ACM-issued, cert-manager) |
| `auto-failing` | Set up to renew automatically, but the renewal is failing |
| `manual` | Someone has to replace it by hand |
| `unknown` | Seen on an endpoint, but the source that renews it wasn't scanned |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished, nothing at or above `--fail-on` |
| 1 | The scan couldn't run |
| 2 | At least one finding at or above `--fail-on` |

## Safety

`certlapse` only reads. It never creates, changes or deletes anything in your cloud accounts, clusters or DNS.

## Roadmap

- [x] Endpoint scanning
- [x] AWS: ACM (all key types, any regions) and IAM server certificates, with what uses them
- [x] Kubernetes: TLS secrets, cert-manager status, Ingresses and Gateways
- [x] Matching endpoint certificates to the place that renews them
- [x] cert-manager Certificates that have never issued
- [x] Discovery through Certificate Transparency logs
- [x] Manual renewal workload under shorter lifetimes; Markdown reports
- [x] Renewal pre-flight: CAA and ACM validation records that will make the next renewal fail
- [x] Generated fixes: cert-manager Certificates, ACM requests, DNS records
- [ ] Releases: Homebrew, binaries, container image
- [ ] Watch mode: scan on a schedule, keep history, and alert (Slack, email, PagerDuty) when a renewal starts failing or a certificate gets close to expiry
- [ ] Audit reports (HTML, PDF) as evidence for ISO 27001, SOC 2 and NIS2
- [ ] Revocation checks (OCSP)
- [ ] Post-quantum readiness of key algorithms
- [ ] Azure Key Vault and Google Cloud Certificate Manager
- [ ] Azure and GCP

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Arman Sheikhhosseini. Licensed under [Apache 2.0](LICENSE).
