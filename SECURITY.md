# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on the repository's **Security** tab, choose **Report a vulnerability**. Don't open a public issue.

Include what you found, how to reproduce it, and the version (`certlapse version`). You'll get a reply within a week, and a fix or a plan within 30 days.

## Supported versions

Only the latest release gets security fixes.

## What certlapse touches

`certlapse` only reads. It never creates, changes or deletes anything in your cloud accounts, clusters or DNS. Listing Kubernetes TLS secrets returns their private keys to the client, as `kubectl get secrets` does; `certlapse` only parses `tls.crt`, and never prints or stores keys. Its outbound connections are the ones you ask for: your endpoints, AWS and Kubernetes APIs, your DNS resolver, and crt.sh when you use `--discover`.
