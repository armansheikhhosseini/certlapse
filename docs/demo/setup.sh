#!/usr/bin/env bash
# Adds what the README demo shows on top of the end-to-end setup (make e2e): a plain
# TLS secret holding a publicly trusted certificate, so the scan has a fix to print.
set -euo pipefail

ctx="${KUBE_CONTEXT:?set KUBE_CONTEXT to a kind context}"
case "$ctx" in
  kind-*) ;;
  *) echo "refusing to run against $ctx: not a kind cluster" >&2; exit 1 ;;
esac

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
# example.com's real certificate chain. The key doesn't match it, which is fine: only
# tls.crt is read, and a generic secret skips kubectl's key pair check.
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null 2>/dev/null |
  awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' >"$dir/tls.crt"
openssl ecparam -name prime256v1 -genkey -noout -out "$dir/tls.key"

kubectl --context "$ctx" -n demo create secret generic partner-tls --type kubernetes.io/tls \
  --from-file tls.crt="$dir/tls.crt" --from-file tls.key="$dir/tls.key" --dry-run=client -o yaml |
  kubectl --context "$ctx" apply -f -
kubectl --context "$ctx" apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: partner
  namespace: demo
spec:
  tls:
    - hosts: [example.com]
      secretName: partner-tls
  rules:
    - host: example.com
EOF
