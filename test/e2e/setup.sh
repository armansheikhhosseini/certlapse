#!/usr/bin/env bash
# Prepares a kind cluster for the end-to-end test: installs Gateway API and
# cert-manager, then creates certificates in every state the scanner reports.
#
# Usage: KUBE_CONTEXT=kind-<name> test/e2e/setup.sh
# It refuses to run against any context that isn't a kind cluster.
set -euo pipefail

CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.21.3}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.7.0}"

ctx="${KUBE_CONTEXT:-$(kubectl config current-context)}"
case "$ctx" in
  kind-*) ;;
  *) echo "refusing to run against context '$ctx': only kind-* contexts are allowed" >&2; exit 1 ;;
esac
k() { kubectl --context "$ctx" "$@"; }

dir="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Installing Gateway API $GATEWAY_API_VERSION and cert-manager $CERT_MANAGER_VERSION"
k apply --server-side -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" >/dev/null
k apply -f "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml" >/dev/null
k -n cert-manager rollout status deploy/cert-manager-webhook --timeout=180s
k -n cert-manager rollout status deploy/cert-manager --timeout=180s

# A self-signed certificate made by hand, as a TLS secret.
tls_secret() { # name days common-name
  openssl req -x509 -newkey rsa:2048 -nodes -days "$2" -subj "/CN=$3" \
    -addext "subjectAltName=DNS:$3" -keyout "$tmp/$1.key" -out "$tmp/$1.crt" 2>/dev/null
  k -n demo create secret tls "$1" --cert="$tmp/$1.crt" --key="$tmp/$1.key" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
}

echo "Creating test objects"
k apply -f "$dir/manifests.yaml" >/dev/null 2>&1 || {
  sleep 5 # the cert-manager webhook can need a moment after rollout
  k apply -f "$dir/manifests.yaml" >/dev/null
}
tls_secret manual-tls 40 manual.demo.example
if ! k -n demo get secret stale-tls >/dev/null 2>&1; then
  tls_secret stale-tls 20 stale.demo.example
fi

# Orphan: a secret whose Certificate has been deleted.
k apply -f - >/dev/null <<'EOF'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: temp, namespace: demo}
spec:
  secretName: orphan-tls
  dnsNames: [old.demo.example]
  issuerRef: {kind: ClusterIssuer, name: selfsigned}
EOF
k -n demo wait certificate/web certificate/temp --for=condition=Ready --timeout=120s
k -n demo delete certificate temp >/dev/null

echo "Ready: $(k -n demo get secrets --field-selector type=kubernetes.io/tls -o name | tr '\n' ' ')"
