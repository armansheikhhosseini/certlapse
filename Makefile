.PHONY: build test lint e2e-cluster e2e e2e-clean

# Name of the local kind cluster used by the end-to-end test.
E2E_CLUSTER ?= certlapse-e2e
KUBE_CONTEXT ?= kind-$(E2E_CLUSTER)

build:
	go build -o certlapse ./cmd/certlapse

test:
	go test -race ./...

# Runs the same golangci-lint version as CI without installing it.
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run --build-tags e2e ./...

# Creates a throwaway kind cluster for the end-to-end test.
e2e-cluster:
	kind create cluster --name $(E2E_CLUSTER) --wait 120s

# Runs the end-to-end test against $(KUBE_CONTEXT), which must be a kind cluster.
e2e:
	KUBE_CONTEXT=$(KUBE_CONTEXT) test/e2e/setup.sh
	KUBE_CONTEXT=$(KUBE_CONTEXT) go test -tags e2e -count=1 -v ./test/e2e/

e2e-clean:
	kind delete cluster --name $(E2E_CLUSTER)
