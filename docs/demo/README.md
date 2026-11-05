# Recording the demo

`docs/demo.gif` is a real scan of a throwaway kind cluster. To record it again:

```sh
make e2e-cluster                                    # kind cluster certlapse-e2e
KUBE_CONTEXT=kind-certlapse-e2e test/e2e/setup.sh
KUBE_CONTEXT=kind-certlapse-e2e docs/demo/setup.sh
kubectl config rename-context kind-certlapse-e2e staging   # a shorter name on screen
go build -o bin/certlapse ./cmd/certlapse
vhs docs/demo/demo.tape
make e2e-clean
```

Renaming the context changes your kubeconfig; set `KUBECONFIG` to a scratch file first to keep it out of your own.
