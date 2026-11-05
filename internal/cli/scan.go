package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"

	"github.com/armansheikhhosseini/certlapse/internal/classify"
	"github.com/armansheikhhosseini/certlapse/internal/correlate"
	"github.com/armansheikhhosseini/certlapse/internal/model"
	"github.com/armansheikhhosseini/certlapse/internal/preflight"
	"github.com/armansheikhhosseini/certlapse/internal/report"
	"github.com/armansheikhhosseini/certlapse/internal/source/awsscan"
	"github.com/armansheikhhosseini/certlapse/internal/source/ctlog"
	"github.com/armansheikhhosseini/certlapse/internal/source/endpoint"
	"github.com/armansheikhhosseini/certlapse/internal/source/kube"
)

type scanOptions struct {
	endpointsFile string
	discover      []string
	discoverMax   int
	aws           bool
	awsProfile    string
	awsRegions    []string
	kubernetes    bool
	kubeContexts  []string
	kubeconfig    string
	namespace     string
	output        string
	all           bool
	failOn        string
	timeout       time.Duration
	concurrency   int
	noDNSChecks   bool
	dnsServer     string
}

func newScanCommand() *cobra.Command {
	var o scanOptions
	cmd := &cobra.Command{
		Use:   "scan [endpoint...]",
		Short: "Scan for certificates and report their renewal status",
		Example: `  certlapse scan example.com api.example.com:8443
  certlapse scan --endpoints-file domains.txt -o json
  certlapse scan --discover example.com
  certlapse scan --aws-profile prod --aws-region eu-west-1 --aws-region us-east-1
  certlapse scan --kube-context staging --kube-context production
  certlapse scan --aws --kubernetes --endpoints-file domains.txt --fail-on high`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args, o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.endpointsFile, "endpoints-file", "", "file with one endpoint per line (# starts a comment)")
	f.StringSliceVar(&o.discover, "discover", nil, "find hostnames under this domain in Certificate Transparency logs and scan them, repeatable (sends the domain to crt.sh)")
	f.IntVar(&o.discoverMax, "discover-max", 500, "scan at most this many discovered hostnames per domain")
	f.BoolVar(&o.aws, "aws", false, "scan AWS with the default credentials (ACM, IAM server certificates)")
	f.StringVar(&o.awsProfile, "aws-profile", "", "scan AWS with this profile (implies --aws)")
	f.StringSliceVar(&o.awsRegions, "aws-region", nil, "AWS region to scan, repeatable (default: the profile's region and us-east-1, where CloudFront certificates live)")
	f.BoolVar(&o.kubernetes, "kubernetes", false, "scan the current kube context (TLS secrets, cert-manager, Ingresses, Gateways)")
	f.StringSliceVar(&o.kubeContexts, "kube-context", nil, "kube context to scan, repeatable (implies --kubernetes)")
	f.StringVar(&o.kubeconfig, "kubeconfig", "", "kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	f.StringVarP(&o.namespace, "namespace", "n", "", "only scan this namespace (default: all)")
	f.StringVarP(&o.output, "output", "o", "table", "output format: table, json or markdown")
	f.BoolVar(&o.all, "all", false, "list healthy certificates too (JSON always has them)")
	f.StringVar(&o.failOn, "fail-on", "", "exit with code 2 if any finding is at least this severity (info, warning, high, critical)")
	f.DurationVar(&o.timeout, "timeout", 10*time.Second, "timeout per endpoint")
	f.IntVar(&o.concurrency, "concurrency", 10, "endpoints scanned at the same time")
	f.BoolVar(&o.noDNSChecks, "no-dns-checks", false, "don't check the CAA and validation records renewals depend on")
	f.StringVar(&o.dnsServer, "dns-server", "", "DNS server for those checks, host or host:port (default: the system resolver)")
	return cmd
}

func runScan(cmd *cobra.Command, args []string, o scanOptions) error {
	writers := map[string]func(io.Writer, report.Report) error{
		"table": report.WriteTable, "json": report.WriteJSON, "markdown": report.WriteMarkdown, "md": report.WriteMarkdown,
	}
	write, ok := writers[o.output]
	if !ok {
		return fmt.Errorf("unknown output %q (want table, json or markdown)", o.output)
	}
	var failOn model.Severity
	if o.failOn != "" {
		var err error
		if failOn, err = model.ParseSeverity(o.failOn); err != nil {
			return err
		}
	}

	raw := args
	if o.endpointsFile != "" {
		lines, err := readLines(o.endpointsFile)
		if err != nil {
			return err
		}
		raw = append(raw, lines...)
	}
	scanAWS := o.aws || o.awsProfile != "" || len(o.awsRegions) > 0
	scanKube := o.kubernetes || len(o.kubeContexts) > 0
	if len(raw) == 0 && len(o.discover) == 0 && !scanAWS && !scanKube {
		return errors.New("nothing to scan: pass endpoints, --endpoints-file, --discover, --aws or --kubernetes")
	}
	targets := make([]endpoint.Target, 0, len(raw))
	for _, r := range raw {
		t, err := endpoint.ParseTarget(r)
		if err != nil {
			return err
		}
		targets = append(targets, t)
	}

	ctx := cmd.Context()
	var certs []model.Certificate
	var scanErrs []model.ScanError
	discovered := map[string]bool{} // addresses found only through CT logs
	for _, domain := range o.discover {
		found, e := discoverTargets(ctx, cmd.ErrOrStderr(), domain, targets, o.discoverMax)
		scanErrs = append(scanErrs, e...)
		for _, t := range found {
			discovered[t.Address()] = true
		}
		targets = append(targets, found...)
	}
	if scanAWS {
		scanner, err := newAWSScanner(ctx, o.awsProfile, o.awsRegions)
		if err != nil {
			return err
		}
		c, e := scanner.Scan(ctx)
		certs, scanErrs = append(certs, c...), append(scanErrs, e...)
	}
	if scanKube {
		contexts := o.kubeContexts
		if len(contexts) == 0 {
			contexts = []string{""} // the current context
		}
		for _, kc := range contexts {
			scanner, err := kube.New(o.kubeconfig, kc, o.namespace)
			if err != nil {
				return err
			}
			c, e := scanner.Scan(ctx)
			certs, scanErrs = append(certs, c...), append(scanErrs, e...)
		}
	}
	if len(targets) > 0 {
		c, e := endpoint.Scanner{Timeout: o.timeout, Concurrency: o.concurrency}.Scan(ctx, targets)
		certs, scanErrs = append(certs, c...), append(scanErrs, summarizeUnreachable(e, discovered)...)
	}

	now := time.Now()
	certs = correlate.Link(certs)
	if !o.noDNSChecks {
		var e []model.ScanError
		certs, e = checkDNS(ctx, certs, o.dnsServer, now)
		scanErrs = append(scanErrs, e...)
	}
	rep := report.New(classify.ClassifyAll(certs, now), scanErrs, now)
	rep.HideOK = !o.all
	if err := write(cmd.OutOrStdout(), rep); err != nil {
		return err
	}
	if o.failOn != "" && rep.Highest() >= failOn {
		return ExitError{Code: 2}
	}
	return nil
}

// checkDNS looks for DNS records that will make renewals fail. A missing resolver is
// reported rather than fatal, so the rest of the scan still counts.
func checkDNS(ctx context.Context, certs []model.Certificate, server string, now time.Time) ([]model.Certificate, []model.ScanError) {
	lookup, err := preflight.NewResolver(server, 5*time.Second)
	if err != nil {
		return certs, []model.ScanError{{Source: "dns", Location: "resolver", Err: err.Error() + " (use --dns-server, or --no-dns-checks)"}}
	}
	return preflight.Checker{Lookup: lookup}.Check(ctx, certs, now)
}

// discoverTargets finds hostnames under domain in CT logs that aren't already targets,
// keeping at most limit of them. Progress goes to log, so stdout stays clean for JSON.
func discoverTargets(ctx context.Context, log io.Writer, domain string, existing []endpoint.Target, limit int) ([]endpoint.Target, []model.ScanError) {
	fmt.Fprintf(log, "Looking up %s in Certificate Transparency logs (crt.sh)...\n", domain)
	names, wildcards, err := ctlog.Client{}.Hostnames(ctx, domain)
	if err != nil {
		return nil, []model.ScanError{{Source: "ct", Location: domain, Err: err.Error()}}
	}
	have := map[string]bool{}
	for _, t := range existing {
		have[t.Address()] = true
	}
	var found []endpoint.Target
	for _, n := range names {
		t := endpoint.Target{Host: n, Port: "443"}
		if !have[t.Address()] {
			found = append(found, t)
		}
	}
	msg := fmt.Sprintf("Found %d hostnames under %s", len(names), domain)
	if wildcards > 0 {
		msg += fmt.Sprintf(" (%d wildcard names skipped)", wildcards)
	}
	if len(found) > limit {
		msg += fmt.Sprintf("; scanning the first %d (--discover-max)", limit)
		found = found[:limit]
	}
	fmt.Fprintln(log, msg)
	return found, nil
}

// summarizeUnreachable folds connection errors for hostnames found only in CT logs into
// one entry: logs list every name that ever had a certificate, and many are retired.
func summarizeUnreachable(errs []model.ScanError, discovered map[string]bool) []model.ScanError {
	var kept []model.ScanError
	var names []string
	for _, e := range errs {
		if discovered[e.Location] {
			host, _, _ := strings.Cut(e.Location, ":")
			names = append(names, host)
			continue
		}
		kept = append(kept, e)
	}
	if len(names) == 0 {
		return kept
	}
	shown := names[:min(5, len(names))]
	list := strings.Join(shown, ", ")
	if extra := len(names) - len(shown); extra > 0 {
		list += fmt.Sprintf(" +%d more", extra)
	}
	return append(kept, model.ScanError{
		Source:   "ct",
		Location: fmt.Sprintf("%d discovered hostname(s)", len(names)),
		Err:      "no TLS answer on port 443 (no DNS record or nothing listening; often retired hosts): " + list,
	})
}

func newAWSScanner(ctx context.Context, profile string, regions []string) (*awsscan.Scanner, error) {
	var opts []func(*config.LoadOptions) error
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	if len(regions) == 0 {
		if cfg.Region == "" {
			return nil, errors.New("no AWS region configured: use --aws-region")
		}
		regions = []string{cfg.Region}
		if cfg.Region != "us-east-1" {
			regions = append(regions, "us-east-1")
		}
	}
	return awsscan.New(cfg, regions), nil
}

// readLines reads non-empty lines, ignoring everything after a #.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}
