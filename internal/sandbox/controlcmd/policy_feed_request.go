package controlcmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	api "github.com/ejpir/gantry/api/policyservice"
	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/policyservice"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// cmdPolicyFeedRequest creates a host's policy-feed identity: a private key
// that never leaves this directory and a certificate request for an
// administrator to enroll.
func cmdPolicyFeedRequest(args []string) int {
	fs := flag.NewFlagSet("policy feed-request", flag.ContinueOnError)
	out := fs.String("out", "", "new output directory (never overwritten)")
	host := fs.String("host", "", "host name to request, as the administrator will enroll it")
	if code := parsePolicyAuthorFlags(fs, args); code >= 0 {
		return code
	}
	if *host == "" {
		return policyAuthorError(fmt.Errorf("feed-request requires -out and -host"))
	}
	dir, err := newPolicyOutputPath(*out)
	if err != nil {
		return policyAuthorError(err)
	}
	keyPEM, csrPEM, err := policyservice.NewHostRequest(*host)
	if err != nil {
		return policyAuthorError(err)
	}
	if err := localsec.CreateDir(dir); err != nil {
		return policyAuthorError(err)
	}
	keyPath := filepath.Join(dir, api.HostKeyFile)
	if err := atomicfile.WriteFileDurable(keyPath, keyPEM, 0o600); err != nil {
		return policyAuthorError(err)
	}
	if err := localsec.SecureRegularFile(keyPath); err != nil {
		return policyAuthorError(err)
	}
	requestPath := filepath.Join(dir, api.HostRequestFile)
	if err := atomicfile.WriteFileDurable(requestPath, csrPEM, 0o644); err != nil {
		return policyAuthorError(err)
	}
	fmt.Printf("Host key: %s (stays here)\nRequest: %s\n", keyPath, requestPath)
	fmt.Printf("Send %s to your administrator. Place the files they return in %s, then run:\n", api.HostRequestFile, dir)
	fmt.Printf("  gantry serve -policy-feed %s\n", filepath.Join(dir, api.FeedConfigFile))
	_ = os.Stdout.Sync()
	return 0
}
