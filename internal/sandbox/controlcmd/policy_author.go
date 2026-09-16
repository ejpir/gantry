package controlcmd

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
)

func cmdPolicyGenerate(args []string) int {
	fs := flag.NewFlagSet("policy generate", flag.ContinueOnError)
	out := fs.String("out", "", "new output directory (never overwritten)")
	org := fs.String("organization", "local-test", "organization identifier (not proof of enrollment)")
	revision := fs.String("revision", "", "revision identifier (default: generated timestamp)")
	profile := fs.String("profile", "developer", "profile name")
	ttlText := fs.String("ttl", "30d", "expiry from now, 1s..365d (whole days or a duration such as 12h)")
	var mounts []string
	fs.Func("mount", "existing host directory to allow read-only; repeatable; no default mounts", func(path string) error {
		if path == "" || len(mounts) >= 256 {
			return fmt.Errorf("mount requires a directory; at most 256 mounts are supported")
		}
		mounts = append(mounts, path)
		return nil
	})
	if code := parsePolicyAuthorFlags(fs, args); code >= 0 {
		return code
	}
	dir, err := newPolicyOutputPath(*out)
	if err != nil {
		return policyAuthorError(err)
	}
	ttl, err := parsePolicyTTL(*ttlText)
	if err != nil {
		return policyAuthorError(err)
	}
	now := time.Now().UTC()
	if *revision == "" {
		*revision = "generated-" + now.Format("20060102T150405.000000000Z")
	}
	p := policy.Profile{Rules: []policy.Rule{}, Network: policy.Network{Rules: []netpol.GuardRule{}, DNS: []string{}}}
	seen := make(map[string]bool)
	for _, mount := range mounts {
		root, err := canonicalPolicyMount(mount)
		if err != nil {
			return policyAuthorError(err)
		}
		if seen[root] {
			continue
		}
		seen[root] = true
		p.Rules = append(p.Rules, policy.Rule{ID: fmt.Sprintf("mount-read-%d", len(p.Rules)+1), Effect: "allow", Action: policy.MountRead, Path: root})
	}
	document := policy.Document{Version: 1, Organization: *org, Revision: *revision, ExpiresAt: now.Add(ttl), Profiles: map[string]policy.Profile{*profile: p}}
	// Validate before spending time generating a key or creating directories.
	if _, err := policy.MarshalDocument(document); err != nil {
		return policyAuthorError(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return policyAuthorError(fmt.Errorf("generate ephemeral signing key failed"))
	}
	return signAndPublishPolicy(dir, document, key, true)
}

func cmdPolicySign(args []string) int {
	fs := flag.NewFlagSet("policy sign", flag.ContinueOnError)
	data := fs.String("data", "", "source data.json (strict, data-only Gantry policy)")
	out := fs.String("out", "", "new output directory (never overwritten)")
	keyPath := fs.String("signing-key", "", "existing unencrypted PKCS#1/PKCS#8 RSA private key PEM (2048+ bits)")
	ephemeral := fs.Bool("ephemeral", false, "use a fresh test signing key instead; private key is not saved")
	if code := parsePolicyAuthorFlags(fs, args); code >= 0 {
		return code
	}
	if *data == "" || (*keyPath != "") == *ephemeral {
		return policyAuthorError(fmt.Errorf("sign requires -data, -out and exactly one of -signing-key or -ephemeral"))
	}
	dir, err := newPolicyOutputPath(*out)
	if err != nil {
		return policyAuthorError(err)
	}
	document, err := policy.ReadDocument(*data)
	if err != nil {
		return policyAuthorError(err)
	}
	var key *rsa.PrivateKey
	if *ephemeral {
		key, err = rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return policyAuthorError(fmt.Errorf("generate ephemeral signing key failed"))
		}
	} else {
		key, err = policy.ReadSigningKey(*keyPath)
		if err != nil {
			return policyAuthorError(err)
		}
	}
	return signAndPublishPolicy(dir, document, key, *ephemeral)
}

// A negative result means continue; help and usage errors return CLI exit codes.
func parsePolicyAuthorFlags(fs *flag.FlagSet, args []string) int {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "gantry policy: unexpected positional arguments")
		return 2
	}
	return -1
}

func policyAuthorError(err error) int {
	fmt.Fprintln(os.Stderr, "gantry policy:", err)
	return 1
}

func parsePolicyTTL(text string) (time.Duration, error) {
	const day = 24 * time.Hour
	var ttl time.Duration
	var err error
	if days, ok := strings.CutSuffix(text, "d"); ok {
		var count int64
		count, err = strconv.ParseInt(days, 10, 64)
		if err == nil && count >= 1 && count <= 365 {
			ttl = time.Duration(count) * day
		}
	} else {
		ttl, err = time.ParseDuration(text)
	}
	if err != nil || ttl < time.Second || ttl > 365*day {
		return 0, fmt.Errorf("ttl must be 1s..365d (whole days such as 30d, or a duration such as 12h)")
	}
	return ttl, nil
}

func canonicalPolicyMount(path string) (string, error) {
	root, err := filepath.Abs(path)
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	if err != nil {
		return "", fmt.Errorf("mount directory: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("mount directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("mount requires an existing directory: %s", path)
	}
	return filepath.Clean(root), nil
}

func newPolicyOutputPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("-out requires a new directory")
	}
	dir, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(dir); err == nil {
		return "", fmt.Errorf("refusing to overwrite existing output %s; choose a new directory", dir)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return dir, nil
}

func signAndPublishPolicy(dir string, document policy.Document, key *rsa.PrivateKey, ephemeral bool) int {
	signed, err := policy.SignDocument(document, key)
	if err != nil {
		return policyAuthorError(err)
	}
	if err := writePolicyOutput(dir, signed); err != nil {
		return policyAuthorError(err)
	}
	profiles := make([]string, 0, len(document.Profiles))
	for profile := range document.Profiles {
		profiles = append(profiles, profile)
	}
	slices.Sort(profiles)
	fmt.Printf("Signed policy: %s / %s\nProfiles: %s\nExpires: %s\nSource: %s\nBundle: %s\nPublic key: %s\n",
		document.Organization, document.Revision, strings.Join(profiles, ", "), document.ExpiresAt.Format(time.RFC3339Nano),
		filepath.Join(dir, "source", "data.json"), filepath.Join(dir, "bundle.tar.gz"), filepath.Join(dir, "public.pem"))
	if ephemeral {
		fmt.Println("TEST ONLY: fresh signing key; private key was not saved. Each invocation has a new public key.")
	}
	fmt.Println("No sandbox was changed. Inspect with policy verify/check before applying with policy set or launch flags.")
	return 0
}

// Reserve the final directory with exclusive Mkdir, not a rename that could
// replace another caller's output. Nothing is published until signing and
// activation validation succeed. On I/O failure, remove only our new tree.
func writePolicyOutput(dir string, signed policy.SignedDocument) (err error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create new policy output (existing paths are never overwritten): %w", err)
	}
	defer func() {
		if err != nil {
			if cleanupErr := os.RemoveAll(dir); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("remove incomplete policy output: %w", cleanupErr))
			}
		}
	}()
	if err := os.Mkdir(filepath.Join(dir, "source"), 0o700); err != nil {
		return err
	}
	for _, file := range []struct {
		path string
		data []byte
	}{
		{filepath.Join("source", "data.json"), signed.Data},
		{"bundle.tar.gz", signed.Bundle},
		{"public.pem", signed.PublicKey},
	} {
		f, err := os.OpenFile(filepath.Join(dir, file.path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(file.data)
		if err := errors.Join(writeErr, f.Close()); err != nil {
			return err
		}
	}
	return nil
}
