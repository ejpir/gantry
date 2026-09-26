package controlcmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// cmdPolicyKeygen creates a stable organization signing key: an owner-only
// private key for administrators and the public key every host pins.
func cmdPolicyKeygen(args []string) int {
	fs := flag.NewFlagSet("policy keygen", flag.ContinueOnError)
	out := fs.String("out", "", "new output directory (never overwritten); keep it outside source trees and guest shares")
	bits := fs.Int("bits", 3072, "RSA key size, 2048..4096")
	if code := parsePolicyAuthorFlags(fs, args); code >= 0 {
		return code
	}
	if *bits < 2048 || *bits > 4096 {
		return policyAuthorError(fmt.Errorf("-bits must be 2048..4096"))
	}
	dir, err := newPolicyOutputPath(*out)
	if err != nil {
		return policyAuthorError(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		return policyAuthorError(fmt.Errorf("generate signing key failed"))
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return policyAuthorError(err)
	}
	if err := localsec.CreateDir(dir); err != nil {
		return policyAuthorError(err)
	}
	keyPath := filepath.Join(dir, "signing-key.pem")
	if err := atomicfile.WriteFileDurable(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		return policyAuthorError(err)
	}
	if err := localsec.SecureRegularFile(keyPath); err != nil {
		return policyAuthorError(err)
	}
	publicPath := filepath.Join(dir, "public.pem")
	if err := atomicfile.WriteFileDurable(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), 0o644); err != nil {
		return policyAuthorError(err)
	}
	sum := sha256.Sum256(public)
	fmt.Printf("Signing key: %s (owner-only; keep it off shared and synced storage)\nPublic key: %s\nFingerprint: sha256:%s\n", keyPath, publicPath, hex.EncodeToString(sum[:]))
	return 0
}
