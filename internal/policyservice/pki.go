package policyservice

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	serverValidity = 2 * 365 * 24 * time.Hour
	hostValidity   = 365 * 24 * time.Hour
	maxPEMBytes    = 64 << 10
)

// newCA creates the organization's host CA. It issues the service's TLS
// certificate and every host's client certificate; the service is the only
// relying party for client certificates, so revocation is a state lookup.
func newCA(organization string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: organization + " hosts CA", Organization: []string{organization}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	return certificate, key, err
}

// issueServer creates the TLS certificate hosts and administrators verify.
func issueServer(ca *x509.Certificate, caKey crypto.Signer, organization string, names []string, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{organization}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     earliest(now.Add(serverValidity), ca.NotAfter),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
}

// signHostRequest issues a client certificate for a host's own key. Only the
// public key and proof of possession are taken from the request; the subject
// and usage are set here.
func signHostRequest(ca *x509.Certificate, caKey crypto.Signer, organization, name string, csrPEM []byte, now time.Time) (*x509.Certificate, error) {
	if len(csrPEM) > maxPEMBytes {
		return nil, fmt.Errorf("certificate request is too large")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("certificate request must be one PEM CERTIFICATE REQUEST")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		return nil, fmt.Errorf("certificate request is invalid or not signed by its key")
	}
	switch key := request.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() {
			return nil, fmt.Errorf("host keys must be ECDSA P-256/P-384, Ed25519, or RSA of at least 2048 bits")
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return nil, fmt.Errorf("host keys must be ECDSA P-256/P-384, Ed25519, or RSA of at least 2048 bits")
		}
	default:
		return nil, fmt.Errorf("host keys must be ECDSA P-256/P-384, Ed25519, or RSA of at least 2048 bits")
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: name, Organization: []string{organization}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     earliest(now.Add(hostValidity), ca.NotAfter),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, request.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// NewHostRequest creates a host's private key and certificate request.
func NewHostRequest(name string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("PRIVATE KEY", keyDER), pemBlock("CERTIFICATE REQUEST", der), nil
}

func parseCertificatePEM(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseSignerPEM(raw []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected a PEM PKCS#8 private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key")
	}
	return signer, nil
}

// publicKeyInfo fingerprints the organization's RSA verification key the
// same way for every client: SHA-256 over its DER SubjectPublicKeyInfo.
func publicKeyInfo(raw []byte) (keyPrint string, bits int, err error) {
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 && len(trimSpace(rest)) != 0 {
		return "", 0, fmt.Errorf("public key must be one PEM RSA public key")
	}
	var key any
	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		err = fmt.Errorf("only public keys are accepted")
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if err != nil || !ok || rsaKey.N.BitLen() < 2048 {
		return "", 0, fmt.Errorf("organization key must be an RSA public key of at least 2048 bits")
	}
	der, err := x509.MarshalPKIXPublicKey(rsaKey)
	if err != nil {
		return "", 0, err
	}
	return fingerprint(der), rsaKey.N.BitLen(), nil
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newToken returns 64 hex characters of fresh randomness.
func newToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func randomSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return serial.Add(serial, big.NewInt(1))
}

func pemBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func trimSpace(raw []byte) []byte {
	for len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\n' || raw[0] == '\r' || raw[0] == '\t') {
		raw = raw[1:]
	}
	return raw
}
