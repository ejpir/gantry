package remoteprofile

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetadataRejectsNonPublicTrustAndInvalidOrigins(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	valid := Profile{Name: "team", URL: server.URL, CACert: ca}
	if err := Validate(valid); err != nil {
		t.Fatal(err)
	}
	for _, bundle := range []string{ca + "\n-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----\n", "secret\n" + ca, " \n", strings.Repeat("x", (64<<10)+1)} {
		if err := ValidateCA(bundle); err == nil {
			t.Fatal("nonpublic/invalid CA material accepted")
		}
	}
	for _, url := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com/path", "https://example.com?", "https://example.com#"} {
		candidate := valid
		candidate.URL = url
		if err := Validate(candidate); err == nil {
			t.Fatalf("invalid origin accepted: %s", url)
		}
	}
	valid.Name = "two.labels"
	if err := Validate(valid); err == nil {
		t.Fatal("ambiguous remote hostname accepted")
	}
}
