package main

import (
	"strings"
	"testing"
)

func TestReadCredentialQuery(t *testing.T) {
	q, err := readCredentialQuery(strings.NewReader("protocol=https\nhost=github.com\npath=org/repo.git\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if q["protocol"] != "https" || q["host"] != "github.com" || q["path"] != "org/repo.git" {
		t.Fatalf("query = %v", q)
	}

	// EOF without the blank terminator is still a complete query.
	q, err = readCredentialQuery(strings.NewReader("host=github.com"))
	if err != nil || q["host"] != "github.com" {
		t.Fatalf("query = %v, err = %v", q, err)
	}

	// Lines without '=' are ignored, not fatal.
	q, err = readCredentialQuery(strings.NewReader("garbage\nhost=x\n"))
	if err != nil || len(q) != 1 {
		t.Fatalf("query = %v, err = %v", q, err)
	}
}
