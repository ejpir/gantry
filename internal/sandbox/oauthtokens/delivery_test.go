package oauthtokens

import (
	"testing"
	"time"
)

func TestCustodyDeliveryFailsClosed(t *testing.T) {
	r := New()
	for _, set := range []TokenSet{
		{Provider: "missing"},
		{Provider: "expired", AccessToken: "access", Expiry: time.Now().Add(-time.Second)},
	} {
		if err := r.Put(set); err != nil {
			t.Fatal(err)
		}
		if _, ok := r.AccessToken(set.Provider); ok {
			t.Fatal("unusable access token served")
		}
	}
	if err := r.Put(TokenSet{Provider: "github", AccessToken: "access"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.AccessToken("GITHUB"); !ok {
		t.Fatal("non-expiring token not served")
	}
	if err := r.Delete("github"); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.AccessToken("github"); ok {
		t.Fatal("revoked token served")
	}
}

func TestRefreshCannotOverwriteLoginOrResurrectRevocation(t *testing.T) {
	r := New()
	old := TokenSet{Provider: "company", AccessToken: "old", Registration: "context"}
	next := TokenSet{Provider: "company", AccessToken: "rotated", Registration: "context"}
	if err := r.Put(old); err != nil {
		t.Fatal(err)
	}
	if updated, err := r.UpdateIfCurrent(old, &next); err != nil || !updated {
		t.Fatal("current refresh not installed")
	}
	if updated, err := r.UpdateIfCurrent(old, nil); err != nil || updated {
		t.Fatal("stale failed refresh deleted newer token")
	}
	if err := r.Delete(next.Provider); err != nil {
		t.Fatal(err)
	}
	if updated, err := r.UpdateIfCurrent(next, &old); err != nil || updated {
		t.Fatal("refresh resurrected revoked token")
	}
}

func TestRegistrationContextPersists(t *testing.T) {
	dir := t.TempDir()
	r := New()
	r.AttachFile(dir)
	if err := r.Put(TokenSet{Provider: "company", AccessToken: "access", Registration: "context-hash"}); err != nil {
		t.Fatal(err)
	}
	restored := New()
	restored.AttachFile(dir)
	set, ok := restored.Get("company")
	if !ok || set.Registration != "context-hash" {
		t.Fatal("registration binding lost across restart")
	}
}
