package main

// gantry-guest oauth login <name> delegates to a host-owned registration.
// The guest receives browser instructions and completion status only. The
// daemon owns PKCE/device codes, exchange, refresh, and token delivery policy.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
)

func runOAuth(args []string) {
	if len(args) != 2 || args[0] != "login" {
		fmt.Fprintln(os.Stderr, "usage: gantry-guest oauth login <provider>")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := oauthLogin(ctx, strings.ToLower(args[1]), oauthRoundTrip, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gantry-guest:", err)
		os.Exit(1)
	}
}

func oauthLogin(ctx context.Context, provider string, roundTrip func(credproto.Request) (credproto.Response, error), out io.Writer) error {
	resp, err := roundTrip(credproto.Request{Op: credproto.OpOAuthLogin, Provider: provider})
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	if resp.State == "" || resp.AuthorizeURL == "" {
		return fmt.Errorf("host returned incomplete OAuth login instructions")
	}
	if _, err := fmt.Fprintf(out, "Open this URL in your HOST browser to log in:\n\n%s\n\n", resp.AuthorizeURL); err != nil {
		return err
	}
	if resp.UserCode != "" {
		if _, err := fmt.Fprintf(out, "Enter this code: %s\n\n", resp.UserCode); err != nil {
			return err
		}
	}
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("login timed out waiting for browser authorization")
		}
		st, err := roundTrip(credproto.Request{Op: credproto.OpOAuthStatus, Provider: provider, State: resp.State})
		if err != nil {
			return err
		}
		if st.Error != "" {
			return fmt.Errorf("%s", st.Error)
		}
		if st.OK {
			_, err := fmt.Fprintln(out, st.Message)
			return err
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func oauthRoundTrip(req credproto.Request) (credproto.Response, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return credproto.Response{}, err
	}
	return brokerRoundTrip(raw)
}
