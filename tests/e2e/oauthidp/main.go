// oauthidp runs Gantry's disposable OAuth authorization server for the
// cross-platform real-VM custody battery. It emits one bounded JSON readiness
// record and otherwise keeps protocol credentials out of process output.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/ejpir/gantry/internal/orgauth/testidp"
)

func main() {
	provider := testidp.NewOAuth()
	defer provider.Close()
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Origin         string `json:"origin"`
		ClientID       string `json:"client_id"`
		Scope          string `json:"scope"`
		GitHubClientID string `json:"github_client_id"`
		GitHubScope    string `json:"github_scope"`
	}{
		Origin: provider.URL(), ClientID: testidp.OAuthClientID,
		Scope: testidp.OAuthScope, GitHubClientID: testidp.GitHubClientID,
		GitHubScope: testidp.GitHubScope,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "oauth fixture readiness failed")
		os.Exit(1)
	}
	stdinClosed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stdinClosed)
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	select {
	case <-signals:
	case <-stdinClosed:
	}
}
