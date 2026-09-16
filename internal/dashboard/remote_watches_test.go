package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/remote"
)

func TestRemoteWatchesAdoptAddAndRemoveWithoutDashboardRestart(t *testing.T) {
	m, _ := onboardingModel(t)
	profile := onboardingManager(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/events":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, ": ready\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/v1/sandboxes":
			_ = json.NewEncoder(w).Encode(map[string]any{"sandboxes": []managerapi.Sandbox{{Name: "remote-dev", State: "running"}}})
		default:
			t.Errorf("unexpected watch endpoint %s", r.URL.Path)
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	events := make(chan tea.Msg, 32)
	stop := startRemoteWatches(ctx, func(msg tea.Msg) {
		select {
		case events <- msg:
		case <-ctx.Done():
		}
	})
	defer stop()
	if err := remote.Add(profile, onboardTestToken); err != nil {
		t.Fatal(err)
	}
	wait := func(removed bool) {
		t.Helper()
		timer := time.NewTimer(7 * time.Second)
		defer timer.Stop()
		for {
			select {
			case event := <-events:
				m.Update(event)
				if msg, ok := event.(remoteSectionMsg); ok && msg.snapshot.Remote == profile.Name && (removed && msg.removed || !removed && len(msg.snapshot.Sandboxes) == 1) {
					return
				}
			case <-timer.C:
				t.Fatal("dashboard did not adopt profile change")
			}
		}
	}
	wait(false)
	if len(m.sandboxes) != 0 {
		t.Fatal("remote watch inserted local action rows")
	}
	if err := remote.Remove(profile.Name); err != nil {
		t.Fatal(err)
	}
	wait(true)
	if len(m.remotes) != 0 {
		t.Fatal("removed profile retained rows")
	}
}
