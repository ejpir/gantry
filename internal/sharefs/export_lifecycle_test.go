//go:build linux || darwin || windows

package sharefs

import (
	"reflect"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
)

type recordingShareWatcher struct{ events *[]string }

func (*recordingShareWatcher) WatchDirectory(string) error { return nil }
func (*recordingShareWatcher) ForgetDirectory(string)      {}
func (*recordingShareWatcher) Reset() error                { return nil }
func (watcher *recordingShareWatcher) Close() error {
	*watcher.events = append(*watcher.events, "watcher")
	return nil
}

func TestExportLifecycleTransitions(t *testing.T) {
	tests := []struct {
		current ExportState
		next    ExportState
		valid   bool
	}{
		{ExportActive, ExportDraining, true},
		{ExportActive, ExportRevoked, true},
		{ExportActive, ExportGone, false},
		{ExportDraining, ExportActive, false},
		{ExportDraining, ExportRevoked, true},
		{ExportDraining, ExportGone, false},
		{ExportRevoked, ExportGone, true},
		{ExportRevoked, ExportDraining, false},
		{ExportGone, ExportGone, false},
	}
	for _, test := range tests {
		if got := validExportTransition(test.current, test.next); got != test.valid {
			t.Errorf("transition %s -> %s = %v, want %v", test.current, test.next, got, test.valid)
		}
	}
}

func TestExportFinishReleasesWatcherBeforePinnedRoot(t *testing.T) {
	var events []string
	export := &Export{release: func() { events = append(events, "root") }}
	export.state.Store(int32(ExportActive))
	export.coherence = &exportCoherence{
		export: export, paths: make(map[string]coherencePath), reverse: make(map[*fs.Inode]map[string]struct{}),
		watcher: &recordingShareWatcher{events: &events},
	}
	export.coherence.healthy.Store(true)
	export.finishNow()
	if want := []string{"watcher", "root"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("release order = %v, want %v", events, want)
	}
}

func TestExportFinishPublishesGoneAfterRelease(t *testing.T) {
	releaseEntered := make(chan struct{})
	releaseContinue := make(chan struct{})
	export := &Export{release: func() {
		close(releaseEntered)
		<-releaseContinue
	}}
	export.state.Store(int32(ExportActive))
	done := make(chan struct{})
	go func() {
		export.finishNow()
		close(done)
	}()
	<-releaseEntered
	if got := export.State(); got != ExportRevoked {
		t.Fatalf("state during root release = %s, want revoked", got)
	}
	close(releaseContinue)
	<-done
	if got := export.State(); got != ExportGone {
		t.Fatalf("state after root release = %s, want gone", got)
	}
}
