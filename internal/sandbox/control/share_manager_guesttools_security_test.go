//go:build linux || darwin

package control

import (
	"context"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/shares"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestGuestToolsPayloadReadOnlyAndRetainedHandleRevokedAfterDelivery(t *testing.T) {
	m, _ := newGuestToolsShareManager(t, policytest.Signed(t, policy.Profile{}))
	const payload = "trusted helper bytes"
	var fileNode uint64
	var readIn []byte
	err := m.WithGuestToolsShare(context.Background(), []byte(payload), func(entry shares.Entry) error {
		retainManagerShareRoot(t, m.Hub(), entry.Tag)
		lookup := func(parent uint64, name string) uint64 {
			data := append([]byte(name), 0)
			out := managerFuseRequest(t, m.Hub(), [][]byte{managerFuseHeader(1, 10, parent, len(data)), data}, 128)
			return binary.LittleEndian.Uint64(out[1][:8])
		}
		root := lookup(1, entry.Tag)
		fileNode = lookup(root, "gantry-guest")
		openIn := make([]byte, 8)
		opened := managerFuseRequest(t, m.Hub(), [][]byte{managerFuseHeader(14, 11, fileNode, len(openIn)), openIn}, 16)
		readIn = make([]byte, 40)
		copy(readIn[:8], opened[1][:8])
		binary.LittleEndian.PutUint32(readIn[16:20], uint32(len(payload)))
		out := managerFuseRequest(t, m.Hub(), [][]byte{managerFuseHeader(15, 12, fileNode, len(readIn)), readIn}, len(payload))
		if string(out[1]) != payload {
			t.Fatalf("guest read = %q", out[1])
		}

		binary.LittleEndian.PutUint32(openIn[:4], uint32(os.O_WRONLY))
		out = [][]byte{make([]byte, 16), make([]byte, 16)}
		_, status := m.Hub().HandleRequest([][]byte{managerFuseHeader(14, 13, fileNode, len(openIn)), openIn}, out)
		if status != fuse.OK || int32(binary.LittleEndian.Uint32(out[0][4:8])) != -int32(fuse.EROFS) {
			t.Fatalf("writable helper open not refused: %v %v", status, out[0])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	out := [][]byte{make([]byte, 16), make([]byte, len(payload))}
	_, status := m.Hub().HandleRequest([][]byte{managerFuseHeader(15, 14, fileNode, len(readIn)), readIn}, out)
	if status != fuse.OK || int32(binary.LittleEndian.Uint32(out[0][4:8])) != -int32(fuse.ESTALE) {
		t.Fatalf("retained helper handle still usable: %v %v", status, out[0])
	}
}

func TestGuestToolsPayloadStillRejectsProtectedStateAndOverlappingExports(t *testing.T) {
	m, _ := newGuestToolsShareManager(t, nil)
	err := withGuestToolsStage(m.dir, []byte("helper"), func(path string) error {
		_, _, err := m.addGuestToolsShare(path)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "overlaps Gantry state root") {
		t.Fatalf("internal payload bypassed state barrier: %v", err)
	}
	root := t.TempDir()
	if _, err := m.Add("code="+root+",ro", false, false); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", root)
	if err := m.WithGuestToolsShare(context.Background(), []byte("helper"), func(shares.Entry) error { t.Fatal("overlapping payload published"); return nil }); err == nil || !strings.Contains(err.Error(), "overlaps share") {
		t.Fatalf("internal payload bypassed overlap barrier: %v", err)
	}
}
