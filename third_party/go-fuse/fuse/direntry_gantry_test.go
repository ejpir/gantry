package fuse

import (
	"testing"
	"unsafe"
)

func TestGantryReadDirEOFMarker(t *testing.T) {
	for _, prefix := range []int{0, int(unsafe.Sizeof(EntryOut{}))} {
		buffer := make([]byte, prefix+direntSize)
		entries := NewDirEntryList(buffer, 0)
		entries.enableGantryEOF(prefix)
		if !entries.MarkEOF() {
			t.Fatalf("prefix %d: marker did not fit", prefix)
		}
		if entries.MarkEOF() {
			t.Fatalf("prefix %d: duplicate marker appended", prefix)
		}
		if got := len(entries.bytes()); got != len(buffer) {
			t.Fatalf("prefix %d: marker length %d, want %d", prefix, got, len(buffer))
		}
		marker := (*_Dirent)(unsafe.Pointer(&entries.bytes()[prefix]))
		if marker.Ino != GANTRY_READDIR_EOF_INO || marker.Off != GANTRY_READDIR_EOF_OFF ||
			marker.NameLen != 0 || marker.Typ != GANTRY_READDIR_EOF_TYPE {
			t.Fatalf("prefix %d: malformed marker: %+v", prefix, marker)
		}
	}
}

func TestGantryReadDirEOFMarkerRequiresNegotiationAndSpace(t *testing.T) {
	entries := NewDirEntryList(make([]byte, direntSize), 0)
	if entries.MarkEOF() {
		t.Fatal("marker appended without negotiation")
	}

	entries = NewDirEntryList(make([]byte, direntSize-1), 0)
	entries.enableGantryEOF(0)
	if entries.MarkEOF() {
		t.Fatal("marker appended without space")
	}
	if got := len(entries.bytes()); got != 0 {
		t.Fatalf("short buffer grew to %d bytes", got)
	}
}
