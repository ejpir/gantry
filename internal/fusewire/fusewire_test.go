package fusewire

import (
	"encoding/binary"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestWriteErrorAcrossIOVs(t *testing.T) {
	request := make([]byte, InHeaderSize)
	binary.LittleEndian.PutUint64(request[8:16], 0x1020304050607080)
	in := [][]byte{request[:5], request[5:]}
	out := [][]byte{make([]byte, 3), make([]byte, 7), make([]byte, 6)}

	if n := WriteError(in, out, fuse.EROFS); n != 16 {
		t.Fatalf("response length = %d, want 16", n)
	}
	var got [16]byte
	CopyPrefix(got[:], out)
	if length := binary.LittleEndian.Uint32(got[0:4]); length != 16 {
		t.Fatalf("header length = %d, want 16", length)
	}
	if errno := int32(binary.LittleEndian.Uint32(got[4:8])); errno != -int32(fuse.EROFS) {
		t.Fatalf("errno = %d, want %d", errno, -int32(fuse.EROFS))
	}
	if unique := binary.LittleEndian.Uint64(got[8:16]); unique != 0x1020304050607080 {
		t.Fatalf("unique = %#x", unique)
	}
}

func TestWriteErrorRejectsShortOutput(t *testing.T) {
	out := [][]byte{make([]byte, 8), make([]byte, 7)}
	if n := WriteError([][]byte{make([]byte, InHeaderSize)}, out, fuse.EIO); n != 0 {
		t.Fatalf("response length = %d, want 0", n)
	}
	for i, part := range out {
		for j, value := range part {
			if value != 0 {
				t.Fatalf("out[%d][%d] changed to %d", i, j, value)
			}
		}
	}
}

func TestValidRequestMatchesParserInputShape(t *testing.T) {
	tests := []struct {
		name string
		in   [][]byte
		want bool
	}{
		{name: "missing", want: false},
		{name: "short", in: [][]byte{make([]byte, InHeaderSize-1)}, want: false},
		{name: "split header", in: [][]byte{make([]byte, 7), make([]byte, InHeaderSize-7)}, want: true},
		{name: "header in third vector", in: [][]byte{nil, nil, make([]byte, InHeaderSize)}, want: false},
		{name: "complete", in: [][]byte{make([]byte, InHeaderSize)}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidRequest(tt.in); got != tt.want {
				t.Fatalf("ValidRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteErrorRejectsMalformedInput(t *testing.T) {
	out := [][]byte{make([]byte, outHeaderSize)}
	if n := WriteError([][]byte{make([]byte, InHeaderSize-1)}, out, fuse.EIO); n != 0 {
		t.Fatalf("response length = %d, want 0", n)
	}
	for i, value := range out[0] {
		if value != 0 {
			t.Fatalf("out[0][%d] changed to %d", i, value)
		}
	}
}
