package ext4view

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/diskfs/go-diskfs/filesystem/ext4/crc"
)

const testBlockSize = 4096

func TestNewReplaysCommittedJournalWithoutChangingSource(t *testing.T) {
	path := makeJournalImage(t, true, 0)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	view, result, err := New(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.Close() }()
	if !result.JournalReplayed || result.BlocksReplayed != 1 {
		t.Fatalf("recovery result = %+v", result)
	}

	recovered := make([]byte, testBlockSize)
	if err := readFullAt(view, recovered, 3*testBlockSize); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, bytes.Repeat([]byte{'J'}, testBlockSize)) {
		t.Fatal("committed journal data was not overlaid")
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original[3*testBlockSize:4*testBlockSize], bytes.Repeat([]byte{'H'}, testBlockSize)) {
		t.Fatal("journal replay modified the source image")
	}
}

func TestNewDoesNotReplayUncommittedTransaction(t *testing.T) {
	path := makeJournalImage(t, false, 0)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	view, result, err := New(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.Close() }()
	if result.JournalReplayed || result.BlocksReplayed != 0 {
		t.Fatalf("uncommitted recovery result = %+v", result)
	}
	block := make([]byte, testBlockSize)
	if err := readFullAt(view, block, 3*testBlockSize); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, bytes.Repeat([]byte{'H'}, testBlockSize)) {
		t.Fatal("uncommitted journal data was exposed")
	}
}

func TestNewRejectsUnsupportedJournalChecksums(t *testing.T) {
	path := makeJournalImage(t, true, jbd2IncompatChecksumV3)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, _, err := New(file); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("New error = %v, want unsupported checksum", err)
	}
}

func TestReadAtSynthesizesChecksumsOnlyWithoutMetadataCSum(t *testing.T) {
	path := makeJournalImage(t, true, 0)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	view, _, err := New(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.Close() }()

	const inodeNumber = uint32(11)
	offset := int64(4*testBlockSize + (inodeNumber-1)*256)
	inode := make([]byte, 256)
	if err := readFullAt(view, inode, offset); err != nil {
		t.Fatal(err)
	}
	onDisk := uint32(binary.LittleEndian.Uint16(inode[0x7c:0x7e])) |
		uint32(binary.LittleEndian.Uint16(inode[0x82:0x84]))<<16
	inode[0x7c], inode[0x7d], inode[0x82], inode[0x83] = 0, 0, 0, 0
	var value [4]byte
	binary.LittleEndian.PutUint32(value[:], inodeNumber)
	calculated := crc.CRC32c(0, value[:])
	binary.LittleEndian.PutUint32(value[:], binary.LittleEndian.Uint32(inode[0x64:0x68]))
	calculated = crc.CRC32c(calculated, value[:])
	calculated = crc.CRC32c(calculated, inode)
	if onDisk != calculated {
		t.Fatalf("synthesized inode checksum = %x, want %x", onDisk, calculated)
	}
}

func makeJournalImage(t *testing.T, committed bool, journalFeatures uint32) string {
	t.Helper()
	path := t.TempDir() + "/journal.ext4"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(64 * testBlockSize); err != nil {
		t.Fatal(err)
	}
	writeBlock := func(block uint64, data []byte) {
		t.Helper()
		if len(data) != testBlockSize {
			t.Fatalf("block %d has %d bytes", block, len(data))
		}
		if _, err := file.WriteAt(data, int64(block*testBlockSize)); err != nil {
			t.Fatal(err)
		}
	}

	superblock := make([]byte, ext4SuperblockSize)
	binary.LittleEndian.PutUint32(superblock[0x00:0x04], 32) // inodes
	binary.LittleEndian.PutUint32(superblock[0x04:0x08], 64) // blocks
	binary.LittleEndian.PutUint32(superblock[0x18:0x1c], 2)  // 4 KiB
	binary.LittleEndian.PutUint32(superblock[0x20:0x24], 64)
	binary.LittleEndian.PutUint32(superblock[0x28:0x2c], 32)
	binary.LittleEndian.PutUint16(superblock[0x38:0x3a], ext4Magic)
	binary.LittleEndian.PutUint16(superblock[0x58:0x5a], 256)
	binary.LittleEndian.PutUint32(superblock[0x5c:0x60], ext4CompatJournal)
	binary.LittleEndian.PutUint32(superblock[0x60:0x64], ext4IncompatRecovery|ext4IncompatExtents|ext4Incompat64Bit)
	binary.LittleEndian.PutUint32(superblock[0xe0:0xe4], 8)
	binary.LittleEndian.PutUint16(superblock[0xfe:0x100], 64)
	if _, err := file.WriteAt(superblock, ext4SuperblockOffset); err != nil {
		t.Fatal(err)
	}

	groupDescriptor := make([]byte, testBlockSize)
	binary.LittleEndian.PutUint32(groupDescriptor[0x08:0x0c], 4) // inode table
	writeBlock(1, groupDescriptor)

	inodeTable := make([]byte, 2*testBlockSize)
	journalInode := inodeTable[7*256 : 8*256]
	binary.LittleEndian.PutUint16(journalInode[0:2], 0o100600)
	binary.LittleEndian.PutUint32(journalInode[0x04:0x08], 8*testBlockSize)
	binary.LittleEndian.PutUint32(journalInode[0x20:0x24], 0x80000) // extents
	extentRoot := journalInode[0x28:0x64]
	binary.LittleEndian.PutUint16(extentRoot[0:2], 0xf30a)
	binary.LittleEndian.PutUint16(extentRoot[2:4], 1)
	binary.LittleEndian.PutUint16(extentRoot[4:6], 4)
	binary.LittleEndian.PutUint16(extentRoot[12+4:12+6], 8)
	binary.LittleEndian.PutUint32(extentRoot[12+8:12+12], 16)
	// Deliberately stale checksum fields on inode 11 exercise the compatibility
	// patch for filesystems created without metadata_csum.
	inode11 := inodeTable[10*256 : 11*256]
	binary.LittleEndian.PutUint32(inode11[0x64:0x68], 7)
	binary.LittleEndian.PutUint32(inode11[0x7c:0x80], 0xdeadbeef)
	writeBlock(4, inodeTable[:testBlockSize])
	writeBlock(5, inodeTable[testBlockSize:])

	writeBlock(3, bytes.Repeat([]byte{'H'}, testBlockSize))
	journalSuper := make([]byte, testBlockSize)
	binary.BigEndian.PutUint32(journalSuper[0:4], jbd2Magic)
	binary.BigEndian.PutUint32(journalSuper[4:8], jbd2SuperblockV2)
	binary.BigEndian.PutUint32(journalSuper[0x0c:0x10], testBlockSize)
	binary.BigEndian.PutUint32(journalSuper[0x10:0x14], 8)
	binary.BigEndian.PutUint32(journalSuper[0x14:0x18], 1)
	binary.BigEndian.PutUint32(journalSuper[0x18:0x1c], 2)
	binary.BigEndian.PutUint32(journalSuper[0x1c:0x20], 1)
	binary.BigEndian.PutUint32(journalSuper[0x28:0x2c], jbd2Incompat64Bit|journalFeatures)
	writeBlock(16, journalSuper)

	descriptor := make([]byte, testBlockSize)
	binary.BigEndian.PutUint32(descriptor[0:4], jbd2Magic)
	binary.BigEndian.PutUint32(descriptor[4:8], jbd2Descriptor)
	binary.BigEndian.PutUint32(descriptor[8:12], 2)
	binary.BigEndian.PutUint32(descriptor[12:16], 3)
	binary.BigEndian.PutUint32(descriptor[16:20], jbd2TagSameUUID|jbd2TagLast)
	writeBlock(17, descriptor)
	writeBlock(18, bytes.Repeat([]byte{'J'}, testBlockSize))
	if committed {
		commit := make([]byte, testBlockSize)
		binary.BigEndian.PutUint32(commit[0:4], jbd2Magic)
		binary.BigEndian.PutUint32(commit[4:8], jbd2Commit)
		binary.BigEndian.PutUint32(commit[8:12], 2)
		writeBlock(19, commit)
	}
	return path
}
