// Package ext4view exposes a read-only, journal-replayed view of an ext4
// filesystem to go-diskfs. Gantry normally stops a VM after a trusted guest
// sync rather than unmounting its writable disk. ext4 may therefore leave
// committed metadata in its JBD2 journal even though all bytes are durable.
// Replaying those committed blocks into this in-memory COW view lets offline
// readers observe the same state the kernel would recover on the next mount,
// without changing the sandbox disk.
package ext4view

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/diskfs/go-diskfs/backend"
	backendfile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/ext4/crc"
)

const (
	ext4SuperblockOffset = int64(1024)
	ext4SuperblockSize   = 1024
	ext4Magic            = 0xef53

	ext4CompatJournal        = uint32(0x0004)
	ext4IncompatRecovery     = uint32(0x0004)
	ext4IncompatJournalDev   = uint32(0x0008)
	ext4IncompatExtents      = uint32(0x0040)
	ext4Incompat64Bit        = uint32(0x0080)
	ext4ROCompatMetadataCSum = uint32(0x0400)

	jbd2Magic              = uint32(0xc03b3998)
	jbd2Descriptor         = uint32(1)
	jbd2Commit             = uint32(2)
	jbd2SuperblockV1       = uint32(3)
	jbd2SuperblockV2       = uint32(4)
	jbd2Revoke             = uint32(5)
	jbd2CompatChecksum     = uint32(0x1)
	jbd2IncompatRevoke     = uint32(0x1)
	jbd2Incompat64Bit      = uint32(0x2)
	jbd2IncompatChecksumV3 = uint32(0x10) // test coverage for unsupported features
	jbd2TagEscape          = uint32(0x1)
	jbd2TagSameUUID        = uint32(0x2)
	jbd2TagDeleted         = uint32(0x4)
	jbd2TagLast            = uint32(0x8)
)

// Result reports whether committed journal blocks were overlaid. The source
// file itself is never written.
type Result struct {
	JournalReplayed bool
	BlocksReplayed  int
}

type inodeTable struct {
	start int64
	end   int64
	group uint32
}

type storage struct {
	backend.Storage
	blockSize          int64
	blockCount         uint64
	overlay            map[uint64][]byte
	inodeTables        []inodeTable
	inodeSize          int64
	inodesPerGroup     uint32
	checksumSeed       uint32
	patchInodeChecksum bool
}

type ext4Superblock struct {
	blockSize      uint32
	blockCount     uint64
	inodeCount     uint32
	blocksPerGroup uint32
	inodesPerGroup uint32
	inodeSize      uint16
	descriptorSize uint16
	compat         uint32
	incompat       uint32
	roCompat       uint32
	journalInode   uint32
	checksumSeed   uint32
}

type extent struct {
	logical  uint32
	physical uint64
	count    uint32
}

type journal struct {
	view      *storage
	extents   []extent
	maxLen    uint32
	first     uint32
	sequence  uint32
	start     uint32
	incompat  uint32
	blockSize uint32
}

type journalTag struct {
	block uint64
	flags uint32
}

// New returns a backend suitable for ext4.Read. It owns file through the
// returned backend and closes it when Storage.Close is called.
func New(file *os.File) (backend.Storage, Result, error) {
	if file == nil {
		return nil, Result{}, errors.New("ext4 view has no source file")
	}
	base := backendfile.New(file, true)
	rawSuperblock := make([]byte, ext4SuperblockSize)
	if err := readFullAt(base, rawSuperblock, ext4SuperblockOffset); err != nil {
		return nil, Result{}, fmt.Errorf("read ext4 superblock: %w", err)
	}
	superblock, err := parseExt4Superblock(rawSuperblock)
	if err != nil {
		return nil, Result{}, err
	}
	info, err := base.Stat()
	if err != nil {
		return nil, Result{}, fmt.Errorf("stat ext4 image: %w", err)
	}
	filesystemSize := superblock.blockCount * uint64(superblock.blockSize)
	if filesystemSize > uint64(info.Size()) {
		return nil, Result{}, fmt.Errorf("ext4 filesystem is %d bytes but its image is only %d bytes", filesystemSize, info.Size())
	}
	view := &storage{
		Storage:    base,
		blockSize:  int64(superblock.blockSize),
		blockCount: superblock.blockCount,
		overlay:    make(map[uint64][]byte),
	}
	result := Result{}
	if superblock.incompat&ext4IncompatRecovery != 0 {
		if superblock.compat&ext4CompatJournal == 0 || superblock.journalInode == 0 {
			return nil, Result{}, errors.New("ext4 recovery is required but the filesystem has no internal journal")
		}
		if superblock.incompat&ext4IncompatJournalDev != 0 {
			return nil, Result{}, errors.New("ext4 recovery from an external journal is not supported")
		}
		journalExtents, err := readJournalExtents(base, superblock)
		if err != nil {
			return nil, Result{}, fmt.Errorf("read ext4 journal inode: %w", err)
		}
		journal, err := openJournal(view, journalExtents)
		if err != nil {
			return nil, Result{}, err
		}
		replayed, err := journal.replay()
		if err != nil {
			return nil, Result{}, fmt.Errorf("replay ext4 journal: %w", err)
		}
		result.JournalReplayed = replayed > 0
		result.BlocksReplayed = replayed
	}

	// Journal replay may replace the primary superblock or group descriptor
	// table. Build inode locations from the recovered view, not stale home
	// blocks.
	recoveredBytes := make([]byte, ext4SuperblockSize)
	if err := readFullAt(view, recoveredBytes, ext4SuperblockOffset); err != nil {
		return nil, Result{}, fmt.Errorf("read recovered ext4 superblock: %w", err)
	}
	recovered, err := parseExt4Superblock(recoveredBytes)
	if err != nil {
		return nil, Result{}, err
	}
	if recovered.blockSize != superblock.blockSize || recovered.blockCount != superblock.blockCount ||
		recovered.inodeCount != superblock.inodeCount || recovered.blocksPerGroup != superblock.blocksPerGroup ||
		recovered.inodesPerGroup != superblock.inodesPerGroup || recovered.inodeSize != superblock.inodeSize ||
		recovered.descriptorSize != superblock.descriptorSize {
		return nil, Result{}, errors.New("ext4 journal changed fundamental filesystem geometry")
	}
	if err := view.configureInodeTables(recovered); err != nil {
		return nil, Result{}, err
	}
	return view, result, nil
}

func parseExt4Superblock(data []byte) (ext4Superblock, error) {
	if len(data) != ext4SuperblockSize {
		return ext4Superblock{}, fmt.Errorf("ext4 superblock has %d bytes, want %d", len(data), ext4SuperblockSize)
	}
	if binary.LittleEndian.Uint16(data[0x38:0x3a]) != ext4Magic {
		return ext4Superblock{}, errors.New("invalid ext4 superblock magic")
	}
	logBlockSize := binary.LittleEndian.Uint32(data[0x18:0x1c])
	if logBlockSize > 2 {
		return ext4Superblock{}, fmt.Errorf("unsupported ext4 block-size shift %d", logBlockSize)
	}
	blockSize := uint32(1024) << logBlockSize
	compat := binary.LittleEndian.Uint32(data[0x5c:0x60])
	incompat := binary.LittleEndian.Uint32(data[0x60:0x64])
	roCompat := binary.LittleEndian.Uint32(data[0x64:0x68])
	blockCount := uint64(binary.LittleEndian.Uint32(data[0x04:0x08]))
	descriptorSize := uint16(32)
	if incompat&ext4Incompat64Bit != 0 {
		blockCount |= uint64(binary.LittleEndian.Uint32(data[0x150:0x154])) << 32
		descriptorSize = binary.LittleEndian.Uint16(data[0xfe:0x100])
		if descriptorSize != 64 {
			return ext4Superblock{}, fmt.Errorf("unsupported 64-bit ext4 descriptor size %d", descriptorSize)
		}
	}
	blocksPerGroup := binary.LittleEndian.Uint32(data[0x20:0x24])
	inodesPerGroup := binary.LittleEndian.Uint32(data[0x28:0x2c])
	inodeSize := binary.LittleEndian.Uint16(data[0x58:0x5a])
	inodeCount := binary.LittleEndian.Uint32(data[0x00:0x04])
	if blockCount == 0 || blockCount > uint64(math.MaxInt64)/uint64(blockSize) || inodeCount == 0 ||
		blocksPerGroup == 0 || inodesPerGroup == 0 || inodeSize < 128 || inodeSize > uint16(blockSize) {
		return ext4Superblock{}, errors.New("invalid ext4 filesystem geometry")
	}
	return ext4Superblock{
		blockSize:      blockSize,
		blockCount:     blockCount,
		inodeCount:     inodeCount,
		blocksPerGroup: blocksPerGroup,
		inodesPerGroup: inodesPerGroup,
		inodeSize:      inodeSize,
		descriptorSize: descriptorSize,
		compat:         compat,
		incompat:       incompat,
		roCompat:       roCompat,
		journalInode:   binary.LittleEndian.Uint32(data[0xe0:0xe4]),
		checksumSeed:   binary.LittleEndian.Uint32(data[0x270:0x274]),
	}, nil
}

func (s *storage) configureInodeTables(superblock ext4Superblock) error {
	if superblock.blockCount > uint64(math.MaxInt64)/uint64(superblock.blockSize) {
		return errors.New("ext4 filesystem size overflows host offsets")
	}
	filesystemSize := superblock.blockCount * uint64(superblock.blockSize)
	groups := (superblock.blockCount-1)/uint64(superblock.blocksPerGroup) + 1
	if groups == 0 || groups > 1<<20 {
		return fmt.Errorf("invalid ext4 block-group count %d", groups)
	}
	gdtBlock := uint64(1)
	if superblock.blockSize == 1024 {
		gdtBlock = 2
	}
	s.inodeTables = make([]inodeTable, 0, groups)
	for group := uint64(0); group < groups; group++ {
		descriptor := make([]byte, superblock.descriptorSize)
		offset := int64(gdtBlock*uint64(superblock.blockSize) + group*uint64(superblock.descriptorSize))
		if err := readFullAt(s, descriptor, offset); err != nil {
			return fmt.Errorf("read ext4 group descriptor %d: %w", group, err)
		}
		tableBlock := uint64(binary.LittleEndian.Uint32(descriptor[0x08:0x0c]))
		if superblock.incompat&ext4Incompat64Bit != 0 {
			tableBlock |= uint64(binary.LittleEndian.Uint32(descriptor[0x28:0x2c])) << 32
		}
		start := tableBlock * uint64(superblock.blockSize)
		length := uint64(superblock.inodesPerGroup) * uint64(superblock.inodeSize)
		if tableBlock >= superblock.blockCount || start > math.MaxUint64-length || start+length > filesystemSize {
			return fmt.Errorf("invalid inode table in ext4 group %d", group)
		}
		s.inodeTables = append(s.inodeTables, inodeTable{start: int64(start), end: int64(start + length), group: uint32(group)})
	}
	s.inodeSize = int64(superblock.inodeSize)
	s.inodesPerGroup = superblock.inodesPerGroup
	s.checksumSeed = superblock.checksumSeed
	// go-diskfs v1.9.4 checks every inode checksum unconditionally. ext4 does
	// not maintain those fields when metadata_csum is disabled, so Linux writes
	// make them stale. Synthesize exactly the value the reader expects.
	s.patchInodeChecksum = superblock.roCompat&ext4ROCompatMetadataCSum == 0
	return nil
}

func readJournalExtents(source io.ReaderAt, superblock ext4Superblock) ([]extent, error) {
	if superblock.incompat&ext4IncompatExtents == 0 {
		return nil, errors.New("journal inode does not use extents")
	}
	inode, err := readRawInode(source, superblock, superblock.journalInode)
	if err != nil {
		return nil, err
	}
	if len(inode) < 0x64 {
		return nil, errors.New("journal inode is truncated")
	}
	return parseExtentNode(source, superblock, inode[0x28:0x64], 0)
}

func readRawInode(source io.ReaderAt, superblock ext4Superblock, inodeNumber uint32) ([]byte, error) {
	if inodeNumber == 0 || inodeNumber > superblock.inodeCount {
		return nil, fmt.Errorf("invalid inode number %d", inodeNumber)
	}
	group := uint64(inodeNumber-1) / uint64(superblock.inodesPerGroup)
	groups := (superblock.blockCount-1)/uint64(superblock.blocksPerGroup) + 1
	if group >= groups {
		return nil, fmt.Errorf("inode %d has invalid block group %d", inodeNumber, group)
	}
	gdtBlock := uint64(1)
	if superblock.blockSize == 1024 {
		gdtBlock = 2
	}
	descriptor := make([]byte, superblock.descriptorSize)
	descriptorOffset := int64(gdtBlock*uint64(superblock.blockSize) + group*uint64(superblock.descriptorSize))
	if err := readFullAt(source, descriptor, descriptorOffset); err != nil {
		return nil, err
	}
	tableBlock := uint64(binary.LittleEndian.Uint32(descriptor[0x08:0x0c]))
	if superblock.incompat&ext4Incompat64Bit != 0 {
		tableBlock |= uint64(binary.LittleEndian.Uint32(descriptor[0x28:0x2c])) << 32
	}
	index := uint64(inodeNumber-1) % uint64(superblock.inodesPerGroup)
	offset := tableBlock*uint64(superblock.blockSize) + index*uint64(superblock.inodeSize)
	inode := make([]byte, superblock.inodeSize)
	if err := readFullAt(source, inode, int64(offset)); err != nil {
		return nil, err
	}
	return inode, nil
}

func parseExtentNode(source io.ReaderAt, superblock ext4Superblock, node []byte, recursion int) ([]extent, error) {
	if recursion > 5 || len(node) < 12 || binary.LittleEndian.Uint16(node[0:2]) != 0xf30a {
		return nil, errors.New("invalid ext4 extent tree")
	}
	entries := int(binary.LittleEndian.Uint16(node[2:4]))
	maximum := int(binary.LittleEndian.Uint16(node[4:6]))
	depth := binary.LittleEndian.Uint16(node[6:8])
	if entries > maximum || entries < 0 || 12+entries*12 > len(node) {
		return nil, errors.New("invalid ext4 extent count")
	}
	var result []extent
	for index := 0; index < entries; index++ {
		entry := node[12+index*12 : 24+index*12]
		logical := binary.LittleEndian.Uint32(entry[0:4])
		if depth == 0 {
			length := uint32(binary.LittleEndian.Uint16(entry[4:6]) & 0x7fff)
			physical := uint64(binary.LittleEndian.Uint16(entry[6:8]))<<32 | uint64(binary.LittleEndian.Uint32(entry[8:12]))
			if length == 0 || physical >= superblock.blockCount || uint64(length) > superblock.blockCount-physical {
				return nil, errors.New("invalid ext4 extent range")
			}
			result = append(result, extent{logical: logical, physical: physical, count: length})
			continue
		}
		childBlock := uint64(binary.LittleEndian.Uint32(entry[4:8])) | uint64(binary.LittleEndian.Uint16(entry[8:10]))<<32
		if childBlock >= superblock.blockCount {
			return nil, errors.New("invalid ext4 extent index")
		}
		child := make([]byte, superblock.blockSize)
		if err := readFullAt(source, child, int64(childBlock*uint64(superblock.blockSize))); err != nil {
			return nil, err
		}
		childExtents, err := parseExtentNode(source, superblock, child, recursion+1)
		if err != nil {
			return nil, err
		}
		result = append(result, childExtents...)
	}
	if len(result) == 0 {
		return nil, errors.New("ext4 journal has no data extents")
	}
	return result, nil
}

func openJournal(view *storage, extents []extent) (*journal, error) {
	block, err := readExtentBlock(view.Storage, extents, 0, uint32(view.blockSize))
	if err != nil {
		return nil, fmt.Errorf("read JBD2 superblock: %w", err)
	}
	if binary.BigEndian.Uint32(block[0:4]) != jbd2Magic {
		return nil, errors.New("invalid JBD2 superblock magic")
	}
	kind := binary.BigEndian.Uint32(block[4:8])
	if kind != jbd2SuperblockV1 && kind != jbd2SuperblockV2 {
		return nil, fmt.Errorf("invalid JBD2 superblock type %d", kind)
	}
	blockSize := binary.BigEndian.Uint32(block[0x0c:0x10])
	maxLen := binary.BigEndian.Uint32(block[0x10:0x14])
	first := binary.BigEndian.Uint32(block[0x14:0x18])
	start := binary.BigEndian.Uint32(block[0x1c:0x20])
	compat := binary.BigEndian.Uint32(block[0x24:0x28])
	incompat := binary.BigEndian.Uint32(block[0x28:0x2c])
	unsupported := incompat & ^uint32(jbd2IncompatRevoke|jbd2Incompat64Bit)
	if compat&jbd2CompatChecksum != 0 || unsupported != 0 {
		return nil, errors.New("JBD2 checksum or fast-commit recovery is not supported")
	}
	if blockSize != uint32(view.blockSize) || maxLen < 2 || first == 0 || first >= maxLen || start >= maxLen {
		return nil, errors.New("invalid JBD2 geometry")
	}
	return &journal{
		view:      view,
		extents:   extents,
		maxLen:    maxLen,
		first:     first,
		sequence:  binary.BigEndian.Uint32(block[0x18:0x1c]),
		start:     start,
		incompat:  incompat,
		blockSize: blockSize,
	}, nil
}

func (j *journal) replay() (int, error) {
	if j.start == 0 {
		return 0, nil
	}
	position := j.start
	sequence := j.sequence
	visited := uint32(0)
	limit := j.maxLen - j.first
	replayed := 0
	for visited < limit {
		pending := make(map[uint64][]byte)
		revoked := make(map[uint64]struct{})
		transactionSeen := false
		committed := false
		for visited < limit {
			block, err := j.readBlock(position)
			if err != nil {
				return 0, err
			}
			if binary.BigEndian.Uint32(block[0:4]) != jbd2Magic || binary.BigEndian.Uint32(block[8:12]) != sequence {
				return replayed, nil // incomplete tail is not replayed
			}
			kind := binary.BigEndian.Uint32(block[4:8])
			visited++
			position = j.next(position)
			switch kind {
			case jbd2Descriptor:
				transactionSeen = true
				tags, err := j.parseTags(block)
				if err != nil {
					return 0, err
				}
				for _, tag := range tags {
					if tag.block >= j.view.blockCount {
						return 0, fmt.Errorf("journal target block %d is outside filesystem", tag.block)
					}
					if tag.flags&jbd2TagDeleted != 0 {
						revoked[tag.block] = struct{}{}
						continue
					}
					if visited >= limit {
						return 0, errors.New("JBD2 transaction exceeds journal")
					}
					data, err := j.readBlock(position)
					if err != nil {
						return 0, err
					}
					visited++
					position = j.next(position)
					if tag.flags&jbd2TagEscape != 0 {
						binary.BigEndian.PutUint32(data[0:4], jbd2Magic)
					}
					pending[tag.block] = data
				}
			case jbd2Revoke:
				transactionSeen = true
				if j.incompat&jbd2IncompatRevoke == 0 {
					return 0, errors.New("JBD2 revoke block without advertised feature")
				}
				if err := j.parseRevokes(block, revoked); err != nil {
					return 0, err
				}
			case jbd2Commit:
				if !transactionSeen {
					return 0, errors.New("JBD2 commit has no descriptor")
				}
				committed = true
			default:
				return 0, fmt.Errorf("unexpected JBD2 block type %d in transaction %d", kind, sequence)
			}
			if committed {
				break
			}
		}
		if !committed {
			return replayed, nil
		}
		for block := range revoked {
			delete(pending, block)
			delete(j.view.overlay, block)
		}
		for block, data := range pending {
			j.view.overlay[block] = data
			replayed++
		}
		sequence++
	}
	return replayed, nil
}

func (j *journal) parseTags(block []byte) ([]journalTag, error) {
	tagSize := 8
	if j.incompat&jbd2Incompat64Bit != 0 {
		tagSize = 12
	}
	var tags []journalTag
	for offset := 12; ; {
		if offset+tagSize > len(block) {
			return nil, errors.New("truncated JBD2 descriptor tag")
		}
		target := uint64(binary.BigEndian.Uint32(block[offset : offset+4]))
		flags := binary.BigEndian.Uint32(block[offset+4 : offset+8])
		if flags & ^uint32(jbd2TagEscape|jbd2TagSameUUID|jbd2TagDeleted|jbd2TagLast) != 0 {
			return nil, fmt.Errorf("unsupported JBD2 tag flags %#x", flags)
		}
		if tagSize == 12 {
			target |= uint64(binary.BigEndian.Uint32(block[offset+8:offset+12])) << 32
		}
		offset += tagSize
		if flags&jbd2TagSameUUID == 0 {
			if offset+16 > len(block) {
				return nil, errors.New("truncated JBD2 descriptor UUID")
			}
			offset += 16
		}
		tags = append(tags, journalTag{block: target, flags: flags})
		if len(tags) > int(j.maxLen) {
			return nil, errors.New("too many JBD2 descriptor tags")
		}
		if flags&jbd2TagLast != 0 {
			return tags, nil
		}
	}
}

func (j *journal) parseRevokes(block []byte, revoked map[uint64]struct{}) error {
	if len(block) < 16 {
		return errors.New("truncated JBD2 revoke block")
	}
	used := int(binary.BigEndian.Uint32(block[12:16]))
	width := 4
	if j.incompat&jbd2Incompat64Bit != 0 {
		width = 8
	}
	if used < 16 || used > len(block) || (used-16)%width != 0 {
		return errors.New("invalid JBD2 revoke length")
	}
	for offset := 16; offset < used; offset += width {
		var target uint64
		if width == 8 {
			target = binary.BigEndian.Uint64(block[offset : offset+8])
		} else {
			target = uint64(binary.BigEndian.Uint32(block[offset : offset+4]))
		}
		if target >= j.view.blockCount {
			return fmt.Errorf("revoked journal block %d is outside filesystem", target)
		}
		revoked[target] = struct{}{}
	}
	return nil
}

func (j *journal) readBlock(logical uint32) ([]byte, error) {
	return readExtentBlock(j.view.Storage, j.extents, logical, j.blockSize)
}

func (j *journal) next(block uint32) uint32 {
	block++
	if block >= j.maxLen {
		return j.first
	}
	return block
}

func readExtentBlock(source io.ReaderAt, extents []extent, logical, blockSize uint32) ([]byte, error) {
	for _, item := range extents {
		if logical < item.logical || logical-item.logical >= item.count {
			continue
		}
		physical := item.physical + uint64(logical-item.logical)
		block := make([]byte, blockSize)
		if err := readFullAt(source, block, int64(physical*uint64(blockSize))); err != nil {
			return nil, err
		}
		return block, nil
	}
	return nil, fmt.Errorf("journal logical block %d is not mapped", logical)
}

func (s *storage) ReadAt(buffer []byte, offset int64) (int, error) {
	read, err := s.Storage.ReadAt(buffer, offset)
	if read > 0 {
		s.applyOverlay(buffer[:read], offset)
		if s.patchInodeChecksum && int64(read) == s.inodeSize {
			s.patchInode(buffer[:read], offset)
		}
	}
	return read, err
}

func (s *storage) applyOverlay(buffer []byte, offset int64) {
	if len(s.overlay) == 0 || len(buffer) == 0 || offset < 0 {
		return
	}
	end := offset + int64(len(buffer))
	first := uint64(offset / s.blockSize)
	last := uint64((end - 1) / s.blockSize)
	for block := first; block <= last; block++ {
		data, ok := s.overlay[block]
		if !ok {
			continue
		}
		blockStart := int64(block) * s.blockSize
		copyStart := max(offset, blockStart)
		copyEnd := min(end, blockStart+s.blockSize)
		copy(buffer[copyStart-offset:copyEnd-offset], data[copyStart-blockStart:copyEnd-blockStart])
	}
}

func (s *storage) patchInode(inode []byte, offset int64) {
	for _, table := range s.inodeTables {
		if offset < table.start || offset+s.inodeSize > table.end || (offset-table.start)%s.inodeSize != 0 {
			continue
		}
		index := uint32((offset - table.start) / s.inodeSize)
		number := table.group*s.inodesPerGroup + index + 1
		if len(inode) < 0x84 {
			return
		}
		inode[0x7c], inode[0x7d], inode[0x82], inode[0x83] = 0, 0, 0, 0
		var value [4]byte
		binary.LittleEndian.PutUint32(value[:], number)
		checksum := crc.CRC32c(s.checksumSeed, value[:])
		binary.LittleEndian.PutUint32(value[:], binary.LittleEndian.Uint32(inode[0x64:0x68]))
		checksum = crc.CRC32c(checksum, value[:])
		checksum = crc.CRC32c(checksum, inode)
		binary.LittleEndian.PutUint16(inode[0x7c:0x7e], uint16(checksum))
		binary.LittleEndian.PutUint16(inode[0x82:0x84], uint16(checksum>>16))
		return
	}
}

func readFullAt(source io.ReaderAt, buffer []byte, offset int64) error {
	read, err := source.ReadAt(buffer, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if read != len(buffer) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
