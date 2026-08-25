package ext4view

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	ext4ExtentsInodeFlag = uint32(0x00080000)
	ext4RegularFileMode  = uint16(0x8000)
)

// Reader opens regular files from a journal-replayed ext4 storage view. It is
// intentionally separate from go-diskfs' File reader: that reader does not
// advance across sparse holes and can spin forever after returning (0, nil).
type Reader struct {
	source     io.ReaderAt
	superblock ext4Superblock
}

// NewReader prepares sparse-aware regular-file reads from source. Source must
// be the storage returned by New so committed journal blocks remain visible.
func NewReader(source io.ReaderAt) (*Reader, error) {
	if source == nil {
		return nil, errors.New("ext4 file reader has no storage")
	}
	rawSuperblock := make([]byte, ext4SuperblockSize)
	if err := readFullAt(source, rawSuperblock, ext4SuperblockOffset); err != nil {
		return nil, fmt.Errorf("read ext4 superblock: %w", err)
	}
	superblock, err := parseExt4Superblock(rawSuperblock)
	if err != nil {
		return nil, err
	}
	return &Reader{source: source, superblock: superblock}, nil
}

// OpenRegularFile returns a sequential reader for one inode, materializing
// sparse holes and unwritten extents as zero bytes as required by ext4.
func (reader *Reader) OpenRegularFile(inodeNumber uint32, size int64) (io.ReadCloser, error) {
	if reader == nil || reader.source == nil {
		return nil, errors.New("ext4 file reader is not initialized")
	}
	if size < 0 {
		return nil, fmt.Errorf("inode %d has negative size %d", inodeNumber, size)
	}
	inode, err := readRawInode(reader.source, reader.superblock, inodeNumber)
	if err != nil {
		return nil, fmt.Errorf("read inode %d: %w", inodeNumber, err)
	}
	if len(inode) < 0x70 {
		return nil, fmt.Errorf("inode %d is truncated", inodeNumber)
	}
	mode := binary.LittleEndian.Uint16(inode[0x00:0x02])
	if mode&0xf000 != ext4RegularFileMode {
		return nil, fmt.Errorf("inode %d is not a regular file", inodeNumber)
	}
	inodeSize := uint64(binary.LittleEndian.Uint32(inode[0x04:0x08])) |
		uint64(binary.LittleEndian.Uint32(inode[0x6c:0x70]))<<32
	if inodeSize != uint64(size) {
		return nil, fmt.Errorf("inode %d size changed from %d to %d", inodeNumber, size, inodeSize)
	}
	flags := binary.LittleEndian.Uint32(inode[0x20:0x24])
	if flags&ext4ExtentsInodeFlag == 0 {
		if size == 0 {
			return &sparseFile{source: reader.source, size: 0, blockSize: uint64(reader.superblock.blockSize)}, nil
		}
		return nil, fmt.Errorf("inode %d uses unsupported legacy block mapping", inodeNumber)
	}
	extents, err := parseFileExtentNode(reader.source, reader.superblock, inode[0x28:0x64], 0, -1)
	if err != nil {
		return nil, fmt.Errorf("read inode %d extents: %w", inodeNumber, err)
	}
	var previousEnd uint64
	for index, item := range extents {
		start := uint64(item.logical)
		end := start + uint64(item.count)
		if end > 1<<32 || index > 0 && start < previousEnd {
			return nil, fmt.Errorf("inode %d has overlapping or unordered extents", inodeNumber)
		}
		previousEnd = end
	}
	return &sparseFile{
		source:    reader.source,
		size:      size,
		blockSize: uint64(reader.superblock.blockSize),
		extents:   extents,
	}, nil
}

type fileExtent struct {
	logical   uint32
	physical  uint64
	count     uint32
	unwritten bool
}

func parseFileExtentNode(source io.ReaderAt, superblock ext4Superblock, node []byte, recursion, expectedDepth int) ([]fileExtent, error) {
	if recursion > 5 || len(node) < 12 || binary.LittleEndian.Uint16(node[0:2]) != 0xf30a {
		return nil, errors.New("invalid ext4 extent tree")
	}
	entries := int(binary.LittleEndian.Uint16(node[2:4]))
	maximum := int(binary.LittleEndian.Uint16(node[4:6]))
	depth := int(binary.LittleEndian.Uint16(node[6:8]))
	capacity := (len(node) - 12) / 12
	if depth > 5 || expectedDepth >= 0 && depth != expectedDepth || maximum <= 0 || maximum > capacity || entries > maximum {
		return nil, errors.New("invalid ext4 extent header")
	}
	result := make([]fileExtent, 0, entries)
	for index := 0; index < entries; index++ {
		entry := node[12+index*12 : 24+index*12]
		logical := binary.LittleEndian.Uint32(entry[0:4])
		if depth == 0 {
			encodedLength := binary.LittleEndian.Uint16(entry[4:6])
			length := extentLength(encodedLength)
			physical := uint64(binary.LittleEndian.Uint16(entry[6:8]))<<32 |
				uint64(binary.LittleEndian.Uint32(entry[8:12]))
			if length == 0 || physical >= superblock.blockCount || uint64(length) > superblock.blockCount-physical {
				return nil, errors.New("invalid ext4 extent range")
			}
			result = append(result, fileExtent{
				logical: logical, physical: physical, count: length, unwritten: encodedLength > 0x8000,
			})
			continue
		}
		childBlock := uint64(binary.LittleEndian.Uint32(entry[4:8])) |
			uint64(binary.LittleEndian.Uint16(entry[8:10]))<<32
		if childBlock >= superblock.blockCount {
			return nil, errors.New("invalid ext4 extent index")
		}
		child := make([]byte, superblock.blockSize)
		if err := readFullAt(source, child, int64(childBlock*uint64(superblock.blockSize))); err != nil {
			return nil, err
		}
		childExtents, err := parseFileExtentNode(source, superblock, child, recursion+1, depth-1)
		if err != nil {
			return nil, err
		}
		result = append(result, childExtents...)
	}
	return result, nil
}

type sparseFile struct {
	source      io.ReaderAt
	size        int64
	offset      int64
	blockSize   uint64
	extents     []fileExtent
	extentIndex int
	closed      bool
}

func (file *sparseFile) Read(buffer []byte) (int, error) {
	if file.closed {
		return 0, errors.New("read closed ext4 file")
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	if file.offset >= file.size {
		return 0, io.EOF
	}
	count := int64(len(buffer))
	if remaining := file.size - file.offset; count > remaining {
		count = remaining
	}
	output := buffer[:count]
	clear(output)
	start, end := uint64(file.offset), uint64(file.offset+count)
	for file.extentIndex < len(file.extents) {
		item := file.extents[file.extentIndex]
		extentStart := uint64(item.logical) * file.blockSize
		extentEnd := extentStart + uint64(item.count)*file.blockSize
		if extentEnd <= start {
			file.extentIndex++
			continue
		}
		if extentStart >= end {
			break
		}
		overlapStart := max(start, extentStart)
		overlapEnd := min(end, extentEnd)
		if !item.unwritten && overlapStart < overlapEnd {
			physical := item.physical*file.blockSize + overlapStart - extentStart
			destination := output[overlapStart-start : overlapEnd-start]
			if err := readFullAt(file.source, destination, int64(physical)); err != nil {
				return 0, fmt.Errorf("read ext4 extent at block %d: %w", item.physical, err)
			}
		}
		if extentEnd <= end {
			file.extentIndex++
		} else {
			break
		}
	}
	file.offset += count
	return int(count), nil
}

func (file *sparseFile) Close() error {
	file.closed = true
	return nil
}
