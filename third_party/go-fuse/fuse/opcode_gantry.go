// GANTRY PATCH (third of three; see validGuestName in bridge.go and
// LoopbackNode.securePath in loopback.go): exported aliases for the wire
// opcodes that gantry's host-side read-only gate (internal/virtio/vfs.go,
// roFuseHandler) must classify.
//
// The gate used to carry its own numeric opcode table; two entries were
// wrong (SETXATTR written as 20 — actually FSYNC — and REMOVEXATTR as
// 23 — actually LISTXATTR), so those mutations reached the loopback
// filesystem on a supposedly read-only share. Routing every reference
// through these aliases turns gate/opcode drift into a compile error.
//
// Re-vendoring upstream go-fuse must re-apply this file.
package fuse

const (
	OpLookup        = _OP_LOOKUP
	OpForget        = _OP_FORGET
	OpGetattr       = _OP_GETATTR
	OpSetattr       = _OP_SETATTR
	OpReadlink      = _OP_READLINK
	OpSymlink       = _OP_SYMLINK
	OpMknod         = _OP_MKNOD
	OpMkdir         = _OP_MKDIR
	OpUnlink        = _OP_UNLINK
	OpRmdir         = _OP_RMDIR
	OpRename        = _OP_RENAME
	OpLink          = _OP_LINK
	OpOpen          = _OP_OPEN
	OpRead          = _OP_READ
	OpWrite         = _OP_WRITE
	OpStatfs        = _OP_STATFS
	OpRelease       = _OP_RELEASE
	OpFsync         = _OP_FSYNC
	OpSetxattr      = _OP_SETXATTR
	OpGetxattr      = _OP_GETXATTR
	OpListxattr     = _OP_LISTXATTR
	OpRemovexattr   = _OP_REMOVEXATTR
	OpFlush         = _OP_FLUSH
	OpInit          = _OP_INIT
	OpOpendir       = _OP_OPENDIR
	OpReaddir       = _OP_READDIR
	OpReleasedir    = _OP_RELEASEDIR
	OpFsyncdir      = _OP_FSYNCDIR
	OpGetlk         = _OP_GETLK
	OpSetlk         = _OP_SETLK
	OpSetlkw        = _OP_SETLKW
	OpAccess        = _OP_ACCESS
	OpCreate        = _OP_CREATE
	OpInterrupt     = _OP_INTERRUPT
	OpBmap          = _OP_BMAP
	OpDestroy       = _OP_DESTROY
	OpIoctl         = _OP_IOCTL
	OpPoll          = _OP_POLL
	OpNotifyReply   = _OP_NOTIFY_REPLY
	OpBatchForget   = _OP_BATCH_FORGET
	OpFallocate     = _OP_FALLOCATE
	OpReaddirplus   = _OP_READDIRPLUS
	OpRename2       = _OP_RENAME2
	OpLseek         = _OP_LSEEK
	OpCopyFileRange = _OP_COPY_FILE_RANGE
	OpTmpfile       = _OP_TMPFILE
	OpStatx         = _OP_STATX
)
