// Copyright 2016 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

import (
	"fmt"
)

func init() {
	// Linux virtio-fs guest capability names (the host is Darwin, but this is
	// not a macFUSE connection).
	initFlagNames.set(CAP_NO_OPENDIR_SUPPORT, "NO_OPENDIR_SUPPORT")
	initFlagNames.set(CAP_EXPLICIT_INVAL_DATA, "EXPLICIT_INVAL_DATA")
	initFlagNames.set(CAP_MAP_ALIGNMENT, "MAP_ALIGNMENT")
	initFlagNames.set(CAP_SUBMOUNTS, "SUBMOUNTS")
	initFlagNames.set(CAP_HANDLE_KILLPRIV_V2, "HANDLE_KILLPRIV_V2")
	initFlagNames.set(CAP_SETXATTR_EXT, "SETXATTR_EXT")
	initFlagNames.set(CAP_INIT_EXT, "INIT_EXT")
	initFlagNames.set(CAP_INIT_RESERVED, "INIT_RESERVED")
}

func (me *CreateIn) string() string {
	return fmt.Sprintf(
		"{0%o [%s]}", me.Mode,
		flagString(openFlagNames, int64(me.Flags), "O_RDONLY"))
}

func (me *GetAttrIn) string() string { return "" }

func (me *MknodIn) string() string {
	return fmt.Sprintf("{0%o, %d}", me.Mode, me.Rdev)
}

func (me *ReadIn) string() string {
	return fmt.Sprintf("{Fh %d [%d +%d) %s}",
		me.Fh, me.Offset, me.Size,
		flagString(readFlagNames, int64(me.ReadFlags), ""))
}

func (me *WriteIn) string() string {
	return fmt.Sprintf("{Fh %d [%d +%d) %s}",
		me.Fh, me.Offset, me.Size,
		flagString(writeFlagNames, int64(me.WriteFlags), ""))
}
