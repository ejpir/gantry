package config

import (
	"os"
	"strings"
)

// ImageIdentity is the stable identity used for rwlayer pairing: the
// OCI digest when the image came through the store, else the file path.
func (c RunConfig) ImageIdentity() string {
	if c.LayerSet != nil {
		return "layerset:" + c.LayerSet.FSMeta
	}
	if c.ImageDigest != "" {
		return c.ImageDigest
	}
	return c.Image
}

// IsErofsFile reports whether p is an existing plain file with the
// .erofs suffix — the one -image form that needs no resolution.
func IsErofsFile(p string) bool {
	if !strings.HasSuffix(p, ".erofs") {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
