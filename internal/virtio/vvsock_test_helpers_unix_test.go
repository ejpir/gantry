//go:build linux || darwin

package virtio

func (h vsockHdr) marshal() []byte {
	b := make([]byte, vsockHdrLen)
	h.marshalTo(b)
	return b
}
