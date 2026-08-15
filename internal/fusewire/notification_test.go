package fusewire

import (
	"encoding/binary"
	"testing"
)

func notificationFrame(code int32, payload []byte) []byte {
	message := make([]byte, 16+len(payload))
	binary.LittleEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.LittleEndian.PutUint32(message[4:8], uint32(code))
	copy(message[16:], payload)
	return message
}

func TestValidNotification(t *testing.T) {
	inode := make([]byte, 24)
	entry := make([]byte, 16+len("name")+1)
	binary.LittleEndian.PutUint32(entry[8:12], uint32(len("name")))
	copy(entry[16:], "name")
	prune := make([]byte, 16+2*8)
	binary.LittleEndian.PutUint32(prune[0:4], 2)
	for _, test := range []struct {
		name    string
		message []byte
		valid   bool
	}{
		{name: "inode", message: notificationFrame(2, inode), valid: true},
		{name: "entry", message: notificationFrame(3, entry), valid: true},
		{name: "epoch", message: notificationFrame(8, nil), valid: true},
		{name: "prune", message: notificationFrame(9, prune), valid: true},
		{name: "negative notification rejected", message: notificationFrame(-9, prune)},
		{name: "store rejected", message: notificationFrame(4, inode)},
		{name: "request response rejected", message: notificationFrame(0, nil)},
		{name: "entry no nul", message: notificationFrame(3, entry[:len(entry)-1])},
		{name: "oversize", message: notificationFrame(8, make([]byte, MaxNotificationBytes))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ValidNotification(test.message); got != test.valid {
				t.Fatalf("ValidNotification = %v, want %v", got, test.valid)
			}
		})
	}
}
