//go:build !windows

package vmm

import "fmt"

// WHPXBrokerMain is present so the cross-platform command dispatcher builds.
func WHPXBrokerMain() int {
	fmt.Println("WHPX broker is available only on Windows")
	return 2
}
