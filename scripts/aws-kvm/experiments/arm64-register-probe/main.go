//go:build linux && arm64

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	getAPI     = 0xAE00
	createVM   = 0xAE01
	createVCPU = 0xAE41
	initVCPU   = 0x4020AEAE
	setOne     = 0x4010AEAC
	getOne     = 0xC010AEAB
	runReq     = 0xAE80
	arm64      = 0x6000000000000000
	size64     = 0x0030000000000000
	core       = 0x0000000000100000
)

type vi struct {
	Target   uint32
	Features [7]uint32
}
type one struct{ ID, Addr uint64 }

func ioc(fd uintptr, r uintptr, p unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, r, uintptr(p))
	if e != 0 {
		return e
	}
	return nil
}
func reg(fd uintptr, index uint64, val uint64) {
	o := one{arm64 | size64 | core | index, uint64(uintptr(unsafe.Pointer(&val)))}
	e := ioc(fd, setOne, unsafe.Pointer(&o))
	fmt.Printf("set index=%d id=%#x value=%#x err=%v\n", index, o.ID, val, e)
	var got uint64
	o.Addr = uint64(uintptr(unsafe.Pointer(&got)))
	e = ioc(fd, getOne, unsafe.Pointer(&o))
	fmt.Printf("get index=%d value=%#x err=%v\n", index, got, e)
}
func main() {
	f, e := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if e != nil {
		panic(e)
	}
	v, _, en := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), getAPI, 0)
	fmt.Println("api", v, en)
	vm, _, en := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), createVM, 0)
	fmt.Println("vm", vm, en)
	vc, _, en := syscall.Syscall(syscall.SYS_IOCTL, vm, createVCPU, 0)
	fmt.Println("vcpu", vc, en)
	x := vi{Target: 5}
	x.Features[0] = 1 << 2
	fmt.Println("init", ioc(vc, initVCPU, unsafe.Pointer(&x)))
	for _, n := range []uint64{0, 1, 2, 3, 32, 33, 62, 64, 66, 128, 132} {
		reg(vc, n, 0x12340000+n)
	}
	_ = runReq
}
