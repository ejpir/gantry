//go:build linux && arm64

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	getAPI     = 0xAE00
	createVM   = 0xAE01
	createVCPU = 0xAE41
	initVCPU   = 0x4020AEAE
	setMem     = 0x4020AE46
	setOne     = 0x4010AEAC
	getOne     = 0x4010AEAB
	runReq     = 0xAE80
	arm64      = 0x6000000000000000
	size64     = 0x0030000000000000
	core       = 0x100000
)

type vi struct {
	Target   uint32
	Features [7]uint32
}
type one struct{ ID, Addr uint64 }
type mem struct {
	Slot, Flags    uint32
	GPA, Size, UVA uint64
}

func ioc(fd uintptr, r uintptr, p unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, r, uintptr(p))
	if e != 0 {
		return e
	}
	return nil
}
func sr(fd uintptr, index, val uint64) error {
	o := one{arm64 | size64 | core | index, uint64(uintptr(unsafe.Pointer(&val)))}
	return ioc(fd, setOne, unsafe.Pointer(&o))
}
func gr(fd uintptr, index uint64) (uint64, error) {
	var val uint64
	o := one{arm64 | size64 | core | index, uint64(uintptr(unsafe.Pointer(&val)))}
	e := ioc(fd, getOne, unsafe.Pointer(&o))
	return val, e
}
func main() {
	f, _ := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	vm, _, _ := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), createVM, 0)
	ram := make([]byte, 0x20000)
	code := []uint32{0xd2800820, 0xd51b4420, 0x58000040, 0xd61f0000, 0x10000}
	for n, x := range code {
		*(*uint32)(unsafe.Pointer(&ram[n*4])) = x
	}
	m := mem{GPA: 0x40000000, Size: uint64(len(ram)), UVA: uint64(uintptr(unsafe.Pointer(&ram[0])))}
	fmt.Println("mem", ioc(vm, setMem, unsafe.Pointer(&m)))
	vc, _, e := syscall.Syscall(syscall.SYS_IOCTL, vm, createVCPU, 0)
	fmt.Println("vc", vc, e)
	x := vi{Target: 5}
	x.Features[0] = 1 << 2
	fmt.Println("init", ioc(vc, initVCPU, unsafe.Pointer(&x)))
	for _, z := range []struct{ i, v uint64 }{{0, 0}, {64, 0x40000000}, {66, 0x3c5}} {
		fmt.Println("set", z.i, sr(vc, z.i, z.v))
		g, e := gr(vc, z.i)
		fmt.Println("get", z.i, fmt.Sprintf("%#x", g), e)
	}
	done := make(chan struct{})
	go func() {
		r, _, e := syscall.Syscall(syscall.SYS_IOCTL, vc, runReq, 0)
		fmt.Println("run", r, e)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		fmt.Println("run blocked")
	}
	for _, i := range []uint64{0, 64, 66} {
		g, e := gr(vc, i)
		fmt.Println("after", i, fmt.Sprintf("%#x", g), e)
	}
}
