// Package boot builds what a guest boots from: the x86 boot protocol setup
// (zero page, e820 map, MP tables, bzImage load) and the arm64 flattened
// device tree.
//
// Both describe the same machine to the guest, from opposite directions, so
// they must agree with the device models and the RAM layout. Keeping them
// together is what makes that agreement checkable in one place.
package boot
