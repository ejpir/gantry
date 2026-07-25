// mkinitramfs builds a gzip'd newc-format cpio initramfs — no external
// tools needed. Usage:
//
//	mkinitramfs -out initramfs.cpio.gz init=/path/to/init busybox=/path/to/busybox
package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type entry struct {
	name string // path inside initramfs
	mode uint32
	data []byte // nil for dirs
	link string // symlink target (optional)
}

var ino uint32 = 700

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

func writeEntry(b *bytes.Buffer, e entry) {
	ino++
	now := uint32(time.Now().Unix())
	var data []byte
	mode := e.mode
	switch {
	case e.link != "":
		mode = 0o120777
		data = []byte(e.link)
	case e.data != nil:
		data = e.data
	default: // directory
		mode = 0o040000 | (e.mode & 0o7777)
		if e.mode&0o7777 == 0 {
			mode = 0o040755
		}
	}
	name := strings.TrimPrefix(e.name, "/")
	namesize := uint32(len(name) + 1)

	hdr := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		ino, mode, 0, 0, 1, now, len(data), 3, 1, 0, 0, namesize, 0)
	b.WriteString(hdr)
	b.WriteString(name)
	b.WriteByte(0)
	pad4(b)
	b.Write(data)
	pad4(b)
}

func main() {
	out := flag.String("out", "initramfs.cpio.gz", "output file")
	flag.Parse()

	var entries []entry
	// base directories first
	for _, d := range []string{"bin", "dev", "etc", "proc", "sys", "tmp", "root"} {
		entries = append(entries, entry{name: d})
	}
	entries = append(entries,
		entry{name: "etc/motd", mode: 0o100644, data: []byte("\n  welcome to your own microVM\n\n")},
		entry{name: "etc/passwd", mode: 0o100644, data: []byte("root:x:0:0:root:/root:/bin/sh\n")},
	)

	for _, spec := range flag.Args() {
		dst, src, ok := strings.Cut(spec, "=")
		if !ok {
			fmt.Fprintln(os.Stderr, "bad file spec (want dst=src):", spec)
			os.Exit(2)
		}
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		mode := uint32(0o100644)
		if fi, _ := os.Stat(src); fi != nil && fi.Mode()&0o111 != 0 {
			mode = 0o100755
		}
		entries = append(entries, entry{name: dst, mode: mode, data: data})
		fmt.Printf("+ /%s (%d bytes)\n", dst, len(data))
	}

	var b bytes.Buffer
	for _, e := range entries {
		writeEntry(&b, e)
	}
	writeEntry(&b, entry{name: "TRAILER!!!", data: []byte{}})
	for b.Len()%512 != 0 {
		b.WriteByte(0)
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	gz, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	if _, err := io.Copy(gz, &b); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	gz.Close()
	fi, _ := f.Stat()
	fmt.Printf("wrote %s (%d bytes)\n", *out, fi.Size())
}
