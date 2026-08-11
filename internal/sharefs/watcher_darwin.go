//go:build darwin

package sharefs

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	fseventMustScanSubDirs = uint32(0x00000001)
	fseventUserDropped     = uint32(0x00000002)
	fseventKernelDropped   = uint32(0x00000004)
	fseventIDsWrapped      = uint32(0x00000008)
	fseventRootChanged     = uint32(0x00000020)
	fseventUnmount         = uint32(0x00000080)
	fseventItemRemoved     = uint32(0x00000200)
	fseventItemRenamed     = uint32(0x00000800)
	fseventItemIsDir       = uint32(0x00020000)
	fseventOwnEvent        = uint32(0x00080000)

	fseventCreateNoDefer    = uint32(0x00000002)
	fseventCreateWatchRoot  = uint32(0x00000004)
	fseventCreateFileEvents = uint32(0x00000010)
	fseventCreateMarkSelf   = uint32(0x00000020)

	cfStringEncodingUTF8 = uint32(0x08000100)
)

type darwinFSEventAPI struct {
	cfStringCreateWithCString func(uintptr, *byte, uint32) uintptr
	cfArrayCreate             func(uintptr, *uintptr, int64, uintptr) uintptr
	cfRelease                 func(uintptr)
	streamCreate              func(uintptr, uintptr, uintptr, uintptr, uint64, float64, uint32) uintptr
	streamSetDispatchQueue    func(uintptr, uintptr)
	streamStart               func(uintptr) uint8
	streamStop                func(uintptr)
	streamInvalidate          func(uintptr)
	streamRelease             func(uintptr)
	dispatchQueueCreate       func(*byte, uintptr) uintptr
	dispatchRelease           func(uintptr)
	arrayCallbacks            uintptr
	callback                  uintptr
}

var (
	darwinFSEventsOnce sync.Once
	darwinFSEventsAPI  darwinFSEventAPI
	darwinFSEventsErr  error
	darwinWatchers     sync.Map // map[uintptr]*darwinShareWatcher
)

type darwinShareWatcher struct {
	root   string
	stream uintptr
	queue  uintptr
	emit   func(shareWatchEvent)
	closed atomic.Bool
}

func loadDarwinFSEvents() (darwinFSEventAPI, error) {
	darwinFSEventsOnce.Do(func() {
		coreServices, err := purego.Dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			darwinFSEventsErr = err
			return
		}
		coreFoundation, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			darwinFSEventsErr = err
			return
		}
		libSystem, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			darwinFSEventsErr = err
			return
		}
		api := &darwinFSEventsAPI
		purego.RegisterLibFunc(&api.cfStringCreateWithCString, coreFoundation, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&api.cfArrayCreate, coreFoundation, "CFArrayCreate")
		purego.RegisterLibFunc(&api.cfRelease, coreFoundation, "CFRelease")
		purego.RegisterLibFunc(&api.streamCreate, coreServices, "FSEventStreamCreate")
		purego.RegisterLibFunc(&api.streamSetDispatchQueue, coreServices, "FSEventStreamSetDispatchQueue")
		purego.RegisterLibFunc(&api.streamStart, coreServices, "FSEventStreamStart")
		purego.RegisterLibFunc(&api.streamStop, coreServices, "FSEventStreamStop")
		purego.RegisterLibFunc(&api.streamInvalidate, coreServices, "FSEventStreamInvalidate")
		purego.RegisterLibFunc(&api.streamRelease, coreServices, "FSEventStreamRelease")
		purego.RegisterLibFunc(&api.dispatchQueueCreate, libSystem, "dispatch_queue_create")
		purego.RegisterLibFunc(&api.dispatchRelease, libSystem, "dispatch_release")
		callbacks, err := purego.Dlsym(coreFoundation, "kCFTypeArrayCallBacks")
		if err != nil {
			darwinFSEventsErr = err
			return
		}
		api.arrayCallbacks = callbacks
		api.callback = purego.NewCallback(darwinFSEventCallback)
	})
	return darwinFSEventsAPI, darwinFSEventsErr
}

func newPlatformShareWatcher(export *Export, emit func(shareWatchEvent)) (shareWatcher, error) {
	if export == nil || export.Path == "" {
		return nil, fmt.Errorf("share root path is unavailable")
	}
	api, err := loadDarwinFSEvents()
	if err != nil {
		return nil, err
	}
	rootCString := append([]byte(export.Path), 0)
	rootString := api.cfStringCreateWithCString(0, &rootCString[0], cfStringEncodingUTF8)
	if rootString == 0 {
		return nil, fmt.Errorf("create FSEvents root string")
	}
	defer api.cfRelease(rootString)
	paths := api.cfArrayCreate(0, &rootString, 1, api.arrayCallbacks)
	if paths == 0 {
		return nil, fmt.Errorf("create FSEvents path array")
	}
	defer api.cfRelease(paths)
	label := append([]byte("com.gantry.sharefs."+export.Tag), 0)
	queue := api.dispatchQueueCreate(&label[0], 0)
	if queue == 0 {
		return nil, fmt.Errorf("create FSEvents dispatch queue")
	}
	flags := fseventCreateNoDefer | fseventCreateWatchRoot | fseventCreateFileEvents | fseventCreateMarkSelf
	stream := api.streamCreate(0, api.callback, 0, paths, ^uint64(0), 0.05, flags)
	runtime.KeepAlive(rootCString)
	runtime.KeepAlive(label)
	if stream == 0 {
		api.dispatchRelease(queue)
		return nil, fmt.Errorf("create FSEvents stream")
	}
	watcher := &darwinShareWatcher{root: export.Path, stream: stream, queue: queue, emit: emit}
	darwinWatchers.Store(stream, watcher)
	api.streamSetDispatchQueue(stream, queue)
	if api.streamStart(stream) == 0 {
		darwinWatchers.Delete(stream)
		api.streamInvalidate(stream)
		api.streamRelease(stream)
		api.dispatchRelease(queue)
		return nil, fmt.Errorf("start FSEvents stream")
	}
	return watcher, nil
}

func (w *darwinShareWatcher) WatchDirectory(string) error { return nil }
func (w *darwinShareWatcher) ForgetDirectory(string)      {}
func (w *darwinShareWatcher) Reset() error                { return nil }

func (w *darwinShareWatcher) Close() error {
	if w == nil || !w.closed.CompareAndSwap(false, true) {
		return nil
	}
	api, _ := loadDarwinFSEvents()
	api.streamStop(w.stream)
	api.streamInvalidate(w.stream)
	darwinWatchers.Delete(w.stream)
	api.streamRelease(w.stream)
	api.dispatchRelease(w.queue)
	return nil
}

func darwinFSEventCallback(stream, _ uintptr, count uintptr, eventPaths **byte, eventFlags *uint32, _ uintptr) {
	value, ok := darwinWatchers.Load(stream)
	if !ok || count == 0 || eventPaths == nil || eventFlags == nil {
		return
	}
	watcher := value.(*darwinShareWatcher)
	if watcher.closed.Load() {
		return
	}
	paths := unsafe.Slice(eventPaths, int(count))
	flags := unsafe.Slice(eventFlags, int(count))
	for index, pathPointer := range paths {
		flag := flags[index]
		if flag&(fseventMustScanSubDirs|fseventUserDropped|fseventKernelDropped|fseventIDsWrapped|fseventRootChanged|fseventUnmount) != 0 {
			watcher.emit(shareWatchEvent{loss: fmt.Errorf("FSEvents continuity lost (flags %#x)", flag)})
			return
		}
		if flag&fseventOwnEvent != 0 {
			continue // the guest VFS already invalidated its own successful mutation
		}
		hostPath := darwinCString(pathPointer)
		rel, ok := trimDarwinWatchRoot(watcher.root, hostPath)
		if !ok {
			watcher.emit(shareWatchEvent{loss: fmt.Errorf("FSEvents path escaped root: %q", hostPath)})
			return
		}
		watcher.emit(shareWatchEvent{
			rel: rel, rename: flag&fseventItemRenamed != 0,
			invalidateDirs: flag&fseventItemIsDir != 0 && flag&(fseventItemRemoved|fseventItemRenamed) != 0,
		})
	}
}

func trimDarwinWatchRoot(root, hostPath string) (string, bool) {
	if hostPath == root {
		return "", true
	}
	prefix := strings.TrimSuffix(root, "/") + "/"
	if !strings.HasPrefix(hostPath, prefix) {
		return "", false
	}
	return strings.TrimPrefix(hostPath, prefix), true
}

func darwinCString(pointer *byte) string {
	if pointer == nil {
		return ""
	}
	const maxPathBytes = 1 << 20
	for length := 0; length < maxPathBytes; length++ {
		if *(*byte)(unsafe.Add(unsafe.Pointer(pointer), length)) == 0 {
			return unsafe.String(pointer, length)
		}
	}
	return ""
}
