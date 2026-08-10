package main

/*
#cgo CFLAGS: -pthread
#cgo LDFLAGS: -pthread
#include <pthread.h>
#include <errno.h>

static void *workerconf_noop(void *unused) {
	return unused;
}

static int workerconf_pthread_roundtrip(void) {
	pthread_t thread;
	int rc = pthread_create(&thread, NULL, workerconf_noop, NULL);
	if (rc != 0) {
		return rc;
	}
	return pthread_join(thread, NULL);
}

static pthread_mutex_t workerconf_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t workerconf_cv = PTHREAD_COND_INITIALIZER;
static int workerconf_release;

static void *workerconf_wait(void *unused) {
	pthread_mutex_lock(&workerconf_mu);
	while (!workerconf_release) {
		pthread_cond_wait(&workerconf_cv, &workerconf_mu);
	}
	pthread_mutex_unlock(&workerconf_mu);
	return unused;
}

// Return the number of simultaneously live threads when pthread_create first
// hit EAGAIN. -1 means the configured ceiling was not enforced.
static int workerconf_fill_task_limit(void) {
	pthread_t threads[320];
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 64 * 1024);
	int count = 0;
	int rc = 0;
	for (; count < 320; count++) {
		rc = pthread_create(&threads[count], &attr, workerconf_wait, NULL);
		if (rc != 0) {
			break;
		}
	}
	pthread_attr_destroy(&attr);
	pthread_mutex_lock(&workerconf_mu);
	workerconf_release = 1;
	pthread_cond_broadcast(&workerconf_cv);
	pthread_mutex_unlock(&workerconf_mu);
	for (int i = 0; i < count; i++) {
		pthread_join(threads[i], NULL);
	}
	if (rc == EAGAIN) {
		return count;
	}
	return -1;
}
*/
import "C"

import (
	"fmt"
	"os"
	"syscall"

	"github.com/ejpir/gantry/internal/workerconf"
	"golang.org/x/sys/unix"
)

func main() {
	root := ""
	if os.Getenv("WORKERCONF_CGO_NAMESPACED") == "1" {
		root = os.Getenv("WORKERCONF_ROOT")
	}
	report, err := workerconf.Apply(workerconf.DefaultSpec(2, root))
	if err != nil || report == nil || !report.Applied {
		fmt.Fprintln(os.Stderr, "apply:", err, report)
		os.Exit(2)
	}
	if rc := int(C.workerconf_pthread_roundtrip()); rc != 0 {
		fmt.Fprintln(os.Stderr, "pthread_create/join:", syscall.Errno(rc))
		os.Exit(2)
	}
	fmt.Println("CGO-PTHREAD-OK")
	if root != "" {
		count := int(C.workerconf_fill_task_limit())
		if count < 1 || count >= 320 {
			fmt.Fprintln(os.Stderr, "task limit not enforced; live threads:", count)
			os.Exit(2)
		}
		fmt.Println("TASK-LIMIT-ENFORCED", count)
	}

	pid, _, errno := syscall.RawSyscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
	if errno == 0 {
		if pid == 0 {
			os.Exit(99)
		}
		var status syscall.WaitStatus
		_, _ = syscall.Wait4(int(pid), &status, 0, nil)
		fmt.Fprintln(os.Stderr, "process clone unexpectedly succeeded")
		os.Exit(2)
	}
	if errno != syscall.EPERM {
		fmt.Fprintln(os.Stderr, "process clone:", errno)
		os.Exit(2)
	}
	fmt.Println("PROCESS-CLONE-DENIED")
}
