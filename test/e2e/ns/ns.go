package ns

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Returns an object representing the current OS thread's network namespace
func GetCurrentNS() (NetNS, error) {
	// Lock the thread in case other goroutine executes in it and changes its
	// network namespace after getCurrentThreadNetNSPath(), otherwise it might
	// return an unexpected network namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return GetNS(getCurrentThreadNetNSPath())
}

func (ns *netNS) Close() error {
	if err := ns.errorIfClosed(); err != nil {
		return err
	}

	if err := ns.file.Close(); err != nil {
		return fmt.Errorf("Failed to close %q: %v", ns.file.Name(), err)
	}
	ns.closed = true

	return ns.Unmount()
}

type NetNS interface {
	// Executes the passed closure in this object's network namespace,
	// attempting to restore the original namespace before returning.
	// However, since each OS thread can have a different network namespace,
	// and Go's thread scheduling is highly variable, callers cannot
	// guarantee any specific namespace is set unless operations that
	// require that namespace are wrapped with Do().  Also, no code called
	// from Do() should call runtime.UnlockOSThread(), or the risk
	// of executing code in an incorrect namespace will be greater.  See
	// https://github.com/golang/go/wiki/LockOSThread for further details.
	Do(toRun func(NetNS) error) error

	// Sets the current network namespace to this object's network namespace.
	// Note that since Go's thread scheduling is highly variable, callers
	// cannot guarantee the requested namespace will be the current namespace
	// after this function is called; to ensure this wrap operations that
	// require the namespace with Do() instead.
	Set() error

	// Returns the filesystem path representing this object's network namespace
	Path() string

	// Returns a file descriptor representing this object's network namespace
	Fd() uintptr

	// Cleans up this instance of the network namespace; if this instance
	// is the last user the namespace will be destroyed
	Close() error
}

type netNS struct {
	file   *os.File
	closed bool
}

// netNS implements the NetNS interface
var _ NetNS = &netNS{}

const (
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h
	NSFS_MAGIC   = 0x6e736673
	PROCFS_MAGIC = 0x9fa0
)

type NSPathNotExistErr struct{ msg string }

func (e NSPathNotExistErr) Error() string { return e.msg }

type NSPathNotNSErr struct{ msg string }

func (e NSPathNotNSErr) Error() string { return e.msg }

func IsNSorErr(nspath string) error {
	stat := syscall.Statfs_t{}
	if err := syscall.Statfs(nspath, &stat); err != nil {
		if os.IsNotExist(err) {
			err = NSPathNotExistErr{msg: fmt.Sprintf("failed to Statfs %q: %v", nspath, err)}
		} else {
			err = fmt.Errorf("failed to Statfs %q: %v", nspath, err)
		}
		return err
	}

	switch stat.Type {
	case PROCFS_MAGIC, NSFS_MAGIC:
		return nil
	default:
		return NSPathNotNSErr{msg: fmt.Sprintf("unknown FS magic on %q: %x", nspath, stat.Type)}
	}
}

// Returns an object representing the namespace referred to by @path
func GetNS(nspath string) (NetNS, error) {
	err := IsNSorErr(nspath)
	if err != nil {
		return nil, err
	}

	fd, err := os.Open(nspath)
	if err != nil {
		return nil, err
	}

	return &netNS{file: fd}, nil
}

func (ns *netNS) Path() string {
	return ns.file.Name()
}

func (ns *netNS) Fd() uintptr {
	return ns.file.Fd()
}

func (ns *netNS) errorIfClosed() error {
	if ns.closed {
		return fmt.Errorf("%q has already been closed", ns.file.Name())
	}
	return nil
}

func (ns *netNS) Do(toRun func(NetNS) error) error {
	if err := ns.errorIfClosed(); err != nil {
		return err
	}

	containedCall := func(hostNS NetNS) error {
		threadNS, err := GetCurrentNS()
		if err != nil {
			return fmt.Errorf("failed to open current netns: %v", err)
		}
		defer threadNS.Close()

		// switch to target namespace
		if err = ns.Set(); err != nil {
			return fmt.Errorf("error switching to ns %v: %v", ns.file.Name(), err)
		}
		defer func() {
			err := threadNS.Set() // switch back
			if err == nil {
				// Unlock the current thread only when we successfully switched back
				// to the original namespace; otherwise leave the thread locked which
				// will force the runtime to scrap the current thread, that is maybe
				// not as optimal but at least always safe to do.
				runtime.UnlockOSThread()
			}
		}()

		return toRun(hostNS)
	}

	// save a handle to current network namespace
	hostNS, err := GetCurrentNS()
	if err != nil {
		return fmt.Errorf("Failed to open current namespace: %v", err)
	}
	defer hostNS.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	// Start the callback in a new green thread so that if we later fail
	// to switch the namespace back to the original one, we can safely
	// leave the thread locked to die without a risk of the current thread
	// left lingering with incorrect namespace.
	var innerError error
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		innerError = containedCall(hostNS)
	}()
	wg.Wait()

	return innerError
}

// WithNetNSPath executes the passed closure under the given network
// namespace, restoring the original namespace afterwards.
func WithNetNSPath(nspath string, toRun func(NetNS) error) error {
	ns, err := GetNS(nspath)
	if err != nil {
		return err
	}
	defer ns.Close()
	return ns.Do(toRun)
}

func getNsRunDir() string {
	xdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")

	/// If XDG_RUNTIME_DIR is set, check if the current user owns /var/run.  If
	// the owner is different, we are most likely running in a user namespace.
	// In that case use $XDG_RUNTIME_DIR/netns as runtime dir.
	if xdgRuntimeDir != "" {
		if s, err := os.Stat("/var/run"); err == nil {
			st, ok := s.Sys().(*syscall.Stat_t)
			if ok && int(st.Uid) != os.Geteuid() {
				return path.Join(xdgRuntimeDir, "netns")
			}
		}
	}

	return "/var/run/netns"
}

// Unmount unmounts the NS held by the netns object
func (ns *netNS) Unmount() error {
	nsPath := ns.Path()
	// Only unmount if it's been bind-mounted (don't touch namespaces in /proc...)
	if strings.HasPrefix(nsPath, getNsRunDir()) {
		if err := unix.Unmount(nsPath, 0); err != nil {
			return fmt.Errorf("failed to unmount NS: at %s: %v", nsPath, err)
		}

		if err := os.Remove(nsPath); err != nil {
			return fmt.Errorf("failed to remove ns path %s: %v", nsPath, err)
		}
	}

	return nil
}
