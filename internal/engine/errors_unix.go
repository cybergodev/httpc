//go:build !windows

package engine

import "syscall"

// retryableSyscallErrorsExt checks platform-specific error codes that are not
// covered by the POSIX-style syscall.E* constants. On non-Windows platforms,
// the POSIX constants already match the actual errno values, so this is a no-op.
func retryableSyscallErrorsExt(errno syscall.Errno) bool {
	_ = errno
	return false
}
