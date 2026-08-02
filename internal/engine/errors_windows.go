package engine

import "syscall"

// wsaRetryableErrors maps Windows Sockets (Winsock) error codes that indicate
// transient network conditions warranting a retry.
//
// Background: Go 1.25+ on Windows defines POSIX-style syscall.E* constants
// (e.g. ECONNREFUSED) using an APPLICATION_ERROR (1<<29) base offset, e.g.
// ECONNREFUSED = 536870934. However, the actual errors returned by Windows
// networking functions are raw WSA* codes (e.g. WSAECONNREFUSED = 10061).
// These two encodings never match via == or errors.Is, so the POSIX constants
// in isRetryableSyscallError's switch are silently bypassed on Windows.
// Furthermore, Go's syscall package does not export WSAECONNREFUSED,
// WSAETIMEDOUT, WSAENETUNREACH, or WSAEHOSTUNREACH as named constants,
// so the raw values must be used directly.
//
// These values are Windows-specific; on Unix they do not correspond to any
// POSIX errno and will not cause false positives.
var wsaRetryableErrors = map[syscall.Errno]bool{
	10054: true, // WSAECONNRESET — Connection reset by remote
	10060: true, // WSAETIMEDOUT — Connection timed out
	10061: true, // WSAECONNREFUSED — Target machine actively refused
	10051: true, // WSAENETUNREACH — Network is unreachable
	10065: true, // WSAEHOSTUNREACH — No route to host
}

// retryableSyscallErrorsExt checks platform-specific error codes that are not
// covered by the POSIX-style syscall.E* constants.
func retryableSyscallErrorsExt(errno syscall.Errno) bool {
	return wsaRetryableErrors[errno]
}
