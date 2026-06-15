package httpc

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// testingConfigWarnOnce ensures the TestingConfig warning is printed at most once per process.
var testingConfigWarnOnce sync.Once

// insecureSkipVerifyWarnOnce ensures the InsecureSkipVerify warning is printed at most once per process.
// Separate from testingConfigWarnOnce so that each warning fires independently.
var insecureSkipVerifyWarnOnce sync.Once

// securityWarnMu protects securityWarnOutput from concurrent read/write.
var securityWarnMu sync.RWMutex

// securityWarnOutput is the writer used for security warnings. Defaults to os.Stderr.
// Can be redirected via SetSecurityWarnOutput for testing or suppression.
var securityWarnOutput io.Writer = os.Stderr

// SetSecurityWarnOutput redirects security warnings (e.g., TestingConfig, InsecureSkipVerify)
// to the specified writer. Pass io.Discard to suppress all warnings.
func SetSecurityWarnOutput(w io.Writer) {
	securityWarnMu.Lock()
	securityWarnOutput = w
	securityWarnMu.Unlock()
}

// getSecurityWarnOutput returns the current security warning output writer.
func getSecurityWarnOutput() io.Writer {
	securityWarnMu.RLock()
	defer securityWarnMu.RUnlock()
	return securityWarnOutput
}

// isTestEnvironment detects if the code is running in a test environment.
// This is used to warn against using TestingConfig in production.
func isTestEnvironment() bool {
	return isTestEnvironmentFrom(filepath.Base(os.Args[0]), os.Getenv("GO_TEST"), os.Getenv("GOTEST"))
}

// isTestEnvironmentFrom is the pure (process-global-free) core of
// isTestEnvironment. Splitting the logic out lets tests exercise every branch
// deterministically by passing controlled inputs, instead of mutating
// os.Args / environment variables — which are package-global and not safe to
// write while other goroutines read them. Concurrent reads of os.Args / env in
// production are safe (they are set once at startup and never mutated during
// normal operation), but tests that flip them race with parallel callers of
// New() -> isTestEnvironment() under -race. Testing the pure function removes
// that race at zero production cost.
func isTestEnvironmentFrom(executable, goTest, gotest string) bool {
	// Check for common test executable patterns
	if strings.HasSuffix(executable, ".test") ||
		strings.HasSuffix(executable, ".test.exe") ||
		strings.Contains(executable, ".test.") {
		return true
	}
	// Check for Go test environment
	if goTest != "" || gotest == "1" {
		return true
	}
	return false
}

// warnTestingConfigInProduction logs a warning if TestingConfig is used outside of a test environment.
// The warning is printed at most once per process via sync.Once.
func warnTestingConfigInProduction() {
	if !isTestEnvironment() {
		testingConfigWarnOnce.Do(func() {
			w := getSecurityWarnOutput()
			fmt.Fprintf(w, "[SECURITY WARNING] TestingConfig is being used in a non-test environment!\n")
			fmt.Fprintf(w, "[SECURITY WARNING] This configuration disables critical security features:\n")
			fmt.Fprintf(w, "[SECURITY WARNING]   - TLS certificate verification is DISABLED\n")
			fmt.Fprintf(w, "[SECURITY WARNING]   - SSRF protection is DISABLED\n")
			fmt.Fprintf(w, "[SECURITY WARNING]   - URL/Header validation is DISABLED\n")
			fmt.Fprintf(w, "[SECURITY WARNING] Use SecureConfig() or DefaultConfig() for production!\n")
		})
	}
}
