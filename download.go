package httpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cybergodev/httpc/internal/engine"
)

// DownloadProgressCallback is called during file download to report progress.
// Parameters: downloaded bytes, total bytes, current speed in bytes/second.
type DownloadProgressCallback func(downloaded, total int64, speed float64)

// ChecksumAlgorithm specifies the hash algorithm for download integrity verification.
type ChecksumAlgorithm string

const (
	// ChecksumSHA256 uses SHA-256 for integrity verification.
	ChecksumSHA256 ChecksumAlgorithm = "sha256"
)

// DownloadConfig configures file download behavior.
// Use DefaultDownloadConfig() to get a configuration with sensible defaults.
type DownloadConfig struct {
	// FilePath is the destination path for the downloaded file.
	FilePath string
	// ProgressCallback is called periodically during download to report progress.
	ProgressCallback DownloadProgressCallback
	// Overwrite allows overwriting an existing file at FilePath.
	Overwrite bool
	// ResumeDownload attempts to resume a previously interrupted download.
	ResumeDownload bool
	// Checksum is the expected hex-encoded checksum of the downloaded file.
	// When set, the file is verified after download completes.
	// A mismatch causes the download to fail and the file to be removed.
	Checksum string
	// ChecksumAlgorithm specifies the hash algorithm for verification.
	// Currently only "sha256" is supported. Default: "sha256".
	ChecksumAlgorithm ChecksumAlgorithm
}

// DefaultDownloadConfig returns a DownloadConfig with default settings.
// Overwrite and ResumeDownload are both false by default.
// Caller must set FilePath before use.
//
// Example:
//
//	cfg := httpc.DefaultDownloadConfig()
//	cfg.FilePath = "/downloads/file.zip"
//	cfg.Overwrite = true
//	result, err := client.DownloadWithOptions(url, cfg)
func DefaultDownloadConfig() *DownloadConfig {
	return &DownloadConfig{
		Overwrite:         false,
		ResumeDownload:    false,
		ChecksumAlgorithm: ChecksumSHA256,
	}
}

// DownloadResult contains information about a completed download.
type DownloadResult struct {
	// FilePath is the path where the file was saved.
	FilePath string
	// BytesWritten is the total number of bytes written to disk.
	BytesWritten int64
	// Duration is the total time taken for the download.
	Duration time.Duration
	// AverageSpeed is the average download speed in bytes/second.
	AverageSpeed float64
	// StatusCode is the HTTP status code of the download response.
	StatusCode int
	// ContentLength is the Content-Length reported by the server.
	ContentLength int64
	// Resumed indicates whether the download was resumed from a previous partial download.
	Resumed bool
	// ResponseCookies contains cookies returned by the download response.
	ResponseCookies []*http.Cookie
	// ActualChecksum is the computed checksum of the downloaded file (hex-encoded).
	// Only set when DownloadConfig.Checksum is provided.
	ActualChecksum string
}

// DownloadFile downloads a file from the given URL to the specified file path using the default client.
// Returns DownloadResult with download statistics or an error if the download fails.
func DownloadFile(url string, filePath string, options ...RequestOption) (*DownloadResult, error) {
	client, err := getDefaultClient()
	if err != nil {
		return nil, err
	}

	return client.DownloadFile(url, filePath, options...)
}

// DownloadWithOptions downloads a file with custom download options using the default client.
// Returns DownloadResult with download statistics or an error if the download fails.
func DownloadWithOptions(url string, downloadOpts *DownloadConfig, options ...RequestOption) (*DownloadResult, error) {
	client, err := getDefaultClient()
	if err != nil {
		return nil, err
	}

	return client.DownloadWithOptions(url, downloadOpts, options...)
}

// DownloadFileWithContext downloads a file using the default client with context control.
// The context parameter allows for timeout and cancellation control during the download.
func DownloadFileWithContext(ctx context.Context, url string, filePath string, options ...RequestOption) (*DownloadResult, error) {
	client, err := getDefaultClient()
	if err != nil {
		return nil, err
	}
	return client.DownloadFileWithContext(ctx, url, filePath, options...)
}

// DownloadWithOptionsWithContext downloads a file with custom download options and context control.
// The context parameter allows for timeout and cancellation control during the download.
func DownloadWithOptionsWithContext(ctx context.Context, url string, downloadOpts *DownloadConfig, options ...RequestOption) (*DownloadResult, error) {
	client, err := getDefaultClient()
	if err != nil {
		return nil, err
	}
	return client.DownloadWithOptionsWithContext(ctx, url, downloadOpts, options...)
}

// DownloadFile downloads a file from the given URL to the specified file path.
func (c *clientImpl) DownloadFile(url string, filePath string, options ...RequestOption) (*DownloadResult, error) {
	return c.DownloadFileWithContext(backgroundCtx, url, filePath, options...)
}

// DownloadWithOptions downloads a file with custom download options.
func (c *clientImpl) DownloadWithOptions(url string, downloadOpts *DownloadConfig, options ...RequestOption) (*DownloadResult, error) {
	return c.DownloadWithOptionsWithContext(backgroundCtx, url, downloadOpts, options...)
}

// DownloadFileWithContext downloads a file with context control for cancellation and timeouts.
func (c *clientImpl) DownloadFileWithContext(ctx context.Context, url string, filePath string, options ...RequestOption) (*DownloadResult, error) {
	downloadOpts := DefaultDownloadConfig()
	downloadOpts.FilePath = filePath
	return c.downloadFile(ctx, url, downloadOpts, options...)
}

// DownloadWithOptionsWithContext downloads a file with custom download options and context control.
func (c *clientImpl) DownloadWithOptionsWithContext(ctx context.Context, url string, downloadOpts *DownloadConfig, options ...RequestOption) (*DownloadResult, error) {
	return c.downloadFile(ctx, url, downloadOpts, options...)
}

func (c *clientImpl) downloadFile(ctx context.Context, url string, opts *DownloadConfig, options ...RequestOption) (result *DownloadResult, err error) {
	if opts == nil {
		return nil, fmt.Errorf("download options cannot be nil")
	}
	if opts.FilePath == "" {
		return nil, ErrEmptyFilePath
	}
	validatedPath, err := prepareFilePath(opts.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare file path: %w", err)
	}
	opts.FilePath = validatedPath

	var resumeOffset int64
	if fileInfo, err := os.Stat(opts.FilePath); err == nil {
		if !opts.Overwrite && !opts.ResumeDownload {
			return nil, fmt.Errorf("%w: %s", ErrFileExists, opts.FilePath)
		}
		// ResumeDownload takes precedence over Overwrite when both are set:
		// the existing file is extended rather than replaced.
		if opts.ResumeDownload {
			resumeOffset = fileInfo.Size()
			rangeOption := WithHeader("Range", fmt.Sprintf("bytes=%d-", resumeOffset))
			combined := make([]RequestOption, len(options)+1)
			copy(combined, options)
			combined[len(options)] = rangeOption
			options = combined
		}
	}

	// Use streaming mode to avoid buffering the entire response body into memory.
	streamOptions := make([]RequestOption, len(options)+1)
	copy(streamOptions, options)
	streamOptions[len(options)] = WithStreamBody(true)

	rawResp, err := c.executeRequest(ctx, "GET", url, streamOptions)
	if err != nil {
		return nil, fmt.Errorf("download request failed: %w", err)
	}
	if rawResp == nil {
		return nil, fmt.Errorf("download request returned nil response")
	}
	engResp, ok := rawResp.(*engine.Response)
	if !ok {
		releaseResponseMutator(rawResp)
		return nil, fmt.Errorf("unexpected response type from download request")
	}
	bodyReader := engResp.RawBodyReader()
	engResp.SetRawBodyReader(nil)
	// Transfer body reader ownership from Response to this function.
	// Setting nil prevents ReleaseResponse from closing the reader; we
	// manage its lifetime here. Closed via defer below, or by
	// writeDownloadBody's io.Copy completing the read.
	defer engine.ReleaseResponse(engResp)

	if bodyReader != nil {
		defer func() { _ = bodyReader.Close() }() // best-effort cleanup
	}

	statusCode := engResp.StatusCode()
	contentLength := engResp.ContentLength()
	responseCookies := engResp.Cookies()

	// Measure the full download duration including body transfer.
	// engResp.Duration() only covers time-to-first-header, which would
	// produce misleading AverageSpeed values for large downloads.
	downloadStart := time.Now()

	resumed := resumeOffset > 0 && statusCode == http.StatusPartialContent

	// When resume was requested but server returned 200 instead of 206,
	// the server does not support range requests. Truncating the existing
	// partial file would silently destroy data the user intended to resume.
	if resumeOffset > 0 && !resumed {
		return nil, fmt.Errorf("server does not support range requests (status %d); cannot resume download", statusCode)
	}

	// Validate response status
	if err := handleDownloadStatus(statusCode, bodyReader, resumeOffset); err != nil {
		return nil, err
	}

	if bodyReader == nil {
		return nil, fmt.Errorf("download response has no body reader")
	}

	return writeDownloadBody(bodyReader, opts, resumed, resumeOffset, statusCode, contentLength, downloadStart, responseCookies)
}

// handleDownloadStatus validates the HTTP response status for a download request.
// Returns an error for 416 Range Not Satisfiable (with body drained),
// an error for unexpected status codes (with body drained),
// or nil for 200 OK / 206 Partial Content (body left intact for caller).
func handleDownloadStatus(statusCode int, bodyReader io.Reader, resumeOffset int64) error {
	if resumeOffset > 0 && statusCode == http.StatusRequestedRangeNotSatisfiable {
		// Drain body for connection reuse
		if bodyReader != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(bodyReader, 1<<20))
		}
		return fmt.Errorf("server cannot satisfy range request (416)")
	}

	if statusCode != http.StatusOK && statusCode != http.StatusPartialContent {
		var bodyPreview string
		if bodyReader != nil {
			previewBuf := make([]byte, 512)
			n, _ := bodyReader.Read(previewBuf)
			if n > 0 {
				bodyPreview = string(previewBuf[:n])
				if len(bodyPreview) > 200 {
					bodyPreview = bodyPreview[:200] + "..."
				}
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(bodyReader, 1<<20))
		}
		if bodyPreview != "" {
			return fmt.Errorf("unexpected status code: %d: %s", statusCode, bodyPreview)
		}
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}

	return nil
}

// writeDownloadBody streams the response body to a file and returns download statistics.
func writeDownloadBody(bodyReader io.Reader, opts *DownloadConfig, resumed bool, resumeOffset int64, statusCode int, contentLength int64, downloadStart time.Time, responseCookies []*http.Cookie) (*DownloadResult, error) {
	var file *os.File
	var err error
	if resumed {
		file, err = os.OpenFile(opts.FilePath, os.O_WRONLY|os.O_APPEND, filePermissions)
	} else {
		file, err = os.OpenFile(opts.FilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePermissions)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	// Stream body directly from network to file — no full-body buffering.
	// When checksum verification is requested, hash the data as it passes through.
	var writer io.Writer = file
	var hasher hash.Hash
	if opts.Checksum != "" {
		hasher = sha256.New()
		writer = io.MultiWriter(file, hasher)
	}
	if opts.ProgressCallback != nil {
		totalSize := contentLength
		if resumed {
			totalSize += resumeOffset
		}
		writer = &progressWriter{
			w:            writer,
			callback:     opts.ProgressCallback,
			total:        totalSize,
			offset:       resumeOffset,
			startTime:    time.Now(),
			lastCallback: time.Now(),
		}
	}

	bytesWritten, err := io.Copy(writer, bodyReader)
	if err != nil {
		_ = file.Close()
		if !resumed {
			_ = os.Remove(opts.FilePath) // best-effort cleanup of partial file
		}
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	// Sync and close file before potential checksum-based removal
	if syncErr := file.Sync(); syncErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to sync file: %w", syncErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		return nil, fmt.Errorf("failed to close file: %w", closeErr)
	}

	// Compute actual checksum if hashing was enabled
	var actualChecksum string
	if hasher != nil {
		actualChecksum = hex.EncodeToString(hasher.Sum(nil))
	}

	// Verify checksum if expected value is provided
	if opts.Checksum != "" && actualChecksum != strings.ToLower(opts.Checksum) {
		_ = os.Remove(opts.FilePath)
		return nil, fmt.Errorf("checksum mismatch: expected %s, got %s", strings.ToLower(opts.Checksum), actualChecksum)
	}

	duration := time.Since(downloadStart)
	avgSpeed := calculateSpeed(bytesWritten, duration)

	// Final callback with complete stats
	if opts.ProgressCallback != nil {
		totalSize := contentLength
		if resumed {
			totalSize += resumeOffset
		}
		opts.ProgressCallback(resumeOffset+bytesWritten, totalSize, avgSpeed)
	}

	return &DownloadResult{
		FilePath:        opts.FilePath,
		BytesWritten:    bytesWritten,
		Duration:        duration,
		AverageSpeed:    avgSpeed,
		StatusCode:      statusCode,
		ContentLength:   contentLength,
		Resumed:         resumed,
		ResponseCookies: responseCookies,
		ActualChecksum:  actualChecksum,
	}, nil
}

const (
	maxFilePathLen  = 4096
	dirPermissions  = 0755
	filePermissions = 0644
)

// getSystemPaths returns platform-specific system paths that should be protected.
func getSystemPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			"c:\\windows\\", "c:\\system32\\",
			"c:\\program files\\", "c:\\programdata\\",
			"c:\\program files (x86)\\",
			// Env-var patterns: Go os.ExpandEnv does not expand %VAR% syntax, these are handled by isSystemPath via os.Getenv
			"%systemroot%", "%windir%", "%programfiles%", "%programfiles(x86)%",
		}
	case "darwin":
		return []string{
			"/system/", "/library/", "/applications/",
			"/usr/", "/bin/", "/sbin/", "/etc/", "/var/",
		}
	case "linux":
		fallthrough
	default:
		return []string{
			"/etc/", "/sys/", "/proc/", "/dev/", "/boot/",
			"/root/",
			"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
			"/lib/", "/lib32/", "/lib64/", "/usr/lib/", "/usr/lib32/", "/usr/lib64/",
			"/run/", "/var/run/", "/sys/fs/",
		}
	}
}

// systemPathsOnce ensures getSystemPaths() is called only once.
var (
	systemPathsOnce   sync.Once
	cachedSystemPaths []string
)

func getSystemPathsCached() []string {
	systemPathsOnce.Do(func() {
		cachedSystemPaths = getSystemPaths()
	})
	return cachedSystemPaths
}

func calculateSpeed(bytes int64, duration time.Duration) float64 {
	if duration.Seconds() > 0 {
		return float64(bytes) / duration.Seconds()
	}
	return 0
}

// prepareFilePath validates and prepares file paths with security checks.
// Returns the validated absolute path that should be used for all file operations.
// SECURITY: This function implements multiple layers of protection:
// 1. UNC path blocking (prevents network resource access)
// 2. Control character filtering
// 3. System path protection
// 4. Path traversal detection
// 5. Symlink attack prevention
func prepareFilePath(filePath string) (string, error) {
	filePathLen := len(filePath)
	if filePathLen == 0 {
		return "", ErrEmptyFilePath
	}
	if filePathLen > maxFilePathLen {
		return "", fmt.Errorf("file path too long (max %d)", maxFilePathLen)
	}

	// Check for UNC paths
	if filePathLen >= 2 {
		if (filePath[0] == '\\' && filePath[1] == '\\') || (filePath[0] == '/' && filePath[1] == '/') {
			return "", fmt.Errorf("UNC paths not allowed for security")
		}
	}

	// Validate characters
	for i := range filePathLen {
		c := filePath[i]
		if c < 0x20 || c == 0x7F || c == 0 {
			return "", fmt.Errorf("file path contains invalid characters at position %d", i)
		}
	}

	cleanPath := filepath.Clean(filePath)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	// SECURITY: Check for symlinks to prevent symlink attacks
	// An attacker could create a symlink pointing to a sensitive file
	// and trick the application into writing to that file
	if fi, err := os.Lstat(absPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink paths not allowed for security")
		}
	}

	// Check for system path access
	if isSystemPath(absPath) {
		return "", fmt.Errorf("system path access denied for security")
	}

	// Check for path traversal: after filepath.Clean, only paths starting with ".."
	// indicate traversal above CWD. Filenames like "backup..zip" are safe.
	if !filepath.IsAbs(filePath) && strings.HasPrefix(cleanPath, "..") {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}
		wdAbs, err := filepath.Abs(wd)
		if err != nil {
			return "", fmt.Errorf("failed to resolve working directory: %w", err)
		}

		if !strings.HasPrefix(absPath+string(filepath.Separator), wdAbs+string(filepath.Separator)) {
			return "", fmt.Errorf("path traversal detected: path outside working directory")
		}
	}

	// SECURITY: Check parent directory for symlinks as well
	// This prevents TOCTOU attacks where a directory is replaced with a symlink
	dir := filepath.Dir(absPath)
	if dir != absPath { // Avoid infinite recursion at root
		if err := checkParentDirSymlinks(dir, 0); err != nil {
			return "", err
		}
	}

	// Create directories
	if err := os.MkdirAll(dir, dirPermissions); err != nil {
		return "", fmt.Errorf("failed to create directories: %w", err)
	}

	return absPath, nil
}

// checkParentDirSymlinks recursively checks if any parent directory is a symlink
// to prevent symlink-based path traversal attacks.
func checkParentDirSymlinks(dir string, depth int) error {
	const maxDepth = 32
	if depth > maxDepth {
		return fmt.Errorf("directory depth limit exceeded")
	}

	// Resolve the directory to its real path
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		// If the directory doesn't exist yet, that's okay - it will be created
		if os.IsNotExist(err) {
			// Check parent recursively
			parent := filepath.Dir(dir)
			if parent != dir {
				return checkParentDirSymlinks(parent, depth+1)
			}
			return nil
		}
		return fmt.Errorf("failed to evaluate symlinks: %w", err)
	}

	// If the resolved path differs from the original, a symlink was involved
	// Check if the resolved path is in a system directory
	if resolvedDir != dir {
		if isSystemPath(resolvedDir) {
			return fmt.Errorf("symlink resolves to system path")
		}
	}

	return nil
}

func isSystemPath(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return true
	}

	cleanPath := filepath.Clean(absPath)

	systemPaths := getSystemPathsCached()

	// Normalize cleanPath once outside the loop
	cleanPathForCompare := cleanPath
	if runtime.GOOS == "windows" {
		cleanPathForCompare = strings.ToLower(cleanPath)
		cleanPathForCompare = strings.ReplaceAll(cleanPathForCompare, "/", "\\")
	} else {
		cleanPathForCompare = strings.ReplaceAll(cleanPathForCompare, "\\", "/")
	}

	for _, sysPath := range systemPaths {
		// Handle environment variable patterns on Windows.
		// Append trailing separator after expansion to prevent prefix collision
		// (e.g., expanded "C:\Windows" must not match "C:\WindowsEvil").
		if strings.HasPrefix(sysPath, "%") && runtime.GOOS == "windows" {
			expanded := os.ExpandEnv(sysPath)
			if expanded != sysPath {
				normalized := strings.TrimRight(strings.ToLower(expanded), "\\") + "\\"
				if strings.HasPrefix(cleanPathForCompare, normalized) {
					return true
				}
			}
		}

		sysPathForCompare := sysPath
		if runtime.GOOS == "windows" {
			sysPathForCompare = strings.ToLower(sysPathForCompare)
		} else {
			sysPathForCompare = strings.ReplaceAll(sysPathForCompare, "\\", "/")
		}

		if strings.HasPrefix(cleanPathForCompare, sysPathForCompare) {
			return true
		}
	}

	return false
}

// progressWriter wraps an io.Writer to invoke progress callbacks during download.
// Callbacks fire at most once per progressInterval to avoid overhead on fast networks.
type progressWriter struct {
	w            io.Writer
	callback     DownloadProgressCallback
	total        int64
	offset       int64
	written      int64
	startTime    time.Time
	lastCallback time.Time
}

const progressInterval = 200 * time.Millisecond

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.w.Write(p)
	if n > 0 {
		pw.written += int64(n)
		if now := time.Now(); now.Sub(pw.lastCallback) >= progressInterval {
			elapsed := now.Sub(pw.startTime).Seconds()
			var speed float64
			if elapsed > 0 {
				speed = float64(pw.written) / elapsed
			}
			pw.callback(pw.offset+pw.written, pw.total, speed)
			pw.lastCallback = now
		}
	}
	return n, err
}
