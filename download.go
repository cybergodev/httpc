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

	// maxDrainBodySize caps how many response-body bytes are read and discarded
	// on error paths to allow connection reuse. Bounded to avoid spending
	// unbounded time/memory draining an oversized error body; the remainder is
	// left unread and the connection is not reused in that case.
	maxDrainBodySize = 1 << 20 // 1 MiB
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
//	result, err := httpc.Download(context.Background(), url, cfg)
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
	// Proto is the HTTP protocol version of the response (e.g., "HTTP/1.1", "HTTP/2.0").
	Proto string
	// ResponseHeaders contains the response headers from the download.
	ResponseHeaders http.Header
	// RequestURL is the actual URL that was requested.
	RequestURL string
	// RequestMethod is the HTTP method used for the download.
	RequestMethod string
	// RequestHeaders contains the request headers that were sent.
	RequestHeaders http.Header
}

// doPackageDownload is a helper for package-level download functions.
// It obtains the default client and delegates to the provided function.
func doPackageDownload(fn func(Client) (*DownloadResult, error)) (*DownloadResult, error) {
	client, err := getDefaultClient()
	if err != nil {
		return nil, err
	}
	return fn(client)
}

// Download downloads a file from url to the path specified in cfg, using the
// default client with the given context and request options.
//
// Download is the single canonical download entry point across the package,
// the Client interface, and DomainClient: one signature collapses the former
// {config} × {context} variant matrix. Callers that already hold a client or
// DomainClient use the Download method of the same signature.
//
// cfg must be non-nil; cfg.FilePath must be set (ErrEmptyFilePath otherwise).
// Use context.Background() when no cancellation or timeout is required. Pass
// options for headers, authentication, query parameters, etc.
func Download(ctx context.Context, url string, cfg *DownloadConfig, options ...RequestOption) (*DownloadResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("download config cannot be nil")
	}
	return doPackageDownload(func(c Client) (*DownloadResult, error) {
		return c.Download(ctx, url, cfg, options...)
	})
}

// Download downloads a file from url to the path specified in cfg, using the
// client's configuration with the given context and request options.
// cfg must be non-nil; cfg.FilePath must be set (ErrEmptyFilePath otherwise).
// Use DefaultDownloadConfig() as the starting point, then set FilePath and any
// of ProgressCallback / Overwrite / ResumeDownload / Checksum as needed.
func (c *clientImpl) Download(ctx context.Context, url string, cfg *DownloadConfig, options ...RequestOption) (*DownloadResult, error) {
	return c.downloadFile(ctx, url, cfg, options...)
}

func (c *clientImpl) downloadFile(ctx context.Context, url string, opts *DownloadConfig, options ...RequestOption) (result *DownloadResult, err error) {
	// SEC-003: default panic safety net for the download path. Mirrors the guard in
	// clientImpl.Request. Deferred cleanups registered below (engine.ReleaseResponse,
	// bodyReader.Close) run during unwinding before this recover (LIFO), so streaming
	// resources are released even when a panic is converted to an error.
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = panicToError(r)
		}
	}()
	if opts == nil {
		return nil, fmt.Errorf("download config cannot be nil")
	}
	if opts.FilePath == "" {
		return nil, ErrEmptyFilePath
	}

	filePath, resumeOffset, options, err := prepareResumeState(opts.FilePath, opts, options)
	if err != nil {
		return nil, err
	}

	// Use streaming mode to avoid buffering the entire response body into memory.
	streamOptions := make([]RequestOption, len(options), len(options)+1)
	copy(streamOptions, options)
	streamOptions = append(streamOptions, WithStreamBody(true))

	rawResp, err := c.executeRequest(ctx, "GET", url, streamOptions)
	if err != nil {
		return nil, fmt.Errorf("download request failed: %w", err)
	}
	if rawResp == nil {
		return nil, fmt.Errorf("download request returned nil response")
	}

	engResp, ok := rawResp.(*engine.Response)
	if !ok {
		// Non-engine responses come from middleware that wraps the engine.Response.
		// Downloads require direct access to the body reader, which is only
		// available on *engine.Response.
		releaseResponseMutator(rawResp)
		return nil, fmt.Errorf("download is not compatible with middleware that wraps ResponseMutator")
	}

	// Register the release defer BEFORE extracting fields: extractDownloadFields
	// reads several accessors on the pooled *engine.Response, and a panic there
	// would otherwise leak the response (the safety net above converts the panic
	// to an error but, without this defer already registered, ReleaseResponse
	// would never run). extractDownloadFields nils the body reader on the
	// response, so ReleaseResponse will not close it; the dedicated bodyReader
	// defer below owns the reader lifetime.
	defer engine.ReleaseResponse(engResp)
	df := extractDownloadFields(engResp)
	if df.bodyReader != nil {
		defer func() { _ = df.bodyReader.Close() }() // best-effort cleanup
	}

	resumed := resumeOffset > 0 && df.statusCode == http.StatusPartialContent

	// When resume was requested but server returned 200 instead of 206,
	// the server does not support range requests. Truncating the existing
	// partial file would silently destroy data the user intended to resume.
	if resumeOffset > 0 && !resumed {
		_, _ = io.Copy(io.Discard, io.LimitReader(df.bodyReader, maxDrainBodySize))
		return nil, fmt.Errorf("server does not support range requests (status %d); cannot resume download", df.statusCode)
	}

	// Validate response status
	if err := handleDownloadStatus(df.statusCode, df.bodyReader, resumeOffset); err != nil {
		return nil, err
	}

	if df.bodyReader == nil {
		return nil, fmt.Errorf("download response has no body reader")
	}

	downloadStart := time.Now()
	result, writeErr := writeDownloadBody(df.bodyReader, filePath, opts, resumed, resumeOffset, df.statusCode, df.contentLength, downloadStart, df.responseCookies)
	if writeErr != nil {
		return nil, writeErr
	}
	result.Proto = df.proto
	result.ResponseHeaders = df.responseHeaders
	result.RequestURL = df.requestURL
	result.RequestMethod = df.requestMethod
	result.RequestHeaders = df.requestHeaders
	return result, nil
}

// prepareResumeState validates the file path and calculates resume state.
// Returns the validated file path, resume offset, updated options, and any error.
func prepareResumeState(filePath string, opts *DownloadConfig, options []RequestOption) (string, int64, []RequestOption, error) {
	validatedPath, err := prepareFilePath(filePath)
	if err != nil {
		return "", 0, nil, fmt.Errorf("failed to prepare file path: %w", err)
	}

	var resumeOffset int64
	if fileInfo, err := os.Stat(validatedPath); err == nil {
		if fileInfo.IsDir() {
			return "", 0, nil, fmt.Errorf("path is a directory, not a file: %s", validatedPath)
		}
		if !opts.Overwrite && !opts.ResumeDownload {
			return "", 0, nil, fmt.Errorf("%w: %s", ErrFileExists, validatedPath)
		}
		// ResumeDownload takes precedence over Overwrite when both are set:
		// the existing file is extended rather than replaced.
		if opts.ResumeDownload {
			resumeOffset = fileInfo.Size()
			rangeOption := WithHeader("Range", fmt.Sprintf("bytes=%d-", resumeOffset))
			combined := make([]RequestOption, len(options), len(options)+1)
			copy(combined, options)
			options = append(combined, rangeOption)
		}
	}

	return validatedPath, resumeOffset, options, nil
}

// downloadFields holds extracted fields from an engine.Response for download processing.
// Transfers body reader ownership to the caller.
type downloadFields struct {
	bodyReader      io.ReadCloser
	statusCode      int
	contentLength   int64
	responseCookies []*http.Cookie
	proto           string
	requestURL      string
	requestMethod   string
	responseHeaders http.Header
	requestHeaders  http.Header
}

// extractDownloadFields extracts download-relevant fields from an engine Response.
// Transfers body reader and header ownership to the caller, avoiding Clone
// allocations — ReleaseResponse will zero the Response afterward, so the
// transferred maps are the sole surviving reference. The caller must call
// engine.ReleaseResponse(engResp) after the body reader is no longer needed.
func extractDownloadFields(engResp *engine.Response) downloadFields {
	// Transfer body reader ownership; nil prevents ReleaseResponse from closing it.
	df := downloadFields{
		bodyReader:      engResp.RawBodyReader(),
		statusCode:      engResp.StatusCode(),
		contentLength:   engResp.ContentLength(),
		responseCookies: engResp.Cookies(),
		proto:           engResp.Proto(),
		requestURL:      engResp.RequestURL(),
		requestMethod:   engResp.RequestMethod(),
		responseHeaders: engResp.TransferHeaders(),
		requestHeaders:  engResp.TransferRequestHeaders(),
	}
	engResp.SetRawBodyReader(nil)

	return df
}

// handleDownloadStatus validates the HTTP response status for a download request.
// Returns an error for 416 Range Not Satisfiable (with body drained),
// an error for unexpected status codes (with body drained),
// or nil for 200 OK / 206 Partial Content (body left intact for caller).
func handleDownloadStatus(statusCode int, bodyReader io.Reader, resumeOffset int64) error {
	if resumeOffset > 0 && statusCode == http.StatusRequestedRangeNotSatisfiable {
		// Drain body for connection reuse
		if bodyReader != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(bodyReader, maxDrainBodySize))
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
			_, _ = io.Copy(io.Discard, io.LimitReader(bodyReader, maxDrainBodySize))
		}
		if bodyPreview != "" {
			return fmt.Errorf("unexpected status code: %d: %s", statusCode, bodyPreview)
		}
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}

	return nil
}

// writeDownloadBody streams the response body to a file and returns download statistics.
func writeDownloadBody(bodyReader io.Reader, filePath string, opts *DownloadConfig, resumed bool, resumeOffset int64, statusCode int, contentLength int64, downloadStart time.Time, responseCookies []*http.Cookie) (*DownloadResult, error) {
	// Validate checksum algorithm BEFORE touching the destination file.
	// A configuration error must not truncate (O_TRUNC) an existing file.
	if opts.Checksum != "" && opts.ChecksumAlgorithm != ChecksumSHA256 && opts.ChecksumAlgorithm != "" {
		return nil, fmt.Errorf("unsupported checksum algorithm: %s", opts.ChecksumAlgorithm)
	}

	var file *os.File
	var err error
	if resumed {
		file, err = os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, filePermissions)
	} else {
		file, err = os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePermissions)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	// Stream body directly from network to file — no full-body buffering.
	// When checksum verification is requested, hash the data as it passes through.
	var writer io.Writer = file
	var hasher hash.Hash
	if opts.Checksum != "" {
		// Algorithm already validated above; both SHA-256 and the empty
		// default map to SHA-256.
		hasher = sha256.New()
		writer = io.MultiWriter(file, hasher)
	}
	if opts.ProgressCallback != nil {
		totalSize := contentLength
		if resumed && totalSize > 0 {
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
		_ = file.Close() // best-effort cleanup on write failure
		if !resumed {
			_ = os.Remove(filePath) // best-effort cleanup of partial file
		}
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	// Sync and close file before potential checksum-based removal.
	// On failure, remove the partial file (unless resuming, where the
	// pre-existing bytes should be preserved for the next resume attempt).
	if syncErr := file.Sync(); syncErr != nil {
		_ = file.Close() // best-effort cleanup on sync failure
		if !resumed {
			_ = os.Remove(filePath) // don't leave a truncated/corrupt file
		}
		return nil, fmt.Errorf("failed to sync file: %w", syncErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		if !resumed {
			_ = os.Remove(filePath)
		}
		return nil, fmt.Errorf("failed to close file: %w", closeErr)
	}

	// Compute actual checksum if hashing was enabled
	var actualChecksum string
	if hasher != nil {
		actualChecksum = hex.EncodeToString(hasher.Sum(nil))
	}

	// Verify checksum if expected value is provided
	if opts.Checksum != "" && actualChecksum != strings.ToLower(opts.Checksum) {
		_ = os.Remove(filePath) // remove corrupted download
		return nil, fmt.Errorf("checksum mismatch: expected %s, got %s", strings.ToLower(opts.Checksum), actualChecksum)
	}

	duration := time.Since(downloadStart)
	avgSpeed := calculateSpeed(bytesWritten, duration)

	// Final callback with complete stats
	if opts.ProgressCallback != nil {
		totalSize := contentLength
		if resumed && totalSize > 0 {
			totalSize += resumeOffset
		}
		opts.ProgressCallback(resumeOffset+bytesWritten, totalSize, avgSpeed)
	}

	return &DownloadResult{
		FilePath:        filePath,
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
			// Env-var patterns, expanded at check time by isSystemPath via
			// os.ExpandEnv. Go only expands ${VAR}/$VAR syntax, NOT Windows
			// %VAR%, so the brace form is required here — a previous %VAR%
			// form expanded to itself and the branch was dead code. These
			// catch installs on a non-C drive where the literals above miss.
			"${SystemRoot}", "${windir}", "${ProgramFiles}", "${ProgramFiles(x86)}",
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

// normalizedSystemEntry holds a pre-normalized system path for fast comparison.
// envPattern is non-empty only on Windows for env-var patterns (e.g., "${SystemRoot}").
type normalizedSystemEntry struct {
	normalized string
	envPattern string // original "${VAR}" pattern, empty for literal paths
}

var (
	systemPathsOnce   sync.Once
	cachedSystemPaths []normalizedSystemEntry
)

// initNormalizedSystemPaths pre-computes normalized system paths once.
// Paths are cleaned, lowercased (Windows), and separator-normalized at init
// time so isSystemPath only needs a single HasPrefix check per entry.
func initNormalizedSystemPaths() {
	raw := getSystemPaths()
	cachedSystemPaths = make([]normalizedSystemEntry, len(raw))
	for i, p := range raw {
		// Windows env-var patterns (e.g., "${SystemRoot}") are expanded at
		// check time, so store the original pattern and skip static normalization.
		if strings.HasPrefix(p, "${") && runtime.GOOS == "windows" {
			cachedSystemPaths[i] = normalizedSystemEntry{envPattern: p}
			continue
		}
		p = filepath.Clean(p)
		if runtime.GOOS == "windows" {
			p = strings.ToLower(p)
			p = strings.ReplaceAll(p, "/", "\\")
		} else {
			p = strings.ReplaceAll(p, "\\", "/")
		}
		// Ensure trailing separator to prevent prefix collision
		// (e.g., "C:\Windows" must not match "C:\WindowsEvil").
		if !strings.HasSuffix(p, string(filepath.Separator)) {
			p += string(filepath.Separator)
		}
		cachedSystemPaths[i] = normalizedSystemEntry{normalized: p}
	}
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

	// Check for system path access (direct path check; symlink targets
	// are checked separately by checkParentDirSymlinks below).
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

// isSystemPath checks whether the given absolute path falls within a protected
// system directory. The caller must supply an already-resolved absolute path
// (e.g., from prepareFilePath) — no redundant filepath.Abs is performed.
func isSystemPath(absPath string) bool {
	systemPathsOnce.Do(initNormalizedSystemPaths)

	// Normalize the input path once for comparison
	pathNorm := absPath
	if runtime.GOOS == "windows" {
		pathNorm = strings.ToLower(pathNorm)
		pathNorm = strings.ReplaceAll(pathNorm, "/", "\\")
	} else {
		pathNorm = strings.ReplaceAll(pathNorm, "\\", "/")
	}
	// Ensure trailing separator for consistent prefix matching
	if !strings.HasSuffix(pathNorm, string(filepath.Separator)) {
		pathNorm += string(filepath.Separator)
	}

	for _, entry := range cachedSystemPaths {
		if entry.envPattern != "" {
			// Windows env-var pattern: expand at check time
			expanded := os.ExpandEnv(entry.envPattern)
			if expanded == entry.envPattern {
				continue // env var not set
			}
			normalized := strings.TrimRight(strings.ToLower(expanded), "\\") + "\\"
			if strings.HasPrefix(pathNorm, normalized) {
				return true
			}
			continue
		}
		if strings.HasPrefix(pathNorm, entry.normalized) {
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
			speed := calculateSpeed(pw.written, now.Sub(pw.startTime))
			pw.callback(pw.offset+pw.written, pw.total, speed)
			pw.lastCallback = now
		}
	}
	return n, err
}
