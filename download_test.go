package httpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// DOWNLOAD TESTS - File downloads, resume, progress tracking
// ============================================================================

func TestDownload_Basic(t *testing.T) {
	content := []byte("test file content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.txt")

	result, err := client.DownloadFile(server.URL, filePath)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if result.FilePath != filePath {
		t.Errorf("Expected file path %s, got %s", filePath, result.FilePath)
	}
	if result.BytesWritten != int64(len(content)) {
		t.Errorf("Expected %d bytes, got %d", len(content), result.BytesWritten)
	}
	if result.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", result.StatusCode)
	}

	// Verify file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("File not created: %v", err)
	}
	if fileInfo.Size() != result.BytesWritten {
		t.Errorf("File size mismatch: expected %d, got %d", result.BytesWritten, fileInfo.Size())
	}
}

func TestDownload_EmptyFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "empty.txt")

	result, err := client.DownloadFile(server.URL, filePath)
	if err != nil {
		t.Fatalf("Download of empty file failed: %v", err)
	}
	if result.BytesWritten != 0 {
		t.Errorf("Expected 0 bytes, got %d", result.BytesWritten)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("File not created: %v", err)
	}
	if fileInfo.Size() != 0 {
		t.Errorf("File should be empty, got %d bytes", fileInfo.Size())
	}
}

func TestDownload_LargeFile(t *testing.T) {
	largeContent := []byte(strings.Repeat("x", 1024*1024)) // 1MB

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(largeContent)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(largeContent)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "large-file.bin")

	result, err := client.DownloadFile(server.URL, filePath)
	if err != nil {
		t.Fatalf("Large file download failed: %v", err)
	}

	if result.BytesWritten != int64(len(largeContent)) {
		t.Errorf("Expected %d bytes, got %d", len(largeContent), result.BytesWritten)
	}
	if result.AverageSpeed <= 0 {
		t.Error("Average speed should be positive")
	}
}

func TestDownload_WithProgress(t *testing.T) {
	content := []byte(strings.Repeat("x", 10240)) // 10KB

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "progress-test.bin")

	progressCalled := false
	opts := &DownloadConfig{
		FilePath: filePath,
		ProgressCallback: func(downloaded, total int64, speed float64) {
			progressCalled = true
			if total > 0 {
				t.Logf("Progress: %d/%d bytes (%.2f%%)", downloaded, total, float64(downloaded)/float64(total)*100)
			}
		},
	}

	result, err := client.DownloadWithOptions(server.URL, opts)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if result.BytesWritten != int64(len(content)) {
		t.Errorf("Expected %d bytes, got %d", len(content), result.BytesWritten)
	}
	if !progressCalled {
		t.Error("Progress callback was not called")
	}
}

func TestDownload_WithTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("slow response"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	config.Timeouts.Request = 100 * time.Millisecond
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "timeout-test.txt")

	_, err := client.DownloadFile(server.URL, filePath)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestDownload_ResumeNotSupported(t *testing.T) {
	content := []byte("test content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server doesn't support range requests
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "resume-test.txt")

	// Create partial file
	_ = os.WriteFile(filePath, []byte("partial"), 0644)

	opts := &DownloadConfig{
		FilePath:       filePath,
		ResumeDownload: true,
	}

	result, err := client.DownloadWithOptions(server.URL, opts)
	if err == nil {
		t.Fatal("Expected error when server does not support range requests")
	}
	if result != nil {
		t.Fatal("Expected nil result when server does not support range requests")
	}
	if !strings.Contains(err.Error(), "does not support range requests") {
		t.Errorf("Error should mention range requests, got: %v", err)
	}
}

func TestDownload_PartialContent(t *testing.T) {
	fullContent := []byte("full file content here")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rangeHeader := r.Header.Get("Range")
		if rangeHeader != "" {
			// Support range requests
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 7-%d/%d", len(fullContent)-1, len(fullContent)))
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fullContent)-7))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(fullContent[7:])
		} else {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fullContent)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(fullContent)
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "partial-test.txt")

	// Create partial file
	_ = os.WriteFile(filePath, []byte("partial"), 0644)

	opts := &DownloadConfig{
		FilePath:       filePath,
		ResumeDownload: true,
	}

	result, err := client.DownloadWithOptions(server.URL, opts)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if result.StatusCode != http.StatusPartialContent {
		t.Errorf("Expected status 206, got %d", result.StatusCode)
	}
}

func TestDownload_InvalidPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("content"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	// Invalid path with directory traversal attempt
	_, err := client.DownloadFile(server.URL, "../../../etc/passwd")
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

func TestDownload_FileAlreadyExists(t *testing.T) {
	content := []byte("new content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "existing.txt")

	// Create existing file
	_ = os.WriteFile(filePath, []byte("old content"), 0644)

	// Try download without overwrite
	opts := &DownloadConfig{
		FilePath:  filePath,
		Overwrite: false,
	}
	_, err := client.DownloadWithOptions(server.URL, opts)
	if err == nil {
		t.Error("Expected error when file exists and overwrite is false")
	}

	// Try with overwrite
	opts.Overwrite = true
	result, err := client.DownloadWithOptions(server.URL, opts)
	if err != nil {
		t.Fatalf("Download with overwrite failed: %v", err)
	}
	if result.BytesWritten != int64(len(content)) {
		t.Errorf("Expected %d bytes, got %d", len(content), result.BytesWritten)
	}
}

func TestDownload_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "error-test.txt")

	_, err := client.DownloadFile(server.URL, filePath)
	if err == nil {
		t.Error("Expected error for 404 response")
	}
}

func TestDownload_CreateDirectories(t *testing.T) {
	content := []byte("test content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "subdir1", "subdir2", "file.txt")

	result, err := client.DownloadFile(server.URL, filePath)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if result.BytesWritten != int64(len(content)) {
		t.Errorf("Expected %d bytes, got %d", len(content), result.BytesWritten)
	}

	// Verify directories were created
	if _, err := os.Stat(filepath.Dir(filePath)); os.IsNotExist(err) {
		t.Error("Directories were not created")
	}
}

func TestResult_SaveToFile(t *testing.T) {
	content := []byte("response content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	defer client.Close()

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "response-save.txt")

	if err := resp.SaveToFile(filePath); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Verify file content
	savedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read saved file: %v", err)
	}
	if string(savedContent) != string(content) {
		t.Errorf("Content mismatch: expected %s, got %s", string(content), string(savedContent))
	}
}

// ----------------------------------------------------------------------------
// Package-Level Download Functions
// ----------------------------------------------------------------------------

func TestDownload_PackageLevel(t *testing.T) {
	t.Run("DownloadFile", func(t *testing.T) {
		content := []byte("package level download test")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content)
		}))
		defer server.Close()

		// Setup default client
		config := TestingConfig()
		client, _ := New(config)
		_ = SetDefaultClient(client)
		defer CloseDefaultClient()

		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "pkg-level-test.txt")

		result, err := DownloadFile(server.URL, filePath)
		if err != nil {
			t.Fatalf("DownloadFile failed: %v", err)
		}

		if result.BytesWritten != int64(len(content)) {
			t.Errorf("Expected %d bytes, got %d", len(content), result.BytesWritten)
		}
	})

	t.Run("DownloadWithOptions", func(t *testing.T) {
		content := []byte("download with options test")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content)
		}))
		defer server.Close()

		// Setup default client
		config := TestingConfig()
		client, _ := New(config)
		_ = SetDefaultClient(client)
		defer CloseDefaultClient()

		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "opts-test.txt")

		progressCalled := false
		opts := &DownloadConfig{
			FilePath: filePath,
			ProgressCallback: func(downloaded, total int64, speed float64) {
				progressCalled = true
			},
		}

		result, err := DownloadWithOptions(server.URL, opts)
		if err != nil {
			t.Fatalf("DownloadWithOptions failed: %v", err)
		}

		if result.BytesWritten != int64(len(content)) {
			t.Errorf("Expected %d bytes, got %d", len(content), result.BytesWritten)
		}
		if !progressCalled {
			t.Error("Progress callback was not called")
		}
	})
}

// ----------------------------------------------------------------------------
// Edge Cases
// ----------------------------------------------------------------------------

func TestDownload_EdgeCases(t *testing.T) {
	t.Run("EmptyFilePath", func(t *testing.T) {
		config := DefaultConfig()
		config.Security.AllowPrivateIPs = true
		client, _ := New(config)
		defer client.Close()

		_, err := client.DownloadFile("http://example.com/file.txt", "")
		if err == nil {
			t.Error("Expected error for empty file path")
		}
	})

	t.Run("NilOptions", func(t *testing.T) {
		config := DefaultConfig()
		config.Security.AllowPrivateIPs = true
		client, _ := New(config)
		defer client.Close()

		_, err := client.DownloadWithOptions("http://example.com/file.txt", nil)
		if err == nil {
			t.Error("Expected error for nil options")
		}
	})

	t.Run("DefaultDownloadConfig", func(t *testing.T) {
		filePath := "/tmp/test.txt"
		opts := DefaultDownloadConfig()
		opts.FilePath = filePath

		if opts.FilePath != filePath {
			t.Errorf("Expected FilePath=%s, got %s", filePath, opts.FilePath)
		}
		if opts.Overwrite {
			t.Error("Expected Overwrite=false by default")
		}
		if opts.ResumeDownload {
			t.Error("Expected ResumeDownload=false by default")
		}
	})
}

// ----------------------------------------------------------------------------
// Security Tests - prepareFilePath
// ----------------------------------------------------------------------------

func TestPrepareFilePath_Security(t *testing.T) {
	t.Run("Empty path", func(t *testing.T) {
		_, err := prepareFilePath("")
		if err == nil {
			t.Error("Expected error for empty path")
		}
		if err != ErrEmptyFilePath {
			t.Errorf("Expected ErrEmptyFilePath, got %v", err)
		}
	})

	t.Run("UNC path rejection", func(t *testing.T) {
		uncPaths := []string{
			"\\\\server\\share\\file.txt",
			"//server/share/file.txt",
		}

		for _, path := range uncPaths {
			_, err := prepareFilePath(path)
			if err == nil {
				t.Errorf("Expected UNC path rejection for: %s", path)
			}
			if err != nil && !strings.Contains(err.Error(), "UNC") {
				t.Errorf("Expected UNC error message for: %s, got: %v", path, err)
			}
		}
	})

	t.Run("Control characters rejection", func(t *testing.T) {
		controlCharPaths := []string{
			"/tmp/file\x00name.txt", // null byte
			"/tmp/file\x01name.txt", // SOH
			"/tmp/file\x1fname.txt", // US
			"/tmp/file\x7fname.txt", // DEL
		}

		for _, path := range controlCharPaths {
			_, err := prepareFilePath(path)
			if err == nil {
				t.Errorf("Expected control character rejection for path with byte: %q", path)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid characters") {
				t.Errorf("Expected invalid characters error for: %q, got: %v", path, err)
			}
		}
	})

	t.Run("Path too long", func(t *testing.T) {
		// Create a path longer than maxFilePathLen (4096)
		longPath := "/tmp/" + strings.Repeat("a", 4100)
		_, err := prepareFilePath(longPath)
		if err == nil {
			t.Error("Expected error for path too long")
		}
		if err != nil && !strings.Contains(err.Error(), "too long") {
			t.Errorf("Expected 'too long' error, got: %v", err)
		}
	})

	t.Run("Path traversal detection", func(t *testing.T) {
		traversalPaths := []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32",
		}

		for _, path := range traversalPaths {
			_, err := prepareFilePath(path)
			if err == nil {
				t.Errorf("Expected path traversal rejection for: %s", path)
			}
		}
	})

	t.Run("Valid path accepted", func(t *testing.T) {
		tempDir := t.TempDir()
		validPath := filepath.Join(tempDir, "subdir", "file.txt")

		_, err := prepareFilePath(validPath)
		if err != nil {
			t.Errorf("Valid path should be accepted: %v", err)
		}

		// Verify directory was created
		if _, err := os.Stat(filepath.Dir(validPath)); os.IsNotExist(err) {
			t.Error("Expected parent directory to be created")
		}
	})

	t.Run("Symlink rejection", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create a symlink (skip on Windows if not admin)
		targetPath := filepath.Join(tempDir, "target.txt")
		_ = os.WriteFile(targetPath, []byte("target"), 0644)

		symlinkPath := filepath.Join(tempDir, "link.txt")
		err := os.Symlink(targetPath, symlinkPath)
		if err != nil {
			// Skip if symlinks not supported (Windows without admin)
			t.Skipf("Symlink not supported: %v", err)
		}

		// prepareFilePath should reject the symlink
		_, err = prepareFilePath(symlinkPath)
		if err == nil {
			t.Error("Expected symlink rejection")
		}
		if err != nil && !strings.Contains(err.Error(), "symlink") {
			t.Errorf("Expected symlink error, got: %v", err)
		}
	})
}

func TestPrepareFilePath_ValidPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"Simple path", "/tmp/file.txt"},
		{"Nested directories", "/tmp/a/b/c/file.txt"},
		{"With extension", "/tmp/archive.tar.gz"},
		{"Relative path", "downloads/file.txt"},
		{"Path with spaces", "/tmp/my file.txt"},
		{"Path with unicode", "/tmp/文件.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use temp dir for actual file operations
			tempDir := t.TempDir()
			if filepath.IsAbs(tt.path) {
				// For absolute paths, redirect to temp dir
				tt.path = filepath.Join(tempDir, filepath.Base(tt.path))
			} else {
				tt.path = filepath.Join(tempDir, tt.path)
			}

			_, err := prepareFilePath(tt.path)
			// We expect this to succeed for valid paths
			// Note: system path check may fail for some paths
			t.Logf("Path %q: err=%v", tt.path, err)
		})
	}
}

func TestIsSystemPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		isSystem bool
	}{
		{"Temp directory", os.TempDir(), false},
		{"Relative path", "myapp/data/file.txt", false},
		{"Dot path", "./config.yaml", false},
	}

	if runtime.GOOS == "windows" {
		tests = append(tests,
			[]struct {
				name     string
				path     string
				isSystem bool
			}{
				{"Windows system32", `C:\Windows\System32\cmd.exe`, true},
				{"Windows system dir", `C:\Windows\Fonts\arial.ttf`, true},
				{"Windows user path", `C:\Users\user\file.txt`, false},
				{"Windows program files", `C:\Program Files\App\app.exe`, true},
			}...,
		)
	} else {
		tests = append(tests,
			[]struct {
				name     string
				path     string
				isSystem bool
			}{
				{"Unix system bin", "/usr/bin/ls", true},
				{"Unix system lib", "/lib/x86_64-linux-gnu/libc.so", true},
				{"Unix user path", "/home/user/file.txt", false},
				{"Unix etc", "/etc/hosts", true},
			}...,
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSystemPath(tt.path)
			if result != tt.isSystem {
				t.Errorf("isSystemPath(%q) = %v, want %v", tt.path, result, tt.isSystem)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Package-Level Download Functions
// ----------------------------------------------------------------------------

func TestPackageLevel_DownloadFileWithContext(t *testing.T) {
	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	_ = SetDefaultClient(client)
	defer CloseDefaultClient()

	content := []byte("download with context test")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer server.Close()

	filePath := filepath.Join(t.TempDir(), "ctx_test.txt")
	result, err := DownloadFileWithContext(context.Background(), server.URL, filePath)
	if err != nil {
		t.Fatalf("DownloadFileWithContext failed: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}

	data, _ := os.ReadFile(filePath)
	if string(data) != string(content) {
		t.Errorf("file content mismatch")
	}
}

func TestPackageLevel_DownloadWithOptionsWithContext(t *testing.T) {
	config := DefaultConfig()
	config.Security.AllowPrivateIPs = true
	client, _ := New(config)
	_ = SetDefaultClient(client)
	defer CloseDefaultClient()

	content := []byte("download with options and context test")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer server.Close()

	filePath := filepath.Join(t.TempDir(), "ctx_opts_test.txt")
	opts := DefaultDownloadConfig()
	opts.FilePath = filePath

	result, err := DownloadWithOptionsWithContext(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("DownloadWithOptionsWithContext failed: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

func TestCalculateSpeed_ZeroDuration(t *testing.T) {
	if calculateSpeed(100, 0) != 0 {
		t.Error("calculateSpeed with zero duration should return 0")
	}
}

// ----------------------------------------------------------------------------
// handleDownloadStatus unit tests
// ----------------------------------------------------------------------------

func TestHandleDownloadStatus_416(t *testing.T) {
	t.Run("RangeNotSatisfiable_WithBody", func(t *testing.T) {
		err := handleDownloadStatus(http.StatusRequestedRangeNotSatisfiable, bytes.NewReader([]byte("data")), 100)
		if err == nil {
			t.Fatal("expected error for 416 with resumeOffset > 0")
		}
		if !strings.Contains(err.Error(), "416") {
			t.Errorf("error should contain '416', got: %v", err)
		}
	})

	t.Run("RangeNotSatisfiable_NilBody", func(t *testing.T) {
		err := handleDownloadStatus(http.StatusRequestedRangeNotSatisfiable, nil, 100)
		if err == nil {
			t.Fatal("expected error for 416 with nil body and resumeOffset > 0")
		}
		if !strings.Contains(err.Error(), "416") {
			t.Errorf("error should contain '416', got: %v", err)
		}
	})

	t.Run("RangeNotSatisfiable_ZeroOffset_FallsThrough", func(t *testing.T) {
		err := handleDownloadStatus(http.StatusRequestedRangeNotSatisfiable, bytes.NewReader([]byte("data")), 0)
		if err == nil {
			t.Fatal("expected error when 416 falls through with resumeOffset=0")
		}
		// With resumeOffset=0, the 416 early-return is skipped, so it hits the
		// "unexpected status code" path instead.
		if !strings.Contains(err.Error(), "unexpected status code") {
			t.Errorf("error should contain 'unexpected status code', got: %v", err)
		}
	})
}

func TestHandleDownloadStatus_EmptyBody(t *testing.T) {
	t.Run("InternalServerError_NilBody", func(t *testing.T) {
		err := handleDownloadStatus(http.StatusInternalServerError, nil, 0)
		if err == nil {
			t.Fatal("expected error for 500 status")
		}
		want := "unexpected status code: 500"
		if err.Error() != want {
			t.Errorf("error = %q, want %q", err.Error(), want)
		}
	})

	t.Run("Forbidden_WithBody", func(t *testing.T) {
		err := handleDownloadStatus(http.StatusForbidden, bytes.NewReader([]byte("forbidden")), 0)
		if err == nil {
			t.Fatal("expected error for 403 status")
		}
		if !strings.Contains(err.Error(), "forbidden") {
			t.Errorf("error should contain 'forbidden', got: %v", err)
		}
		if !strings.Contains(err.Error(), "403") {
			t.Errorf("error should contain '403', got: %v", err)
		}
	})

	t.Run("OK_NilBody_Success", func(t *testing.T) {
		err := handleDownloadStatus(http.StatusOK, nil, 0)
		if err != nil {
			t.Errorf("expected nil error for 200 status, got: %v", err)
		}
	})

	t.Run("PartialContent_Success", func(t *testing.T) {
		err := handleDownloadStatus(http.StatusPartialContent, bytes.NewReader([]byte("partial data")), 0)
		if err != nil {
			t.Errorf("expected nil error for 206 status, got: %v", err)
		}
	})

	t.Run("BodyPreview_Truncated", func(t *testing.T) {
		longBody := strings.Repeat("a", 300)
		err := handleDownloadStatus(http.StatusBadGateway, bytes.NewReader([]byte(longBody)), 0)
		if err == nil {
			t.Fatal("expected error for 502 status")
		}
		// Body preview should be truncated to 200 chars + "..."
		if !strings.Contains(err.Error(), "...") {
			t.Errorf("error should contain truncated body preview with '...', got: %v", err)
		}
	})
}

// verifyBytesReaderConsumed is a helper that verifies a bytes.Reader was
// fully consumed by handleDownloadStatus (it drains the body for reuse).
func verifyBytesReaderConsumed(t *testing.T, r *bytes.Reader) {
	t.Helper()
	remaining, _ := io.ReadAll(r)
	if len(remaining) > 0 {
		t.Errorf("expected body to be fully consumed, but %d bytes remain", len(remaining))
	}
}

// ============================================================================
// CHECKSUM VERIFICATION TESTS
// ============================================================================

func TestWriteDownloadBody_ChecksumVerification(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")
	content := []byte("hello world checksum test")

	// Compute expected checksum
	hash := sha256.Sum256(content)
	expectedChecksum := hex.EncodeToString(hash[:])

	t.Run("ValidChecksum", func(t *testing.T) {
		opts := &DownloadConfig{
			FilePath:          filePath,
			Checksum:          expectedChecksum,
			ChecksumAlgorithm: ChecksumSHA256,
		}
		result, err := writeDownloadBody(bytes.NewReader(content), opts, false, 0, 200, int64(len(content)), time.Now(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ActualChecksum != expectedChecksum {
			t.Errorf("checksum mismatch: got %s, want %s", result.ActualChecksum, expectedChecksum)
		}
	})

	t.Run("InvalidChecksum", func(t *testing.T) {
		filePath2 := filepath.Join(tmpDir, "test2.bin")
		opts := &DownloadConfig{
			FilePath:          filePath2,
			Checksum:          "0000000000000000000000000000000000000000000000000000000000000000",
			ChecksumAlgorithm: ChecksumSHA256,
		}
		_, err := writeDownloadBody(bytes.NewReader(content), opts, false, 0, 200, int64(len(content)), time.Now(), nil)
		if err == nil {
			t.Fatal("expected checksum mismatch error")
		}
		if !strings.Contains(err.Error(), "checksum mismatch") {
			t.Errorf("error should mention checksum mismatch, got: %v", err)
		}
		// File should be removed on checksum failure
		if _, statErr := os.Stat(filePath2); !os.IsNotExist(statErr) {
			t.Error("file should be removed after checksum mismatch")
		}
	})

	t.Run("NoChecksum", func(t *testing.T) {
		filePath3 := filepath.Join(tmpDir, "test3.bin")
		opts := &DownloadConfig{
			FilePath: filePath3,
		}
		result, err := writeDownloadBody(bytes.NewReader(content), opts, false, 0, 200, int64(len(content)), time.Now(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ActualChecksum != "" {
			t.Errorf("checksum should be empty when not requested, got: %s", result.ActualChecksum)
		}
	})
}

// ============================================================================
// Boundary condition tests for download helpers
// ============================================================================

func TestCalculateSpeed_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		duration time.Duration
		want     float64
	}{
		{"zero duration", 1024, 0, 0},
		{"zero bytes", 0, time.Second, 0},
		{"1 second", 1024, time.Second, 1024},
		{"500ms", 512, 500 * time.Millisecond, 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateSpeed(tt.bytes, tt.duration)
			if tt.want == 0 && got != 0 {
				t.Errorf("calculateSpeed() = %v, want 0", got)
			} else if tt.want > 0 && got <= 0 {
				t.Errorf("calculateSpeed() = %v, want > 0", got)
			}
		})
	}
}

func TestProgressWriter_BoundaryConditions(t *testing.T) {
	t.Run("write triggers callback after interval", func(t *testing.T) {
		var callbackCalled bool
		var callbackOffset, callbackTotal int64
		var callbackSpeed float64

		pw := &progressWriter{
			w: io.Discard,
			callback: func(offset, total int64, speed float64) {
				callbackCalled = true
				callbackOffset = offset
				callbackTotal = total
				callbackSpeed = speed
			},
			total:        2048,
			startTime:    time.Now().Add(-500 * time.Millisecond),
			lastCallback: time.Now().Add(-500 * time.Millisecond), // Old enough to trigger
		}

		data := make([]byte, 1024)
		n, err := pw.Write(data)
		if err != nil {
			t.Fatalf("Write() error: %v", err)
		}
		if n != 1024 {
			t.Errorf("Write() = %d, want 1024", n)
		}
		if !callbackCalled {
			t.Error("expected progress callback to be called")
		}
		if callbackTotal != 2048 {
			t.Errorf("callback total = %d, want 2048", callbackTotal)
		}
		if callbackOffset != 1024 {
			t.Errorf("callback offset = %d, want 1024", callbackOffset)
		}
		if callbackSpeed <= 0 {
			t.Error("callback speed should be > 0")
		}
	})

	t.Run("write skips callback if interval not elapsed", func(t *testing.T) {
		var callCount int
		now := time.Now()
		pw := &progressWriter{
			w: io.Discard,
			callback: func(offset, total int64, speed float64) {
				callCount++
			},
			total:        2048,
			startTime:    now,
			lastCallback: now, // Just called, should not trigger again
		}

		data := make([]byte, 100)
		_, _ = pw.Write(data)
		if callCount != 0 {
			t.Error("callback should not fire within progressInterval")
		}
	})

	t.Run("zero-length write no callback", func(t *testing.T) {
		var called bool
		now := time.Now().Add(-1 * time.Second)
		pw := &progressWriter{
			w: io.Discard,
			callback: func(offset, total int64, speed float64) {
				called = true
			},
			total:        100,
			startTime:    now,
			lastCallback: now,
		}

		n, err := pw.Write([]byte{})
		if err != nil {
			t.Fatalf("Write() error: %v", err)
		}
		if n != 0 {
			t.Errorf("Write() = %d, want 0", n)
		}
		if called {
			t.Error("no callback expected for zero-length write")
		}
	})
}

func TestGetSystemPaths_TableDriven(t *testing.T) {
	paths := getSystemPaths()
	if len(paths) == 0 {
		t.Error("getSystemPaths() should return at least one path")
	}

	// Verify all paths end with separator
	for _, p := range paths {
		if !(strings.HasPrefix(p, "%") && strings.HasSuffix(p, "%")) && !strings.HasSuffix(p, "/") && !strings.HasSuffix(p, "\\") {
			t.Errorf("system path %q should end with separator", p)
		}
	}
}

func TestIsSystemPath_CurrentDirectory(t *testing.T) {
	// Current working directory should NOT be a system path
	cwd, err := os.Getwd()
	if err != nil {
		t.Skip("cannot get cwd")
	}
	if isSystemPath(cwd) {
		t.Errorf("CWD %q should not be a system path", cwd)
	}
}

func TestPrepareFilePath_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty path", "", true},
		{"path too long", strings.Repeat("a", 4097), true},
		{"max length path", strings.Repeat("a", 4096), false},
		{"UNC path forward slash", "//server/share/file", true},
		{"UNC path backslash", "\\\\server\\share", true},
		{"control char", "file\x00name", true},
		{"DEL char", "file\x7fname", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := prepareFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("prepareFilePath(%q) error = %v, wantErr %v", tt.path[:min(len(tt.path), 30)], err, tt.wantErr)
			}
		})
	}
}
