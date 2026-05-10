# File Download Guide

This guide covers all aspects of downloading files using HTTPC, from simple downloads to advanced features like progress tracking and resume support.

> **Prerequisite**: This guide assumes you understand the [Client Setup and Error Handling patterns](01_getting-started.md#common-patterns) from the Getting Started guide.

## Table of Contents

- [Quick Start](#quick-start)
- [Basic Download](#basic-download)
- [Progress Tracking](#progress-tracking)
- [Large Files](#large-files)
- [Authentication](#authentication)
- [Advanced Options](#advanced-options)
- [Best Practices](#best-practices)

## Quick Start

### Simple Download (Package-Level Function)

The easiest way to download a file - no need to create a client:

```go
package main

import (
    "fmt"
    "log"
    "strings"
    "time"
    "github.com/cybergodev/httpc"
)

func main() {
    // Download a file using package-level function
    result, err := httpc.DownloadFile(
        "https://example.com/file.zip",
        "downloads/file.zip",
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Downloaded %s in %v",
        httpc.FormatBytes(result.BytesWritten),
        result.Duration,
    )
}
```

## Basic Download

### Using Client Instance

For reusable clients or when making multiple requests, create a client instance:

```go
client, err := httpc.New()
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Download file
result, err := client.DownloadFile(
    "https://example.com/document.pdf",
    "downloads/document.pdf",
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("File: %s\n", result.FilePath)
fmt.Printf("Size: %s\n", httpc.FormatBytes(result.BytesWritten))
fmt.Printf("Speed: %s\n", httpc.FormatSpeed(result.AverageSpeed))
```

### With Request Options

Combine download with standard request options:

```go
result, err := client.DownloadFile(
    "https://api.example.com/files/report.pdf",
    "downloads/report.pdf",
    httpc.WithBearerToken("your-token"),
    httpc.WithTimeout(5*time.Minute),
    httpc.WithMaxRetries(3),
)
```

## Progress Tracking

### Real-time Progress

Track download completion:

**Note**: The download uses streaming mode — the response body is written directly to disk via `io.Copy` without buffering the entire response into memory. The progress callback is invoked periodically during download (approximately every 200ms) with current statistics, and once more at completion with final statistics.

```go
opts := httpc.DefaultDownloadConfig()
opts.FilePath = "downloads/large-file.zip"
opts.Overwrite = true

opts.ProgressCallback = func(downloaded, total int64, speed float64) {
    if total > 0 {
        percentage := float64(downloaded) / float64(total) * 100
        fmt.Printf("\r[%.1f%%] %s / %s - %s/s    ",
            percentage,
            httpc.FormatBytes(downloaded),
            httpc.FormatBytes(total),
            httpc.FormatBytes(int64(speed)),
        )
    } else {
        // Total size unknown
        fmt.Printf("\rDownloaded: %s - %s/s    ",
            httpc.FormatBytes(downloaded),
            httpc.FormatBytes(int64(speed)),
        )
    }
}

result, err := client.DownloadWithOptions(url, opts)
fmt.Println() // New line after progress
```

### Progress Bar Example

Create a simple progress bar:

```go
opts.ProgressCallback = func(downloaded, total int64, speed float64) {
    if total > 0 {
        percentage := float64(downloaded) / float64(total)
        barWidth := 50
        filled := int(percentage * float64(barWidth))
        
        bar := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)
        fmt.Printf("\r[%s] %.1f%% - %s/s",
            bar,
            percentage*100,
            httpc.FormatBytes(int64(speed)),
        )
    }
}
```

## Large Files

### Optimized for Large Files

Configure for optimal large file downloads:

```go
opts := httpc.DefaultDownloadConfig()
opts.FilePath = "downloads/large-video.mp4"
opts.Overwrite = true

opts.ProgressCallback = func(downloaded, total int64, speed float64) {
    if total > 0 {
        percentage := float64(downloaded) / float64(total) * 100
        remaining := total - downloaded
        var eta time.Duration
        if speed > 0 {
            eta = time.Duration(float64(remaining)/speed) * time.Second
        }
        
        fmt.Printf("\r%.1f%% - %s/%s - %s/s - ETA: %v    ",
            percentage,
            httpc.FormatBytes(downloaded),
            httpc.FormatBytes(total),
            httpc.FormatBytes(int64(speed)),
            eta.Round(time.Second),
        )
    }
}

result, err := client.DownloadWithOptions(
    url,
    opts,
    httpc.WithTimeout(30*time.Minute),  // Longer timeout
    httpc.WithMaxRetries(5),            // More retries
)
```

## Authentication

### Bearer Token

Download protected files with authentication:

```go
result, err := client.DownloadFile(
    "https://api.example.com/files/private.zip",
    "downloads/private.zip",
    httpc.WithBearerToken("your-api-token"),
)
```

### Basic Auth

```go
result, err := client.DownloadFile(
    "https://secure.example.com/file.zip",
    "downloads/file.zip",
    httpc.WithBasicAuth("username", "password"),
)
```

### Custom Headers

```go
result, err := client.DownloadFile(
    url,
    filePath,
    httpc.WithHeader("X-API-Key", "your-api-key"),
    httpc.WithHeader("X-Client-ID", "client-123"),
)
```

## Advanced Options

### All Download Options

```go
opts := &httpc.DownloadConfig{
    // Required
    FilePath: "downloads/file.zip",

    // File handling
    Overwrite:      true,      // Overwrite existing files
    ResumeDownload: false,     // Resume partial downloads

    // Integrity verification (optional)
    Checksum:         "a1b2c3...",              // Expected hex-encoded checksum
    ChecksumAlgorithm: httpc.ChecksumSHA256,    // Hash algorithm (default: sha256)

    // Progress tracking
    ProgressCallback: func(downloaded, total int64, speed float64) {
        // Your progress handler
    },
}

result, err := client.DownloadWithOptions(url, opts)
```

**Available Options:**
- `FilePath` (string) - Destination file path (required)
- `Overwrite` (bool) - Overwrite existing files (default: false)
- `ResumeDownload` (bool) - Resume partial downloads (default: false)
- `Checksum` (string) - Expected hex-encoded checksum for integrity verification (optional)
- `ChecksumAlgorithm` (ChecksumAlgorithm) - Hash algorithm for verification (default: `httpc.ChecksumSHA256`)
- `ProgressCallback` (func) - Progress tracking callback (optional)

**DownloadResult Fields:**
- `FilePath` (string) - Path where the file was saved
- `BytesWritten` (int64) - Total bytes written to disk
- `Duration` (time.Duration) - Time taken for the download
- `AverageSpeed` (float64) - Average download speed in bytes/second
- `StatusCode` (int) - HTTP status code from the response
- `ContentLength` (int64) - Content-Length from the response header
- `Resumed` (bool) - Whether the download was resumed from a partial file
- `ResponseCookies` ([]*http.Cookie) - Cookies returned by the server
- `ActualChecksum` (string) - Computed checksum of the downloaded file (only set when `Checksum` is provided)

### Save Response to File

Alternative method for small files:

```go
// Make a regular GET request
result, err := client.Get("https://example.com/data.json")
if err != nil {
    log.Fatal(err)
}

// Save response to file
err = result.SaveToFile("data.json")
if err != nil {
    log.Fatal(err)
}
```

### Context-Aware Downloads

For downloads that need cancellation or timeout control at the call site:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()

// Package-level function with context
result, err := httpc.DownloadFileWithContext(ctx, url, filePath)

// Client method with context and custom options
result, err := client.DownloadWithOptionsWithContext(ctx, url, opts)
```

## Implementation Notes

### Current Behavior

The HTTPC download implementation:
- Uses streaming mode (`io.Copy`) to write response body directly to disk — no full-body memory buffering
- Progress callback is invoked periodically during download (~200ms intervals) and once at completion with final statistics
- Supports resume downloads using HTTP Range requests
- Automatically creates parent directories
- Includes security checks to prevent path traversal attacks (UNC path blocking, symlink prevention, control character filtering)

### Memory Considerations

The streaming download implementation is memory-efficient even for large files. For additional control:
- Use resume functionality (`ResumeDownload: true`) to handle interrupted downloads
- Set appropriate timeouts for large files (`httpc.WithTimeout(30*time.Minute)`)
- Use context-aware download functions for cancellation control

## Best Practices

### 1. Always Close the Client

```go
client, err := httpc.New()
if err != nil {
    log.Fatal(err)
}
defer client.Close()  // Important!
```

### 2. Use Appropriate Timeouts

```go
// Small files (< 10MB)
httpc.WithTimeout(1 * time.Minute)

// Medium files (10-100MB)
httpc.WithTimeout(5 * time.Minute)

// Large files (> 100MB)
httpc.WithTimeout(30 * time.Minute)
```

### 3. Enable Resume for Large Files

```go
opts := httpc.DefaultDownloadConfig()
opts.FilePath = filePath
opts.ResumeDownload = true  // Always enable for large files
```

### 4. Handle Errors Gracefully

```go
result, err := client.DownloadFile(url, filePath)
if err != nil {
    // Check if it's a partial download
    if fileInfo, statErr := os.Stat(filePath); statErr == nil {
        log.Printf("Partial download: %s", httpc.FormatBytes(fileInfo.Size()))
        log.Printf("Use ResumeDownload to continue")
    }
    return err
}
```

## Helper Functions

### Format Bytes

```go
size := httpc.FormatBytes(1048576)  // "1.00 MB"
```

### Format Speed

```go
// FormatSpeed expects bytes per second as float64
speed := httpc.FormatSpeed(1048576.0)  // "1.00 MB/s"
```

## Examples

See the [17_file_operations.go](../examples/17_file_operations.go) example for complete working code.


---
