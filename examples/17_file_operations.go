//go:build examples

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates file upload and download operations.
// It uses httpc.FormatBytes / httpc.FormatSpeed (exported by the library)
// instead of reinventing local helpers.

func main() {
	fmt.Println("=== File Operations Examples ===\n ")

	// Create downloads directory
	if err := os.MkdirAll("downloads", 0755); err != nil {
		log.Printf("Warning: Failed to create downloads directory: %v\n", err)
	}

	client, err := httpc.NewDefault()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// File Upload Examples
	demonstrateFileUpload(client)

	// File Download Examples
	demonstrateFileDownload(client)

	// Context-aware download
	demonstrateContextDownload(client)

	// Checksum verification download
	demonstrateChecksumDownload()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateFileUpload shows various file upload patterns
func demonstrateFileUpload(client httpc.Client) {
	fmt.Println("--- File Upload ---")

	// 1. Single file upload
	fileContent := []byte("This is the document content.\nMultiple lines here.")
	resp, err := client.Post("https://echo.hoppscotch.io/upload",
		httpc.WithFile("file", "document.txt", fileContent),
	)
	if err != nil {
		log.Printf("Single file error: %v\n", err)
	} else {
		fmt.Printf("✓ Single file: Status %d (%d bytes)\n", resp.StatusCode(), len(fileContent))
	}

	// 2. Multiple files upload
	formData := &httpc.FormData{
		Fields: map[string]string{},
		Files: map[string]*httpc.FileData{
			"document": {
				Filename: "report.pdf",
				Content:  []byte{0x25, 0x50, 0x44, 0x46}, // PDF header
			},
			"image": {
				Filename: "photo.jpg",
				Content:  []byte{0xFF, 0xD8, 0xFF, 0xE0}, // JPEG header
			},
		},
	}
	resp, err = client.Post("https://echo.hoppscotch.io/upload",
		httpc.WithFormData(formData),
	)
	if err != nil {
		log.Printf("Multiple files error: %v\n", err)
	} else {
		fmt.Printf("✓ Multiple files: Status %d (%d files)\n", resp.StatusCode(), len(formData.Files))
	}

	// 3. File with form fields (metadata)
	formDataWithFields := &httpc.FormData{
		Fields: map[string]string{
			"title":       "My Document",
			"description": "Important document",
			"category":    "reports",
		},
		Files: map[string]*httpc.FileData{
			"file": {
				Filename:    "document.pdf",
				Content:     []byte("Document content"),
				ContentType: "application/pdf",
			},
		},
	}
	resp, err = client.Post("https://echo.hoppscotch.io/upload",
		httpc.WithFormData(formDataWithFields),
		httpc.WithBearerToken("your-token"),
	)
	if err != nil {
		log.Printf("File with fields error: %v\n", err)
	} else {
		fmt.Printf("✓ File with metadata: Status %d\n", resp.StatusCode())
	}

	// 4. Large file with timeout
	largeFile := make([]byte, 10*1024) // 10KB
	for i := range largeFile {
		largeFile[i] = byte(i % 256)
	}
	resp, err = client.Post("https://echo.hoppscotch.io/upload",
		httpc.WithFile("file", "large.bin", largeFile),
		httpc.WithTimeout(60*time.Second),
		httpc.WithMaxRetries(2),
	)
	if err != nil {
		log.Printf("Large file error: %v\n", err)
	} else {
		fmt.Printf("✓ Large file: Status %d (%d bytes, took %v)\n\n",
			resp.StatusCode(), len(largeFile), resp.Meta.Duration)
	}
}

// demonstrateFileDownload shows various file download patterns
func demonstrateFileDownload(client httpc.Client) {
	fmt.Println("--- File Download ---")

	// 1. Simple download (DefaultDownloadConfig is the documented starting point)
	simpleOpts := httpc.DefaultDownloadConfig()
	simpleOpts.FilePath = "downloads/golang-readme.md"
	simpleOpts.Overwrite = true
	result, err := client.Download(context.Background(),
		"https://raw.githubusercontent.com/golang/go/master/README.md",
		simpleOpts,
	)
	if err != nil {
		log.Printf("Simple download error: %v\n", err)
	} else {
		fmt.Printf("✓ Simple download: %s (%s, %v)\n",
			result.FilePath,
			httpc.FormatBytes(result.BytesWritten),
			result.Duration)
	}

	// 2. Download with progress tracking
	opts := httpc.DefaultDownloadConfig()
	opts.FilePath = "downloads/sample-file.bin"
	opts.Overwrite = true
	opts.ProgressCallback = func(downloaded, total int64, speed float64) {
		if total > 0 {
			percentage := float64(downloaded) / float64(total) * 100
			fmt.Printf("\r  Progress: %.1f%% (%s / %s) - %s",
				percentage,
				httpc.FormatBytes(downloaded),
				httpc.FormatBytes(total),
				httpc.FormatSpeed(speed))
		}
	}

	result, err = client.Download(context.Background(),
		"https://raw.githubusercontent.com/golang/go/master/LICENSE",
		opts,
		httpc.WithTimeout(60*time.Second),
	)
	if err != nil {
		log.Printf("\nProgress download error: %v\n", err)
	} else {
		fmt.Printf("\n✓ Progress download: %s (%s, avg %s)\n",
			result.FilePath,
			httpc.FormatBytes(result.BytesWritten),
			httpc.FormatSpeed(result.AverageSpeed))
	}

	// 3. Download with authentication
	authOpts := httpc.DefaultDownloadConfig()
	authOpts.FilePath = "downloads/authenticated-file.txt"
	authOpts.Overwrite = true
	result, err = client.Download(context.Background(),
		"https://httpbin.org/get",
		authOpts,
		httpc.WithBearerToken("your-api-token"),
		httpc.WithHeader("X-Custom", "value"),
	)
	if err != nil {
		log.Printf("Auth download error: %v\n", err)
	} else {
		fmt.Printf("✓ Authenticated download: %s (%s)\n",
			result.FilePath,
			httpc.FormatBytes(result.BytesWritten))
	}

	// 4. Save response to file (alternative method)
	resp, err := client.Get("https://raw.githubusercontent.com/golang/go/master/LICENSE")
	if err != nil {
		log.Printf("Response fetch error: %v\n", err)
	} else {
		filePath := "downloads/license.txt"
		if err := resp.SaveToFile(filePath); err != nil {
			log.Printf("Save error: %v\n", err)
		} else {
			fmt.Printf("✓ SaveToFile: %s (%s)\n",
				filePath,
				httpc.FormatBytes(int64(len(resp.RawBody()))))
		}
	}

	// 5. Resume interrupted download (demonstration)
	resumeOpts := httpc.DefaultDownloadConfig()
	resumeOpts.FilePath = "downloads/resume-test.bin"
	resumeOpts.ResumeDownload = true
	result, err = client.Download(context.Background(),
		"https://raw.githubusercontent.com/golang/go/master/README.md",
		resumeOpts,
		httpc.WithTimeout(5*time.Minute),
	)
	if err != nil {
		log.Printf("Resume download error: %v\n", err)
	} else {
		if result.Resumed {
			fmt.Printf("✓ Resumed download: %s (resumed from partial)\n", result.FilePath)
		} else {
			fmt.Printf("✓ Complete download: %s (no resume needed)\n", result.FilePath)
		}
	}
}

// demonstrateContextDownload shows context-aware download with cancellation
func demonstrateContextDownload(client httpc.Client) {
	fmt.Println("--- Context-Aware Download ---")

	// Download with a context that has a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := httpc.DefaultDownloadConfig()
	opts.FilePath = "downloads/context-download.txt"
	opts.Overwrite = true

	result, err := client.Download(ctx,
		"https://httpbin.org/get",
		opts,
		httpc.WithBearerToken("test-token"),
	)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("Download timed out: %v\n", err)
		} else {
			log.Printf("Download error: %v\n", err)
		}
		return
	}

	fmt.Printf("✓ Downloaded: %s (%s)\n",
		result.FilePath,
		httpc.FormatBytes(result.BytesWritten))
	fmt.Println("\nPass a context to Download for:")
	fmt.Println("  - Download timeouts independent of client config")
	fmt.Println("  - User-initiated cancellation")
	fmt.Println("  - Graceful shutdown in services")
}

// demonstrateChecksumDownload shows download with integrity verification
func demonstrateChecksumDownload() {
	fmt.Println("--- Download with Checksum Verification ---")

	ctx := context.Background()
	url := "https://raw.githubusercontent.com/golang/go/master/LICENSE"

	// Step 1: Download the file once (no verification).
	firstOpts := httpc.DefaultDownloadConfig()
	firstOpts.FilePath = "downloads/go-license.txt"
	first, err := httpc.Download(ctx, url, firstOpts,
		httpc.WithTimeout(30*time.Second),
	)
	if err != nil {
		log.Printf("Download error: %v\n", err)
		return
	}
	fmt.Printf("Downloaded: %s (%s)\n", first.FilePath, httpc.FormatBytes(first.BytesWritten))

	// Step 2: Compute the expected SHA-256 from the downloaded bytes.
	// In production you would obtain this checksum from a trusted source
	// (release manifest, vendor page) rather than computing it yourself.
	expected, err := sha256OfFile(first.FilePath)
	if err != nil {
		log.Printf("Checksum error: %v\n", err)
		return
	}

	// Step 3: Re-download with checksum verification enabled. When Checksum is
	// set, the body is hashed while streaming to disk and compared after
	// completion; a mismatch removes the downloaded file and returns an error.
	verifyOpts := httpc.DefaultDownloadConfig()
	verifyOpts.FilePath = "downloads/go-license-verified.txt"
	verifyOpts.Overwrite = true
	verifyOpts.Checksum = expected
	verifyOpts.ChecksumAlgorithm = httpc.ChecksumSHA256
	verified, err := httpc.Download(ctx, url, verifyOpts, httpc.WithTimeout(30*time.Second))
	if err != nil {
		log.Printf("Checksum verification failed: %v\n", err)
		return
	}

	fmt.Printf("✓ Verified: %s (checksum %s)\n", verified.FilePath, verified.ActualChecksum)
	fmt.Println("\nChecksum verification:")
	fmt.Println("  - Checksum = expected SHA-256 hex (from a trusted source)")
	fmt.Println("  - A mismatch removes the downloaded file and returns an error")
	fmt.Println("  - ActualChecksum holds the hash computed during a verified download")
}

// sha256OfFile reads a file and returns its lowercase hex SHA-256 (local helper).
func sha256OfFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
