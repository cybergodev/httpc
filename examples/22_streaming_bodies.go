//go:build examples

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates streaming request bodies and large-body downloads.
// Streaming avoids buffering the entire payload in memory — essential for large
// uploads/downloads or when body data is produced incrementally.

func main() {
	fmt.Println("=== Streaming Bodies Examples ===\n ")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// 1. Upload an io.Reader body (no full buffering)
	demonstrateReaderBody(client)

	// 2. Generate-and-upload with io.Pipe (zero-copy streaming)
	demonstratePipeBody(client)

	// 3. Cap an untrusted reader with io.LimitReader (security)
	demonstrateLimitedReader(client)

	// 4. Stream a large response body to disk via Download
	demonstrateStreamDownload(client)

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateReaderBody shows how to POST an io.Reader directly.
// WithBody auto-detects io.Reader and passes it through without setting a
// Content-Type — supply one explicitly if the server expects it.
func demonstrateReaderBody(client httpc.Client) {
	fmt.Println("--- Example 1: io.Reader Body Upload ---")

	// Simulate a large body that we don't want to hold entirely in memory.
	// In practice this could be a file opened with os.Open, a network stream,
	// or any io.Reader.
	largeContent := strings.Repeat("hello world\n", 1000) // ~12 KB
	reader := strings.NewReader(largeContent)

	resp, err := client.Post("https://echo.hoppscotch.io/post",
		httpc.WithBody(reader),
		httpc.WithHeader("Content-Type", "text/plain"),
		httpc.WithTimeout(15*time.Second),
	)
	if err != nil {
		log.Printf("Reader body error: %v\n", err)
		return
	}

	fmt.Printf("✓ Uploaded io.Reader body: Status %d\n", resp.StatusCode())
	fmt.Printf("  Sent %d bytes without buffering the full content\n\n", len(largeContent))
}

// demonstratePipeBody uses io.Pipe to stream data that is generated on the fly.
// The writer goroutine produces chunks while the reader (the HTTP transport)
// consumes them concurrently — the body never exists in full in memory.
func demonstratePipeBody(client httpc.Client) {
	fmt.Println("--- Example 2: io.Pipe Streaming Upload ---")

	pipeReader, pipeWriter := io.Pipe()

	// Producer goroutine: write chunks, then close the writer.
	go func() {
		defer pipeWriter.Close()
		for i := 0; i < 5; i++ {
			chunk := fmt.Sprintf("chunk-%d\n", i)
			_, _ = pipeWriter.Write([]byte(chunk))
		}
	}()

	resp, err := client.Post("https://echo.hoppscotch.io/post",
		httpc.WithBody(pipeReader),
		httpc.WithHeader("Content-Type", "text/plain"),
		httpc.WithTimeout(15*time.Second),
	)
	if err != nil {
		log.Printf("Pipe body error: %v\n", err)
		return
	}

	fmt.Printf("✓ Streamed via io.Pipe: Status %d\n", resp.StatusCode())
	fmt.Println("  Data produced and consumed concurrently — zero intermediate buffering\n ")
}

// demonstrateLimitedReader shows how to protect against unbounded reader sizes.
// WithBody(io.Reader) bypasses request-body-size validation, so wrap untrusted
// sources with io.LimitReader to prevent memory exhaustion.
func demonstrateLimitedReader(client httpc.Client) {
	fmt.Println("--- Example 3: io.LimitReader (Security) ---")

	// Simulate an untrusted reader that could supply more data than expected.
	untrusted := bytes.NewReader([]byte("safe data"))

	// Cap at 10 MB — any excess is silently truncated by the reader.
	const maxUploadSize = 10 << 20 // 10 MB
	limited := io.LimitReader(untrusted, maxUploadSize)

	resp, err := client.Post("https://echo.hoppscotch.io/post",
		httpc.WithBody(limited),
		httpc.WithHeader("Content-Type", "text/plain"),
		httpc.WithTimeout(15*time.Second),
	)
	if err != nil {
		log.Printf("Limited reader error: %v\n", err)
		return
	}

	fmt.Printf("✓ Capped reader upload: Status %d\n", resp.StatusCode())
	fmt.Println("  Always wrap untrusted io.Reader sources with io.LimitReader")
	fmt.Println("  to prevent resource exhaustion (bypasses body-size validation)\n ")
}

// demonstrateStreamDownload shows streaming a large response body to disk.
// WithStreamBody is effective ONLY through Download — regular Get/Post read the
// full body into memory regardless. Download streams directly to the file.
func demonstrateStreamDownload(client httpc.Client) {
	fmt.Println("--- Example 4: Stream Large Body to Disk ---")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := httpc.DefaultDownloadConfig()
	opts.FilePath = "downloads/stream-download.txt"
	opts.Overwrite = true
	opts.ProgressCallback = func(downloaded, total int64, speed float64) {
		if total > 0 {
			fmt.Printf("\r  Progress: %s / %s (%s)",
				httpc.FormatBytes(downloaded),
				httpc.FormatBytes(total),
				httpc.FormatSpeed(speed))
		} else {
			fmt.Printf("\r  Downloaded: %s (%s)",
				httpc.FormatBytes(downloaded),
				httpc.FormatSpeed(speed))
		}
	}

	result, err := client.Download(ctx,
		"https://raw.githubusercontent.com/golang/go/master/CONTRIBUTORS",
		opts,
		httpc.WithTimeout(30*time.Second),
	)
	if err != nil {
		log.Printf("\nStream download error: %v\n", err)
		return
	}

	fmt.Printf("\n✓ Streamed to disk: %s (%s, avg %s)\n",
		result.FilePath,
		httpc.FormatBytes(result.BytesWritten),
		httpc.FormatSpeed(result.AverageSpeed))
	fmt.Println("\n  Download streams the body directly to disk — no full buffering.")
	fmt.Println("  WithStreamBody(true) is applied automatically by Download.")
	fmt.Println("  Regular Get/Post always buffer the full body into memory.")
}
