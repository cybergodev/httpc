//go:build examples

package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cybergodev/httpc"
)

func main() {
	fmt.Println("=== Concurrent Requests Examples ===\n ")

	// Example 1: Parallel requests
	demonstrateParallelRequests()

	// Example 2: Worker pool pattern
	demonstrateWorkerPool()

	// Example 3: Concurrent with error handling
	demonstrateConcurrentWithErrors()

	// Example 4: Rate-limited concurrent requests
	demonstrateRateLimited()

	fmt.Println("\n=== All Examples Completed ===")
}

// demonstrateParallelRequests shows basic parallel requests
func demonstrateParallelRequests() {
	fmt.Println("--- Example 1: Parallel Requests ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	urls := []string{
		"https://echo.hoppscotch.io/api/users",
		"https://echo.hoppscotch.io/api/posts",
		"https://echo.hoppscotch.io/api/comments",
	}

	type result struct {
		url      string
		status   int
		duration time.Duration
		err      error
	}

	results := make(chan result, len(urls))
	var wg sync.WaitGroup

	start := time.Now()

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()

			reqStart := time.Now()
			resp, err := client.Get(u)
			duration := time.Since(reqStart)

			if err != nil {
				results <- result{url: u, err: err, duration: duration}
				return
			}

			results <- result{
				url:      u,
				status:   resp.StatusCode(),
				duration: duration,
			}
		}(url)
	}

	wg.Wait()
	close(results)

	totalDuration := time.Since(start)

	fmt.Println("Results:")
	for r := range results {
		if r.err != nil {
			fmt.Printf("  %s - Error: %v\n", r.url, r.err)
		} else {
			fmt.Printf("  %s - Status: %d, Duration: %v\n", r.url, r.status, r.duration)
		}
	}
	fmt.Printf("Total time: %v (parallel execution)\n\n", totalDuration)
}

// demonstrateWorkerPool shows worker pool pattern
func demonstrateWorkerPool() {
	fmt.Println("--- Example 2: Worker Pool Pattern ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	const numWorkers = 5
	urls := make([]string, 20)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://echo.hoppscotch.io/api/item/%d", i+1)
	}

	jobs := make(chan string, len(urls))
	statusCh := make(chan int, len(urls))
	errCh := make(chan error, len(urls))

	// Start workers
	var wg sync.WaitGroup
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for url := range jobs {
				resp, err := client.Get(url)
				if err != nil {
					errCh <- err
					continue
				}
				statusCh <- resp.StatusCode()
			}
		}(w)
	}

	// Send jobs
	start := time.Now()
	for _, url := range urls {
		jobs <- url
	}
	close(jobs)

	// Wait for completion
	wg.Wait()
	close(statusCh)
	close(errCh)

	// Collect results
	successCount := 0
	for status := range statusCh {
		if status >= 200 && status < 300 {
			successCount++
		}
	}
	errorCount := len(errCh)

	fmt.Printf("Processed %d URLs with %d workers\n", len(urls), numWorkers)
	fmt.Printf("Successful: %d, Errors: %d, Total: %d\n", successCount, errorCount, len(urls))
	fmt.Printf("Duration: %v\n\n", time.Since(start))
}

// demonstrateConcurrentWithErrors shows error handling in concurrent requests
func demonstrateConcurrentWithErrors() {
	fmt.Println("--- Example 3: Concurrent with Error Handling ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	type task struct {
		id  int
		url string
	}

	type taskResult struct {
		id       int
		url      string
		status   int
		duration time.Duration
		err      error
	}

	tasks := []task{
		{1, "https://httpbin.org/status/200"},
		{2, "https://httpbin.org/status/404"},
		{3, "https://httpbin.org/status/500"},
		{4, "https://httpbin.org/delay/1"},
	}

	results := make(chan taskResult, len(tasks))
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, t := range tasks {
		wg.Add(1)
		go func(task task) {
			defer wg.Done()

			start := time.Now()
			resp, err := client.Get(task.url,
				httpc.WithContext(ctx),
				httpc.WithTimeout(5*time.Second),
			)
			duration := time.Since(start)

			if err != nil {
				results <- taskResult{
					id:       task.id,
					url:      task.url,
					err:      err,
					duration: duration,
				}
				return
			}

			results <- taskResult{
				id:       task.id,
				url:      task.url,
				status:   resp.StatusCode(),
				duration: duration,
			}
		}(t)
	}

	wg.Wait()
	close(results)

	successCount := 0
	fmt.Println("Task Results:")
	for r := range results {
		if r.err != nil {
			fmt.Printf("  Task %d: Error - %v (took %v)\n", r.id, r.err, r.duration)
		} else if r.status >= 200 && r.status < 300 {
			fmt.Printf("  Task %d: Success - Status %d (took %v)\n", r.id, r.status, r.duration)
			successCount++
		} else {
			fmt.Printf("  Task %d: HTTP Error - Status %d (took %v)\n", r.id, r.status, r.duration)
		}
	}
	fmt.Printf("Summary: %d/%d successful\n\n", successCount, len(tasks))
}

// demonstrateRateLimited shows rate-limited concurrent requests
func demonstrateRateLimited() {
	fmt.Println("--- Example 4: Rate-Limited Concurrent Requests ---")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	const (
		maxConcurrent = 3
		requestsCount = 10
	)

	// Semaphore to limit concurrency
	sem := make(chan struct{}, maxConcurrent)
	results := make(chan int, requestsCount)
	var wg sync.WaitGroup

	start := time.Now()

	for i := 1; i <= requestsCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			url := fmt.Sprintf("https://echo.hoppscotch.io/api/request/%d", id)
			resp, err := client.Get(url)
			if err != nil {
				log.Printf("Request %d error: %v\n", id, err)
				return
			}

			results <- resp.StatusCode()
			fmt.Printf("  Request %d completed (Status: %d)\n", id, resp.StatusCode())
		}(i)
	}

	wg.Wait()
	close(results)

	successCount := 0
	for status := range results {
		if status >= 200 && status < 300 {
			successCount++
		}
	}

	fmt.Printf("\nCompleted %d requests with max %d concurrent\n", requestsCount, maxConcurrent)
	fmt.Printf("Successful: %d/%d\n", successCount, requestsCount)
	fmt.Printf("Total duration: %v\n\n", time.Since(start))
}
