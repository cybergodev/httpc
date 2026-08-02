//go:build examples

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/httpc"
)

// User represents a user resource
type User struct {
	ID        int       `json:"id,omitempty"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Status    string    `json:"status,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// APIClient wraps the httpc client for a specific API
type APIClient struct {
	client  httpc.Client
	baseURL string
	token   string
}

// NewAPIClient creates a new API client
func NewAPIClient(baseURL, token string) (*APIClient, error) {
	client, err := httpc.NewDefault()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return &APIClient{
		client:  client,
		baseURL: baseURL,
		token:   token,
	}, nil
}

// Close closes the underlying HTTP client
func (c *APIClient) Close() error {
	return c.client.Close()
}

// GetUser retrieves a user by ID
func (c *APIClient) GetUser(ctx context.Context, userID int) (*User, error) {
	url := fmt.Sprintf("%s/users/%d", c.baseURL, userID)

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := c.client.Get(url,
		httpc.WithContext(timeoutCtx),
		httpc.WithBearerToken(c.token),
		httpc.WithHeader("Accept", "application/json"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode())
	}

	var user User
	if err := resp.Unmarshal(&user); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &user, nil
}

// ListUsers retrieves a list of users with pagination
func (c *APIClient) ListUsers(ctx context.Context, page, limit int) ([]User, error) {
	url := fmt.Sprintf("%s/users", c.baseURL)

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	resp, err := c.client.Get(url,
		httpc.WithContext(timeoutCtx),
		httpc.WithBearerToken(c.token),
		httpc.WithQuery("page", page),
		httpc.WithQuery("limit", limit),
		httpc.WithHeader("Accept", "application/json"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode())
	}

	// Try to parse as array first (real API)
	var users []User
	if err := resp.Unmarshal(&users); err != nil {
		// Echo API returns an object, not an array
		// For demo purposes, return empty array (in real API, this would be an actual user list)
		return []User{}, nil
	}

	return users, nil
}

// CreateUser creates a new user
func (c *APIClient) CreateUser(ctx context.Context, user *User) (*User, error) {
	url := fmt.Sprintf("%s/users", c.baseURL)

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	resp, err := c.client.Post(url,
		httpc.WithContext(timeoutCtx),
		httpc.WithBearerToken(c.token),
		httpc.WithJSON(user),
		httpc.WithMaxRetries(2),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode())
	}

	var createdUser User
	if err := resp.Unmarshal(&createdUser); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &createdUser, nil
}

// UpdateUser updates an existing user
func (c *APIClient) UpdateUser(ctx context.Context, userID int, user *User) (*User, error) {
	url := fmt.Sprintf("%s/users/%d", c.baseURL, userID)

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	resp, err := c.client.Put(url,
		httpc.WithContext(timeoutCtx),
		httpc.WithBearerToken(c.token),
		httpc.WithJSON(user),
		httpc.WithMaxRetries(2),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode())
	}

	var updatedUser User
	if err := resp.Unmarshal(&updatedUser); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &updatedUser, nil
}

// DeleteUser deletes a user by ID
func (c *APIClient) DeleteUser(ctx context.Context, userID int) error {
	url := fmt.Sprintf("%s/users/%d", c.baseURL, userID)

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := c.client.Delete(url,
		httpc.WithContext(timeoutCtx),
		httpc.WithBearerToken(c.token),
		httpc.WithMaxRetries(1),
	)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if !resp.IsSuccess() {
		return fmt.Errorf("API error: status %d", resp.StatusCode())
	}

	return nil
}

// SearchUsers searches for users by query
func (c *APIClient) SearchUsers(ctx context.Context, query string) ([]User, error) {
	url := fmt.Sprintf("%s/users/search", c.baseURL)

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	resp, err := c.client.Get(url,
		httpc.WithContext(timeoutCtx),
		httpc.WithBearerToken(c.token),
		httpc.WithQuery("q", query),
		httpc.WithHeader("Accept", "application/json"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode())
	}

	// Try to parse as array first (real API)
	var users []User
	if err := resp.Unmarshal(&users); err != nil {
		// Echo API returns an object, not an array
		// For demo purposes, return empty array (in real API, this would be search results)
		return []User{}, nil
	}

	return users, nil
}

func main() {
	fmt.Println("=== REST API Client Example ===\n ")

	// Create API client
	// Note: Using echo.hoppscotch.io for demonstration
	// Replace with your actual API endpoint
	client, err := NewAPIClient("https://echo.hoppscotch.io", "your-api-token")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	fmt.Println("This example demonstrates a REST API client pattern.")
	fmt.Println("Note: echo.hoppscotch.io echoes requests, so responses show what was sent.\n ")

	// Example 1: Create a user
	fmt.Println("--- Example 1: Create User (POST) ---")
	newUser := &User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	createdUser, err := client.CreateUser(ctx, newUser)
	if err != nil {
		log.Printf("Error: %v\n", err)
		fmt.Println("(This is expected - echo API returns the request, not a user object)\n ")
	} else {
		fmt.Printf("Response: %+v\n\n", createdUser)
	}

	// Example 2: Get a user
	fmt.Println("--- Example 2: Get User (GET) ---")
	user, err := client.GetUser(ctx, 123)
	if err != nil {
		log.Printf("Error: %v\n", err)
		fmt.Println("(This is expected - echo API returns the request, not a user object)\n ")
	} else {
		fmt.Printf("Response: %+v\n\n", user)
	}

	// Example 3: List users with pagination
	fmt.Println("--- Example 3: List Users with Pagination (GET) ---")
	users, err := client.ListUsers(ctx, 1, 10)
	if err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		if len(users) == 0 {
			fmt.Println("Retrieved 0 users (echo API returns request object, not user array)")
			fmt.Println("In a real API, this would return an array of users\n ")
		} else {
			fmt.Printf("Retrieved %d users\n\n", len(users))
		}
	}

	// Example 4: Update a user
	fmt.Println("--- Example 4: Update User (PUT) ---")
	updateUser := &User{
		Name:   "John Doe Updated",
		Email:  "john.updated@example.com",
		Status: "active",
	}

	updatedUser, err := client.UpdateUser(ctx, 123, updateUser)
	if err != nil {
		log.Printf("Error: %v\n", err)
		fmt.Println("(This is expected - echo API returns the request, not a user object)\n ")
	} else {
		fmt.Printf("Response: %+v\n\n", updatedUser)
	}

	// Example 5: Search users
	fmt.Println("--- Example 5: Search Users (GET with query) ---")
	searchResults, err := client.SearchUsers(ctx, "john")
	if err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		if len(searchResults) == 0 {
			fmt.Println("Found 0 users (echo API returns request object, not search results)")
			fmt.Println("In a real API, this would return matching users\n ")
		} else {
			fmt.Printf("Found %d users\n\n", len(searchResults))
		}
	}

	// Example 6: Delete a user
	fmt.Println("--- Example 6: Delete User (DELETE) ---")
	err = client.DeleteUser(ctx, 123)
	if err != nil {
		log.Printf("Error: %v\n", err)
		fmt.Println("(This is expected - echo API returns the request)\n ")
	} else {
		fmt.Println("User deleted successfully\n ")
	}

	fmt.Println("=== Key Takeaways ===")
	fmt.Println("1. APIClient wraps httpc.Client for a specific API")
	fmt.Println("2. Each method handles a specific endpoint")
	fmt.Println("3. Context is used for timeout and cancellation")
	fmt.Println("4. Errors are wrapped with context for debugging")
	fmt.Println("5. Response parsing is centralized in each method")
	fmt.Println("\n=== Example Completed ===")
}
