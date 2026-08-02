//go:build examples

package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates SSRF (Server-Side Request Forgery) protection.
// By default the client blocks connections to private/reserved addresses
// (loopback, RFC1918, link-local, etc.) before any socket is opened. The three
// escape hatches shown here each relax that protection in a different scope.
//
// Targets are loopback/private addresses where nothing is listening, so the
// requests fail WITHOUT needing a local server:
//
//   - 127.0.0.1:9 — loopback; the discard port is essentially never open.
//   - 10.0.0.1:9  — a classic VPC internal address (RFC1918).
//
// What matters is WHERE the request fails: a default SSRF block is rejected
// instantly (before dial); once an override/exemption applies, the request
// reaches the connection phase and fails to connect (connection refused /
// timeout) — a visibly different outcome.

func main() {
	fmt.Println("=== SSRF Protection Examples ===\n ")

	// 1. Default behavior: private/loopback addresses are blocked
	demonstrateDefaultBlock()

	// 2. Per-request override: WithAllowPrivateIPs lets one call through
	demonstratePerRequestOverride()

	// 3. Selective allowlist: exempt a single CIDR range
	demonstrateExemptCIDRs()

	// 4. Whole-client bypass: allow all private IPs
	demonstrateAllowAllPrivate()

	fmt.Println("\n=== All Examples Completed ===")
}

// report interprets a request outcome, surfacing the structured error so the
// difference between an SSRF block and a connection failure is visible.
func report(err error) {
	if err == nil {
		fmt.Println("  ✓ Request succeeded")
		return
	}
	var clientErr *httpc.ClientError
	if errors.As(err, &clientErr) {
		fmt.Printf("  → %s: %s\n", clientErr.Code(), clientErr.Message)
	} else {
		fmt.Printf("  → request failed: %v\n", err)
	}
}

// demonstrateDefaultBlock shows the default client rejecting a loopback target.
// No connection is attempted — the block fires during host validation.
func demonstrateDefaultBlock() {
	fmt.Println("--- Example 1: Default Block (SSRF protection ON) ---")
	fmt.Println("  target: http://127.0.0.1:9/  (loopback, nothing listening)")

	// DefaultConfig() ships with AllowPrivateIPs=false, so 127.0.0.1 is blocked.
	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	_, err = client.Get("http://127.0.0.1:9/")
	report(err)
	fmt.Printf("  (Rejected before dial — SSRF protection working as designed.)\n\n")
}

// demonstratePerRequestOverride uses WithAllowPrivateIPs to let a single call
// reach a private address, without relaxing the client's global policy. The
// request passes the SSRF check, then fails to CONNECT (nothing on :9).
func demonstratePerRequestOverride() {
	fmt.Println("--- Example 2: Per-Request Override (WithAllowPrivateIPs) ---")
	fmt.Println("  target: http://127.0.0.1:9/  + WithAllowPrivateIPs(true)")

	client, err := httpc.NewDefault()
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	// The override applies to this one request only; other requests on the same
	// client keep the default SSRF protection. A short timeout bounds the dial
	// since the host/port is unreachable.
	_, err = client.Get(
		"http://127.0.0.1:9/",
		httpc.WithAllowPrivateIPs(true),
		httpc.WithTimeout(5*time.Second),
	)
	report(err)
	fmt.Printf("  (Passed the SSRF check, then failed at the connection phase.)\n\n")
}

// demonstrateExemptCIDRs allowlists a single CIDR range. Unlike the broad
// override, this grants access only to addresses inside the exempted network —
// the preferred way to reach internal/VPC/VPN services.
//
// NOTE: loopback (127.x) is matched by an earlier hostname check that runs
// before CIDR exemptions are consulted, so to demonstrate the exemption
// actually working we target 10.0.0.1 and exempt 10.0.0.0/8.
func demonstrateExemptCIDRs() {
	fmt.Println("--- Example 3: Selective Allowlist (SSRFExemptCIDRs) ---")
	fmt.Println("  target: http://10.0.0.1:9/  + exempt CIDR 10.0.0.0/8")

	cfg := httpc.DefaultConfig()
	cfg.Security.SSRFExemptCIDRs = []string{"10.0.0.0/8"} // VPC / internal range

	client, err := httpc.New(cfg)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	_, err = client.Get(
		"http://10.0.0.1:9/",
		httpc.WithTimeout(5*time.Second),
	)
	report(err)
	fmt.Println("  (10.0.0.1 is private but exempted; reached the connection phase.)")
	fmt.Printf("  Other private ranges (192.168.x, 172.16.x, 127.x) stay blocked.\n\n")
}

// demonstrateAllowAllPrivate disables SSRF protection for the entire client.
// This is the broadest escape hatch — appropriate only for clients that talk
// exclusively to trusted internal services, never to user-supplied URLs.
func demonstrateAllowAllPrivate() {
	fmt.Println("--- Example 4: Whole-Client Bypass (AllowPrivateIPs) ---")
	fmt.Println("  target: http://127.0.0.1:9/  + Security.AllowPrivateIPs=true")

	cfg := httpc.DefaultConfig()
	cfg.Security.AllowPrivateIPs = true // bypasses ALL SSRF validation

	client, err := httpc.New(cfg)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	_, err = client.Get(
		"http://127.0.0.1:9/",
		httpc.WithTimeout(5*time.Second),
	)
	report(err)
	fmt.Println("  (All private IPs allowed for this client; prefer SSRFExemptCIDRs")
	fmt.Println("   unless every request targets trusted internal hosts.)")
}
