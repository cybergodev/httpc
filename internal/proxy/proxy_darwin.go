//go:build darwin

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// detectPlatform reads proxy settings from macOS system configuration
// using the networksetup command-line tool
func (d *Detector) detectPlatform() func(*http.Request) (*url.URL, error) {
	// Try to get HTTP proxy first, then HTTPS
	proxyURL := d.getMacOSProxy("getwebproxy")
	if proxyURL == nil {
		proxyURL = d.getMacOSProxy("getsecurewebproxy")
	}

	if proxyURL == nil {
		return nil
	}

	return func(req *http.Request) (*url.URL, error) {
		// Loopback targets bypass the system proxy, matching net/http and the
		// environment path (isLoopbackRequest). networksetup bypass domains
		// are not parsed yet.
		if isLoopbackRequest(req) {
			return nil, nil
		}
		return proxyURL, nil
	}
}

// getMacOSProxy retrieves proxy settings using networksetup command
// toolType can be "getwebproxy" (HTTP) or "getsecurewebproxy" (HTTPS)
func (d *Detector) getMacOSProxy(toolType string) *url.URL {
	// First, get the primary network service
	service := d.getPrimaryNetworkService()
	if service == "" {
		return nil
	}

	// Run networksetup command to get proxy settings. Bounded by a timeout:
	// this runs while holding the Detector write lock on the client-construction
	// path, so a wedged networksetup would otherwise block NewClient forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "networksetup", "-"+toolType, service)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil
	}

	// Parse output
	// Format:
	// Enabled: Yes/No
	// Server: hostname
	// Port: port
	// Authenticated Proxy Enabled: 0/1
	// ...
	output := stdout.String()
	return d.parseNetworkSetupOutput(output)
}

// getPrimaryNetworkService returns the primary network service name
func (d *Detector) getPrimaryNetworkService() string {
	// Get list of network services. Bounded by a timeout — see getMacOSProxy.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "networksetup", "-listallnetworkservices")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		// Fallback: try common service names
		return ""
	}

	lines := strings.Split(stdout.String(), "\n")
	if len(lines) < 2 {
		return ""
	}

	// First line is a header, skip it
	// Look for common network services in order of preference
	preferredServices := []string{
		"Wi-Fi",
		"Ethernet",
		"USB 10/100/1000 LAN",
		"Thunderbolt Ethernet",
		"Bluetooth PAN",
	}

	availableServices := lines[1:]

	// Find first preferred service that exists
	for _, preferred := range preferredServices {
		for _, available := range availableServices {
			available = strings.TrimSpace(available)
			if available == "" || strings.Contains(available, "*") {
				continue // Skip disabled services (marked with *)
			}
			if strings.EqualFold(available, preferred) {
				return available
			}
		}
	}

	// If no preferred service found, use first available one
	for _, available := range availableServices {
		available = strings.TrimSpace(available)
		if available != "" && !strings.Contains(available, "*") {
			return available
		}
	}

	return ""
}

// parseNetworkSetupOutput parses networksetup command output
func (d *Detector) parseNetworkSetupOutput(output string) *url.URL {
	lines := strings.Split(output, "\n")

	var enabled bool
	var server string
	var port int

	for _, line := range lines {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch strings.ToLower(key) {
		case "enabled":
			enabled = strings.EqualFold(value, "yes") || value == "1"
		case "server":
			server = value
		case "port":
			if p, err := strconv.Atoi(value); err == nil {
				port = p
			}
		}
	}

	if !enabled || server == "" || port == 0 {
		return nil
	}

	// Construct proxy URL
	proxyStr := fmt.Sprintf("http://%s:%d", server, port)
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return nil
	}

	return proxyURL
}
