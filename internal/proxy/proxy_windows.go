//go:build windows

package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// detectPlatform reads proxy settings from Windows registry/system settings
func (d *Detector) detectPlatform() func(*http.Request) (*url.URL, error) {
	proxyServer, proxyEnable, err := getWindowsProxySettings()
	if err != nil {
		return nil
	}

	if !proxyEnable || proxyServer == "" {
		return nil
	}

	// Parse proxy server string
	proxyURL, err := parseWindowsProxyString(proxyServer)
	if err != nil {
		return nil
	}

	return func(_ *http.Request) (*url.URL, error) {
		return proxyURL, nil
	}
}

// getWindowsProxySettings retrieves proxy settings from Windows registry
func getWindowsProxySettings() (proxyServer string, proxyEnable bool, err error) {
	// Try to read from Windows registry using WinAPI
	// Registry path: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings

	var hKey syscall.Handle

	// Open registry key
	keyPath, err := windows.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if err != nil {
		return "", false, err
	}

	if err := syscall.RegOpenKeyEx(
		syscall.HKEY_CURRENT_USER,
		keyPath,
		0,
		syscall.KEY_READ,
		&hKey,
	); err != nil {
		return "", false, fmt.Errorf("failed to open registry key: %w", err)
	}
	defer func() { _ = syscall.RegCloseKey(hKey) }() // best-effort registry key cleanup

	// Read ProxyEnable value
	valueName, _ := windows.UTF16PtrFromString("ProxyEnable") // compile-time constant; cannot fail
	var dataType uint32
	var dataSize uint32

	err = syscall.RegQueryValueEx(
		hKey,
		valueName,
		nil,
		&dataType,
		nil,
		&dataSize,
	)

	if err == nil && dataSize == 4 {
		var enableValue uint32
		err = syscall.RegQueryValueEx(
			hKey,
			valueName,
			nil,
			&dataType,
			(*byte)(unsafe.Pointer(&enableValue)),
			&dataSize,
		)
		if err == nil {
			proxyEnable = enableValue != 0
		}
	}

	if !proxyEnable {
		return "", false, nil
	}

	// Read ProxyServer value
	valueName, _ = windows.UTF16PtrFromString("ProxyServer") // "ProxyServer" is a compile-time constant; cannot fail
	err = syscall.RegQueryValueEx(
		hKey,
		valueName,
		nil,
		&dataType,
		nil,
		&dataSize,
	)

	if err != nil {
		return "", false, nil
	}

	buf := make([]uint16, dataSize/2+1)
	err = syscall.RegQueryValueEx(
		hKey,
		valueName,
		nil,
		&dataType,
		(*byte)(unsafe.Pointer(&buf[0])),
		&dataSize,
	)

	if err == nil {
		proxyServer = windows.UTF16ToString(buf)
	}

	return proxyServer, proxyEnable, nil
}

// parseWindowsProxyString parses Windows proxy server string
// Format can be:
// - "server:port" (single proxy for all protocols)
// - "http=server:port;https=server:port;ftp=server:port" (per-protocol)
func parseWindowsProxyString(proxyStr string) (*url.URL, error) {
	proxyStr = strings.TrimSpace(proxyStr)
	if proxyStr == "" {
		return nil, fmt.Errorf("empty proxy string")
	}

	// Check for per-protocol configuration
	if strings.Contains(proxyStr, "=") {
		// Parse per-protocol settings
		parts := strings.Split(proxyStr, ";")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				protocol := strings.ToLower(strings.TrimSpace(kv[0]))
				server := strings.TrimSpace(kv[1])

				// Prefer HTTPS proxy, fallback to HTTP
				if protocol == "https" || protocol == "http" {
					return url.Parse("http://" + server)
				}
			}
		}
	}

	// Simple server:port format (possibly with an explicit scheme).
	// Normalize the bare "socks" scheme to "socks5": net/http's Transport proxy
	// support recognizes socks5/socks5h but not "socks://", so leaving a value
	// like "socks://host:1080" unchanged would yield a "socks" scheme the
	// transport cannot use (silently ignored or a confusing dial error).
	if after, ok := strings.CutPrefix(proxyStr, "socks://"); ok {
		proxyStr = "socks5://" + after
	}

	if !strings.HasPrefix(proxyStr, "http://") &&
		!strings.HasPrefix(proxyStr, "https://") &&
		!strings.HasPrefix(proxyStr, "socks5://") &&
		!strings.HasPrefix(proxyStr, "socks5h://") {
		proxyStr = "http://" + proxyStr
	}

	return url.Parse(proxyStr)
}
