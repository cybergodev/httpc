package security

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// CertificatePinner defines the interface for certificate pinning implementations.
// Certificate pinning protects against MITM attacks by verifying that the server's
// certificate matches a known, expected certificate or public key.
type CertificatePinner interface {
	// Pin returns a string representation of the pin for logging/debugging
	Pin() string

	// VerifyPeerCertificate verifies the peer certificate chain against the pin.
	// rawCerts contains the ASN.1 DER-encoded certificates.
	// verifiedChains contains the verified certificate chains (may be nil if verification was skipped).
	VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

// NewSPKIHashPinner creates a CertificatePinner from one or more base64-encoded
// SHA-256 hashes of DER-encoded SubjectPublicKeyInfo (SPKI). This is the standard
// HPKP pin format. Exported for use by the public httpc package.
func NewSPKIHashPinner(hashes ...string) (CertificatePinner, error) {
	return newSPKIHashPinner(hashes...)
}

// NewPublicKeyPinner creates a CertificatePinner from one or more DER-encoded
// PKIX public keys (as returned by x509.MarshalPKIXPublicKey). Exported for use
// by the public httpc package.
func NewPublicKeyPinner(publicKeys ...[]byte) (CertificatePinner, error) {
	return newPublicKeyPinner(publicKeys...)
}

// NewCertificatePinnerChain combines multiple pinners; the certificate is
// accepted if ANY pinner accepts it. This enables key rotation by pinning both
// the current and next keys. Exported for use by the public httpc package.
func NewCertificatePinnerChain(pinners ...CertificatePinner) CertificatePinner {
	return newCertificatePinnerChain(pinners...)
}

// publicKeyPinner pins one or more public keys by their SHA-256 hash.
// The peer certificate's public key must match one of the pinned keys.
// Internally delegates to spkiHashPinner for verification.
type publicKeyPinner struct {
	inner *spkiHashPinner
}

// newPublicKeyPinner creates a new pinner from raw public keys.
// Each public key should be in DER-encoded PKIX format (as used in x509 certificates).
// Returns an error if no valid keys are provided.
func newPublicKeyPinner(publicKeys ...[]byte) (*publicKeyPinner, error) {
	hashes := make([]string, 0, len(publicKeys))
	for _, pk := range publicKeys {
		if len(pk) > 0 {
			hash := sha256.Sum256(pk)
			hashes = append(hashes, base64.StdEncoding.EncodeToString(hash[:]))
		}
	}
	inner, err := newSPKIHashPinner(hashes...)
	if err != nil {
		return nil, fmt.Errorf("no valid public keys provided: %w", err)
	}
	return &publicKeyPinner{inner: inner}, nil
}

// newPublicKeyPinnerFromBase64 creates a new pinner from base64-encoded public key hashes.
// Each hash should be the SHA-256 hash of the DER-encoded public key, base64-encoded.
// Returns an error if no valid hashes are provided.
func newPublicKeyPinnerFromBase64(hashes ...string) (*publicKeyPinner, error) {
	inner, err := newSPKIHashPinner(hashes...)
	if err != nil {
		return nil, fmt.Errorf("no valid SPKI hashes provided: %w", err)
	}
	return &publicKeyPinner{inner: inner}, nil
}

// Pin returns a description of the pinned public keys.
func (p *publicKeyPinner) Pin() string {
	if p == nil || p.inner == nil {
		return "no-pins"
	}
	return fmt.Sprintf("public-key-pins:%d", len(p.inner.hashes))
}

// VerifyPeerCertificate verifies that one of the peer certificates matches a pinned public key.
func (p *publicKeyPinner) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if p == nil || p.inner == nil {
		return nil
	}
	return p.inner.VerifyPeerCertificate(rawCerts, verifiedChains)
}

// pinCacheMaxSize limits the certificate fingerprint cache to prevent
// unbounded memory growth in clients connecting to many unique hosts.
const pinCacheMaxSize = 1024

// spkiHashPinner pins certificates by their Subject Public Key Info (SPKI) hash.
// This is the most common form of certificate pinning used in HTTP Public Key Pinning (HPKP)
// and similar security mechanisms.
type spkiHashPinner struct {
	hashes      map[string]bool // Base64-encoded SHA-256 hashes of SPKI
	mu          sync.RWMutex
	pinCache    map[string]string // fingerprint -> base64(SPKI hash)
	pinCacheOrd []string          // insertion order for LRU eviction
}

// newSPKIHashPinner creates a new SPKI pinner from base64-encoded SHA-256 hashes.
// Each hash should be the base64-encoded SHA-256 hash of the DER-encoded SPKI.
//
// Example hashes:
//   - Google: "7HIpactkIAq2Y49orFOOQKurWxmmSVSJcOooMBf4tTM="
//   - Let's Encrypt: "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2fuihg="
//
// You can generate these hashes using:
//
//	openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
func newSPKIHashPinner(hashes ...string) (*spkiHashPinner, error) {
	p := &spkiHashPinner{
		hashes:      make(map[string]bool),
		pinCache:    make(map[string]string, 4),
		pinCacheOrd: make([]string, 0, 16),
	}

	for _, h := range hashes {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}

		// Validate the hash is valid base64
		if _, err := base64.StdEncoding.DecodeString(h); err != nil {
			return nil, fmt.Errorf("invalid base64 hash '%s': %w", h, err)
		}

		p.hashes[h] = true
	}

	if len(p.hashes) == 0 {
		return nil, fmt.Errorf("at least one valid SPKI hash is required")
	}

	return p, nil
}

// Pin returns a description of the pinned SPKI hashes.
func (p *spkiHashPinner) Pin() string {
	if p == nil || len(p.hashes) == 0 {
		return "no-pins"
	}
	return fmt.Sprintf("spki-pins:%d", len(p.hashes))
}

// VerifyPeerCertificate verifies that one of the peer certificates matches a pinned SPKI hash.
func (p *spkiHashPinner) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if p == nil || len(p.hashes) == 0 {
		return nil // No pins configured
	}

	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificates provided")
	}

	// Check each certificate in the chain
	for _, rawCert := range rawCerts {
		// Compute a fingerprint of the raw DER for cache lookup.
		// Use the full 32-byte SHA-256 digest: a truncated key (e.g. 8 bytes / 64
		// bits) risks collisions under a large or attacker-influenced cert set, in
		// which case a cache hit could return a *different* cert's SPKI hash and,
		// if that hash happens to be pinned, accept the wrong certificate.
		fp := sha256.Sum256(rawCert)
		fpKey := string(fp[:])

		// Check cache first to avoid expensive x509.ParseCertificate
		p.mu.RLock()
		cached, hit := p.pinCache[fpKey]
		p.mu.RUnlock()

		if hit {
			if p.hashes[cached] {
				return nil // Match found (cached)
			}
			continue // Not a match, try next cert
		}

		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			continue // Skip invalid certificates
		}

		// Get the SPKI bytes
		spkiBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			continue // Skip certificates with unsupported key types
		}

		// Hash the SPKI
		hash := sha256.Sum256(spkiBytes)
		hashStr := base64.StdEncoding.EncodeToString(hash[:])

		// Cache the computed hash for future lookups
		p.mu.Lock()
		if _, exists := p.pinCache[fpKey]; !exists {
			// Evict oldest entries when cache exceeds limit
			if len(p.pinCache) >= pinCacheMaxSize && len(p.pinCacheOrd) > 0 {
				evictCount := pinCacheMaxSize / 4
				for i := 0; i < evictCount && i < len(p.pinCacheOrd); i++ {
					delete(p.pinCache, p.pinCacheOrd[i])
				}
				remaining := p.pinCacheOrd[evictCount:]
				p.pinCacheOrd = make([]string, len(remaining), len(remaining)*2)
				copy(p.pinCacheOrd, remaining)
			}
			p.pinCache[fpKey] = hashStr
			p.pinCacheOrd = append(p.pinCacheOrd, fpKey)
		}
		p.mu.Unlock()

		// Check if it matches any pinned hash
		if p.hashes[hashStr] {
			return nil // Match found
		}
	}

	return fmt.Errorf("certificate pinning failed: no matching SPKI hash found")
}

// certificatePinnerChain combines multiple pinners.
// A certificate is considered valid if ANY of the pinners accepts it.
type certificatePinnerChain struct {
	pinners []CertificatePinner
}

// newCertificatePinnerChain creates a new chain of pinners.
// A certificate is valid if ANY pinner accepts it.
func newCertificatePinnerChain(pinners ...CertificatePinner) *certificatePinnerChain {
	return &certificatePinnerChain{pinners: pinners}
}

// Pin returns a description of all pinners in the chain.
func (c *certificatePinnerChain) Pin() string {
	if c == nil || len(c.pinners) == 0 {
		return "no-pins"
	}

	pins := make([]string, 0, len(c.pinners))
	for _, p := range c.pinners {
		pins = append(pins, p.Pin())
	}
	return fmt.Sprintf("chain:[%s]", strings.Join(pins, ","))
}

// VerifyPeerCertificate verifies the certificate against all pinners.
// Returns nil if ANY pinner accepts the certificate.
func (c *certificatePinnerChain) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c == nil || len(c.pinners) == 0 {
		return nil // No pinners means no pinning
	}

	var lastErr error
	for _, pinner := range c.pinners {
		err := pinner.VerifyPeerCertificate(rawCerts, verifiedChains)
		if err == nil {
			return nil // Match found
		}
		lastErr = err
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("certificate pinning failed: no pinner matched")
}

// noOpPinner accepts all certificates. For testing only.
// In production environments, VerifyPeerCertificate returns an error to prevent
// accidental use of this no-op pinner, which disables certificate pinning entirely.
type noOpPinner struct{}

// Pin returns "no-op" to indicate no pinning.
func (n *noOpPinner) Pin() string {
	return "no-op"
}

// VerifyPeerCertificate returns nil in test environments. In all other
// environments, it returns an error to prevent accidental use in production,
// as this pinner disables certificate verification.
func (n *noOpPinner) VerifyPeerCertificate(_ [][]byte, _ [][]*x509.Certificate) error {
	if !isTestEnvironment() {
		return fmt.Errorf("SECURITY: noOpPinner used outside test environment - certificate pinning is DISABLED; this is a security violation")
	}
	return nil
}

// isTestEnvironment detects if the code is running in a test environment.
// Consistent with the detection logic in the httpc package.
//
// SECURITY: Detection is based ONLY on the compiled test-binary name. We
// deliberately do NOT honor GO_TEST / GOTEST environment variables: any
// operator (or attacker controlling the process environment) could otherwise
// flip them and silently disable certificate pinning via noOpPinner.
func isTestEnvironment() bool {
	executable := filepath.Base(os.Args[0])
	if strings.HasSuffix(executable, ".test") ||
		strings.HasSuffix(executable, ".test.exe") ||
		strings.Contains(executable, ".test.") {
		return true
	}
	return false
}
