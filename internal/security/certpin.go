package security

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
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

// spkiHashPinner pins certificates by their Subject Public Key Info (SPKI) hash.
// This is the most common form of certificate pinning used in HTTP Public Key Pinning (HPKP)
// and similar security mechanisms.
type spkiHashPinner struct {
	hashes map[string]bool // Base64-encoded SHA-256 hashes of SPKI
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
		hashes: make(map[string]bool),
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
type noOpPinner struct{}

// Pin returns "no-op" to indicate no pinning.
func (n *noOpPinner) Pin() string {
	return "no-op"
}

// warnNoOpPinnerOnce ensures the production warning is printed at most once.
var warnNoOpPinnerOnce sync.Once

// VerifyPeerCertificate always returns nil, accepting all certificates.
func (n *noOpPinner) VerifyPeerCertificate(_ [][]byte, _ [][]*x509.Certificate) error {
	warnNoOpPinnerOnce.Do(func() {
		if !strings.Contains(os.Args[0], ".test") {
			fmt.Fprintf(os.Stderr, "[SECURITY WARNING] noOpPinner used outside test environment - certificate pinning is DISABLED\n")
		}
	})
	return nil
}
