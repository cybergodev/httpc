package security

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
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
		// Fail closed (see spkiHashPinner.VerifyPeerCertificate): a pinner
		// without pins must not silently disable pinning.
		return fmt.Errorf("certificate pinning failed: no pins configured")
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
	pinCacheOrd []string          // insertion order for FIFO eviction (cache hits do not refresh position)
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

		// Validate the hash is valid base64 of exactly 32 bytes (SHA-256).
		// A decodable-but-wrong-length value (e.g. a truncated or doubled
		// hash) pins nothing and fails every connection with a confusing
		// "no matching SPKI hash" — reject it at construction instead.
		decoded, err := base64.StdEncoding.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 hash '%s': %w", h, err)
		}
		if len(decoded) != sha256.Size {
			return nil, fmt.Errorf("invalid SPKI hash '%s': decoded %d bytes, want %d (SHA-256)", h, len(decoded), sha256.Size)
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
//
// TRUST MODEL: a pin is only honored on certificates that are bound to the
// connection — never on arbitrary extra certificates the server chose to
// append to its presented chain. A MITM can download the victim's real
// (public) certificate and stuff it into its own chain; scanning all of
// rawCerts would then match the pin while the handshake proceeds with the
// attacker's key ("pin stuffing"). Therefore:
//
//   - verifiedChains != nil (standard verification ran): only certificates
//     appearing in a verified chain are eligible. This keeps legitimate CA /
//     intermediate pinning working — those certs are part of the verified
//     chain — while a stuffed cert that was never verified is not.
//   - verifiedChains == nil (InsecureSkipVerify mode, where pinning is the
//     sole verification gate; see connection.PoolManager): only rawCerts[0],
//     the leaf whose key actually keys the handshake, is eligible. Pinning a
//     CA/intermediate is not supported in that mode.
func (p *spkiHashPinner) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if p == nil || len(p.hashes) == 0 {
		// Fail closed: a pinner with no pins must not silently disable
		// pinning. The constructors reject empty inputs, so this guards
		// against future misuse (zero-value or emptied pinner).
		return fmt.Errorf("certificate pinning failed: no pins configured")
	}

	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificates provided")
	}

	// Restrict the scan to connection-bound certificates (see TRUST MODEL).
	var eligible [][]byte
	if verifiedChains != nil {
		verified := make(map[string]bool, len(verifiedChains)*2)
		for _, chain := range verifiedChains {
			for _, cert := range chain {
				verified[string(cert.Raw)] = true
			}
		}
		// Fresh slice, NOT an in-place filter: rawCerts is owned by crypto/tls
		// (and may be retained by a chained VerifyPeerCertificate callback —
		// see pool.createTLSConfig), so compacting its backing array here
		// would be a caller-visible mutation.
		eligible = make([][]byte, 0, len(rawCerts))
		for _, rawCert := range rawCerts {
			if verified[string(rawCert)] {
				eligible = append(eligible, rawCert)
			}
		}
		if len(eligible) == 0 {
			return fmt.Errorf("certificate pinning failed: none of the presented certificates are part of a verified chain")
		}
	} else {
		eligible = rawCerts[:1] // leaf only — see TRUST MODEL
	}

	// Check each eligible certificate
	for _, rawCert := range eligible {
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

		// Hash the raw SubjectPublicKeyInfo bytes exactly as they appear in
		// the certificate. Re-serializing the parsed key (MarshalPKIXPublicKey)
		// can produce different DER for certificates with non-canonical
		// AlgorithmIdentifier parameters, which would falsely reject pins
		// generated by the documented openssl command.
		hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
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
		// Fail closed: an empty chain accepts NOTHING (matching the public
		// NewCertificatePinnerChain doc), not everything. A nil return here
		// would silently disable pinning for every connection.
		return fmt.Errorf("certificate pinning failed: no pinners configured")
	}

	var errs error
	for _, pinner := range c.pinners {
		err := pinner.VerifyPeerCertificate(rawCerts, verifiedChains)
		if err == nil {
			return nil // Match found
		}
		errs = errors.Join(errs, err)
	}

	if errs != nil {
		return errs
	}
	// Unreachable when len(pinners) > 0 (the loop either returned nil or
	// joined at least one error); kept as a fail-closed default.
	return fmt.Errorf("certificate pinning failed: no pinner matched")
}
