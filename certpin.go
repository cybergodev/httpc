package httpc

import (
	"github.com/cybergodev/httpc/internal/security"
)

// CertificatePinner verifies that a server's certificate matches a known,
// expected certificate or public key. This is certificate pinning: it defends
// against man-in-the-middle attacks even if a trusted Certificate Authority is
// compromised, because the handshake is rejected unless the peer presents a
// pinned key.
//
// This is a type alias for the internal security.CertificatePinner interface.
// Construct a pinner with NewSPKIHashPinner, NewPublicKeyPinner, or
// NewCertificatePinnerChain, then assign it to Config.Security.CertificatePinner:
//
//	pinner, err := httpc.NewSPKIHashPinner(
//	    "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2fuihg=", // current key
//	    "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=", // backup key (rotation)
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	cfg := httpc.DefaultConfig()
//	cfg.Security.CertificatePinner = pinner
//	client, err := httpc.New(cfg)
//
// Advanced users may implement this interface directly to support custom
// pinning strategies (e.g. pinning full certificates instead of public keys).
type CertificatePinner = security.CertificatePinner

// NewSPKIHashPinner creates a certificate pinner from one or more base64-encoded
// SHA-256 hashes of DER-encoded SubjectPublicKeyInfo (SPKI). This is the most
// common pinning format (used by HPKP) and is the recommended approach.
//
// Supply multiple hashes to support key rotation: the handshake succeeds if the
// peer's key matches ANY pinned hash.
//
// Generate a hash from a certificate with:
//
//	openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
//	  | openssl dgst -sha256 -binary | openssl enc -base64
//
// Returns an error if no valid hash is provided or if a hash is not valid base64.
func NewSPKIHashPinner(hashes ...string) (CertificatePinner, error) {
	return security.NewSPKIHashPinner(hashes...)
}

// NewPublicKeyPinner creates a certificate pinner from one or more DER-encoded
// PKIX public keys (as returned by x509.MarshalPKIXPublicKey). The pinner hashes
// each key with SHA-256 internally; this is a convenience over NewSPKIHashPinner
// when you already hold the raw public key bytes.
//
// Returns an error if no valid public key is provided.
func NewPublicKeyPinner(publicKeys ...[]byte) (CertificatePinner, error) {
	return security.NewPublicKeyPinner(publicKeys...)
}

// NewCertificatePinnerChain combines multiple pinners into one. A certificate is
// accepted if ANY of the wrapped pinners accepts it. Use this to support multiple
// pinning strategies simultaneously or to combine rotation keys built with
// different constructors.
//
// Returns a no-op pinner (accepts nothing) when called with no pinners.
func NewCertificatePinnerChain(pinners ...CertificatePinner) CertificatePinner {
	return security.NewCertificatePinnerChain(pinners...)
}
