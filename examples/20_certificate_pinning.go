//go:build examples

package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/httpc"
)

// This example demonstrates certificate pinning — a defense against
// man-in-the-middle attacks that holds even if a trusted Certificate Authority
// is compromised. When a pinner is set, the TLS handshake is rejected unless
// the server presents one of the pinned public keys.
//
// Generate a server's SPKI hash from its certificate:
//
//	openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
//	  | openssl dgst -sha256 -binary | openssl enc -base64
//
// Note: the hashes and the public key below are ILLUSTRATIVE. They do not
// match httpbin.org's current key, so the requests below are rejected at the
// TLS handshake — that rejection is pinning working as designed. To see a
// request succeed, replace them with your target's real SPKI hash computed
// via the command above.

func main() {
	fmt.Println("=== Certificate Pinning Examples ===")

	// 1. Pin by a single SPKI hash (recommended / HPKP format)
	demonstrateSPKIHashPinning()

	// 2. Pin multiple hashes to support key rotation
	demonstrateKeyRotation()

	// 3. Combine pinners with NewCertificatePinnerChain
	demonstratePinnerChain()

	// 4. Pin by a raw DER public key (NewPublicKeyPinner)
	demonstratePublicKeyPinner()

	fmt.Println("\n=== All Examples Completed ===")
}

// reportPinnedRequest interprets the outcome of a pinned request.
// A matching pin succeeds; a mismatch (rotated key, or an illustrative pin)
// fails the TLS handshake — and that failure IS the protection working.
func reportPinnedRequest(err error) {
	if err == nil {
		fmt.Println("  [OK] Pin matched — TLS handshake succeeded")
		return
	}
	var clientErr *httpc.ClientError
	if errors.As(err, &clientErr) {
		fmt.Printf("  [X] Handshake rejected (%s): %s\n", clientErr.Code(), clientErr.Message)
	} else {
		fmt.Printf("  [X] Request failed: %v\n", err)
	}
	fmt.Println("    A rejection means the server's key did not match a pinned value")
	fmt.Println("    — expected during key rotation or when testing an illustrative hash.")
}

// demonstrateSPKIHashPinning pins by a single base64 SHA-256 SPKI hash.
func demonstrateSPKIHashPinning() {
	fmt.Println("--- Example 1: SPKI Hash Pinning (Recommended) ---")

	// NewSPKIHashPinner accepts one or more base64 SHA-256 hashes of the
	// DER-encoded SubjectPublicKeyInfo. This is the most common pinning format.
	pinner, err := httpc.NewSPKIHashPinner(
		"YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2fuihg=",
	)
	if err != nil {
		log.Printf("Failed to create pinner: %v\n", err)
		return
	}

	// Assign the pinner to Security.CertificatePinner; nothing else is required.
	cfg := httpc.DefaultConfig()
	cfg.Security.CertificatePinner = pinner

	client, err := httpc.New(cfg)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	_, err = client.Get("https://httpbin.org/get", httpc.WithTimeout(15*time.Second))
	reportPinnedRequest(err)
	fmt.Println()
}

// demonstrateKeyRotation pins multiple hashes: the handshake succeeds if ANY
// pinned key matches. Supply a current key plus one or more backup keys so a
// planned key rotation does not take your client offline.
func demonstrateKeyRotation() {
	fmt.Println("--- Example 2: Key Rotation (Multiple Hashes) ---")

	pinner, err := httpc.NewSPKIHashPinner(
		"YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2fuihg=", // primary pin (illustrative)
		"C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=", // backup pin for planned rotation
	)
	if err != nil {
		log.Printf("Failed to create pinner: %v\n", err)
		return
	}

	cfg := httpc.DefaultConfig()
	cfg.Security.CertificatePinner = pinner

	client, err := httpc.New(cfg)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	_, err = client.Get("https://httpbin.org/get", httpc.WithTimeout(15*time.Second))
	reportPinnedRequest(err)
	fmt.Println()
}

// demonstratePinnerChain combines multiple pinners into one. A certificate is
// accepted if ANY wrapped pinner accepts it — useful for mixing pinning
// strategies or combining rotation sets built with different constructors.
func demonstratePinnerChain() {
	fmt.Println("--- Example 3: Combining Pinners (NewCertificatePinnerChain) ---")

	primary, err := httpc.NewSPKIHashPinner("YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2fuihg=")
	if err != nil {
		log.Printf("Failed to create primary pinner: %v\n", err)
		return
	}
	backup, err := httpc.NewSPKIHashPinner("C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=")
	if err != nil {
		log.Printf("Failed to create backup pinner: %v\n", err)
		return
	}

	// Chain accepts the certificate if either pinner matches.
	cfg := httpc.DefaultConfig()
	cfg.Security.CertificatePinner = httpc.NewCertificatePinnerChain(primary, backup)

	client, err := httpc.New(cfg)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	_, err = client.Get("https://httpbin.org/get", httpc.WithTimeout(15*time.Second))
	reportPinnedRequest(err)
	fmt.Println()
}

// demonstratePublicKeyPinner pins raw DER-encoded PKIX public keys instead of
// precomputed SPKI hashes — a convenience for when you already hold the key
// bytes (e.g., produced by x509.MarshalPKIXPublicKey). The pinner hashes the
// key with SHA-256 internally. As with the hashes above, this key is
// illustrative (a throwaway P-256 key), so the handshake is expected to fail.
func demonstratePublicKeyPinner() {
	fmt.Println("--- Example 4: Raw Public Key Pinning (NewPublicKeyPinner) ---")

	// A complete 91-byte DER-encoded PKIX public key (ECDSA P-256).
	pubKey := []byte{
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
		0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
		0x42, 0x00, 0x04, 0x76, 0x09, 0xa1, 0x1a, 0xae, 0xcb, 0x8c, 0x2f, 0x97,
		0x0a, 0xba, 0x42, 0x91, 0xa7, 0x8d, 0xfa, 0x91, 0x69, 0x5d, 0x0c, 0xfc,
		0xf1, 0xfc, 0xa8, 0x04, 0x9e, 0x78, 0xfb, 0xb6, 0xa2, 0x19, 0x09, 0x67,
		0x23, 0x3c, 0x79, 0xba, 0x95, 0xb2, 0xd8, 0x3f, 0xda, 0x6c, 0x01, 0x15,
		0xef, 0x0c, 0xde, 0x8a, 0x69, 0x23, 0xd4, 0x62, 0xc7, 0x1e, 0x0b, 0x5b,
		0xbc, 0xd8, 0xa4, 0xbb, 0x26, 0x96, 0x9f,
	}

	pinner, err := httpc.NewPublicKeyPinner(pubKey)
	if err != nil {
		log.Printf("Failed to create pinner: %v\n", err)
		return
	}

	cfg := httpc.DefaultConfig()
	cfg.Security.CertificatePinner = pinner

	client, err := httpc.New(cfg)
	if err != nil {
		log.Printf("Failed to create client: %v\n", err)
		return
	}
	defer client.Close()

	_, err = client.Get("https://httpbin.org/get", httpc.WithTimeout(15*time.Second))
	reportPinnedRequest(err)
	fmt.Println()
}
