package httpc

import (
	"strings"
	"testing"
)

// Valid base64-encoded SHA-256 SPKI hash (Let's Encrypt ISRG Root X1, from docs).
// The constructor only validates base64 format, so this is sufficient for unit tests.
const testSPKIHash = "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2fuihg="

func TestNewSPKIHashPinner_Valid(t *testing.T) {
	pinner, err := NewSPKIHashPinner(testSPKIHash)
	if err != nil {
		t.Fatalf("NewSPKIHashPinner returned error: %v", err)
	}
	if pinner == nil {
		t.Fatal("NewSPKIHashPinner returned nil pinner")
	}
	if got := pinner.Pin(); got != "spki-pins:1" {
		t.Errorf("Pin() = %q, want %q", got, "spki-pins:1")
	}
}

func TestNewSPKIHashPinner_MultipleSupportsRotation(t *testing.T) {
	// Multiple hashes are accepted (key rotation) and all counted.
	pinner, err := NewSPKIHashPinner(testSPKIHash, "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=")
	if err != nil {
		t.Fatalf("NewSPKIHashPinner returned error: %v", err)
	}
	if got := pinner.Pin(); got != "spki-pins:2" {
		t.Errorf("Pin() = %q, want %q", got, "spki-pins:2")
	}
}

func TestNewSPKIHashPinner_InvalidBase64(t *testing.T) {
	if _, err := NewSPKIHashPinner("not-valid-base64!!!"); err == nil {
		t.Error("NewSPKIHashPinner accepted invalid base64; want error")
	}
}

func TestNewSPKIHashPinner_Empty(t *testing.T) {
	if _, err := NewSPKIHashPinner(); err == nil {
		t.Error("NewSPKIHashPinner accepted no hashes; want error")
	}
}

func TestNewPublicKeyPinner_Empty(t *testing.T) {
	if _, err := NewPublicKeyPinner(); err == nil {
		t.Error("NewPublicKeyPinner accepted no keys; want error")
	}
}

func TestNewCertificatePinnerChain(t *testing.T) {
	a, err := NewSPKIHashPinner(testSPKIHash)
	if err != nil {
		t.Fatalf("NewSPKIHashPinner: %v", err)
	}
	b, err := NewSPKIHashPinner("C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=")
	if err != nil {
		t.Fatalf("NewSPKIHashPinner: %v", err)
	}
	chain := NewCertificatePinnerChain(a, b)
	if got := chain.Pin(); !strings.HasPrefix(got, "chain:[") {
		t.Errorf("chain Pin() = %q, want chain:[...] prefix", got)
	}
}

// TestConfigCertificatePinner_AcceptedByNew ensures a Config carrying a pinner is
// accepted by New() and reflected in String(). This guards the convertToEngineConfig
// wiring end-to-end (public field -> engine.Config.CertificatePinner).
func TestConfigCertificatePinner_AcceptedByNew(t *testing.T) {
	pinner, err := NewSPKIHashPinner(testSPKIHash)
	if err != nil {
		t.Fatalf("NewSPKIHashPinner: %v", err)
	}

	t.Run("disabled by default", func(t *testing.T) {
		cfg := DefaultConfig()
		if s := cfg.String(); !strings.Contains(s, "CertPinning: <disabled>") {
			t.Errorf("DefaultConfig String() = %q, want CertPinning: <disabled>", s)
		}
	})

	t.Run("configured reflected in String", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Security.CertificatePinner = pinner
		if s := cfg.String(); !strings.Contains(s, "CertPinning: <configured>") {
			t.Errorf("Config String() = %q, want CertPinning: <configured>", s)
		}
	})

	t.Run("accepted by New", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Security.CertificatePinner = pinner
		client, err := New(cfg)
		if err != nil {
			t.Fatalf("New with pinner returned error: %v", err)
		}
		if client == nil {
			t.Fatal("New returned nil client")
		}
		if err := client.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
}
