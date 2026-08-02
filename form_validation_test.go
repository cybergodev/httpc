package httpc

import (
	"net/url"
	"strings"
	"testing"

	"github.com/cybergodev/httpc/internal/validation"
)

// TestValidateFormInput exercises all type-dispatch branches and boundary
// conditions of validateFormInput: map[string]string, url.Values, unsupported
// types, and control-character / length validation within each branch.
func TestValidateFormInput(t *testing.T) {
	longValue := strings.Repeat("x", validation.MaxValueLen+1)
	longKey := strings.Repeat("k", validation.MaxHeaderKeyLen+1)

	tests := []struct {
		name    string
		data    any
		wantErr bool
	}{
		// map[string]string branch
		{"map valid", map[string]string{"key": "value"}, false},
		{"map empty key", map[string]string{"": "value"}, true},
		{"map control char in key", map[string]string{"bad\x00key": "value"}, true},
		{"map control char in value", map[string]string{"key": "bad\x00value"}, true},
		{"map value too long", map[string]string{"key": longValue}, true},
		{"map key too long", map[string]string{longKey: "value"}, true},
		{"map tab in value allowed", map[string]string{"key": "val\tue"}, false},

		// url.Values branch
		{"url.Values valid", url.Values{"k": {"v1", "v2"}}, false},
		{"url.Values empty key", url.Values{"": {"v"}}, true},
		{"url.Values control char in value", url.Values{"k": {"bad\x01val"}}, true},
		{"url.Values key too long", url.Values{longKey: {"v"}}, true},
		{"url.Values with empty value slice", url.Values{"k": {}}, false},

		// default branch — unsupported type
		{"string unsupported", "not a map", true},
		{"int unsupported", 42, true},
		{"nil unsupported", nil, true},
		{"slice unsupported", []string{"a", "b"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFormInput(tt.data)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			} else if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

// TestDefaultLoggingConfig verifies the default constructor returns a usable
// config with logging disabled.
func TestDefaultLoggingConfig(t *testing.T) {
	cfg := DefaultLoggingConfig()
	if cfg == nil {
		t.Fatal("DefaultLoggingConfig() returned nil")
	}
	if cfg.LogFunc != nil {
		t.Error("LogFunc should be nil by default (logging disabled)")
	}
}
