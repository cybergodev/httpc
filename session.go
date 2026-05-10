package httpc

import (
	"fmt"
	"maps"
	"net/http"
	"sync"

	"github.com/cybergodev/httpc/internal/engine"
	"github.com/cybergodev/httpc/internal/validation"
)

// tempReqPool reuses engine.Request objects in captureFromOptions to reduce allocations.
var tempReqPool = sync.Pool{
	New: func() any { return &engine.Request{} },
}

// SessionConfig configures SessionManager behavior.
// Use DefaultSessionConfig() to get a configuration with sensible defaults.
type SessionConfig struct {
	// CookieSecurity configures cookie security validation.
	// If nil, no cookie security validation is performed.
	CookieSecurity *validation.CookieSecurityConfig
}

// DefaultSessionConfig returns a SessionConfig with default settings.
// By default, no cookie security validation is performed.
//
// Example:
//
//	cfg := httpc.DefaultSessionConfig()
//	cfg.CookieSecurity = validation.StrictCookieSecurityConfig()
//	sm, err := httpc.NewSessionManager(cfg)
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{}
}

// SessionManager manages session state including cookies and headers
// for DomainClient instances. It provides thread-safe access to session data.
type SessionManager struct {
	mu             sync.RWMutex
	cookies        map[string]*http.Cookie
	headers        map[string]string
	cookieSecurity *validation.CookieSecurityConfig
}

// NewSessionManager creates a new SessionManager with the given configuration.
// If no configuration is provided or nil is passed, DefaultSessionConfig() is used.
//
// Examples:
//
//	// Use default configuration
//	sm, err := httpc.NewSessionManager()
//
//	// Use custom configuration
//	cfg := httpc.DefaultSessionConfig()
//	cfg.CookieSecurity = mySecurityConfig
//	sm, err := httpc.NewSessionManager(cfg)
//
// Currently always returns a nil error; the error return is reserved for future validation.
func NewSessionManager(config ...*SessionConfig) (*SessionManager, error) {
	cfg := DefaultSessionConfig()
	if len(config) > 0 && config[0] != nil {
		cfg = config[0]
	}
	return &SessionManager{
		cookies:        make(map[string]*http.Cookie),
		headers:        make(map[string]string),
		cookieSecurity: cfg.CookieSecurity,
	}, nil
}

// SetCookieSecurity sets the cookie security configuration.
// This affects all subsequent SetCookie calls.
func (s *SessionManager) SetCookieSecurity(config *validation.CookieSecurityConfig) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cookieSecurity = config
}

// SetHeader adds or updates a header in the session.
// Returns an error if the header key or value is invalid.
func (s *SessionManager) SetHeader(key, value string) error {
	if s == nil {
		return fmt.Errorf("session manager is nil")
	}
	if err := validation.ValidateHeaderKeyValue(key, value); err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.headers[key] = value
	return nil
}

// SetHeaders adds or updates multiple headers in the session.
// Returns an error if any header key or value is invalid.
func (s *SessionManager) SetHeaders(headers map[string]string) error {
	if s == nil {
		return fmt.Errorf("session manager is nil")
	}
	for k, v := range headers {
		if err := validation.ValidateHeaderKeyValue(k, v); err != nil {
			return fmt.Errorf("invalid header %s: %w", k, err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	maps.Copy(s.headers, headers)
	return nil
}

// DeleteHeader removes a header from the session.
func (s *SessionManager) DeleteHeader(key string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.headers, key)
}

// ClearHeaders removes all headers from the session.
func (s *SessionManager) ClearHeaders() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.headers = make(map[string]string)
}

// GetHeaders returns a copy of all session headers.
func (s *SessionManager) GetHeaders() map[string]string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	headers := make(map[string]string, len(s.headers))
	maps.Copy(headers, s.headers)
	return headers
}

// SetCookie adds or updates a cookie in the session.
// Returns an error if the cookie is nil or invalid.
// If cookie security is configured, validates against security requirements.
func (s *SessionManager) SetCookie(cookie *http.Cookie) error {
	if s == nil {
		return fmt.Errorf("session manager is nil")
	}
	if cookie == nil {
		return fmt.Errorf("cookie cannot be nil")
	}
	if err := validation.ValidateCookie(cookie); err != nil {
		return fmt.Errorf("invalid cookie: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Apply cookie security validation if configured (inside lock for thread safety)
	if err := s.validateCookieSecurity(cookie); err != nil {
		return fmt.Errorf("cookie security validation failed: %w", err)
	}

	s.cookies[cookie.Name] = cookie
	return nil
}

// SetCookies adds or updates multiple cookies in the session.
// Returns an error if any cookie is nil or invalid.
// If cookie security is configured, validates against security requirements.
func (s *SessionManager) SetCookies(cookies []*http.Cookie) error {
	if s == nil {
		return fmt.Errorf("session manager is nil")
	}
	// Pre-validate all cookies outside the lock
	for i, cookie := range cookies {
		if cookie == nil {
			return fmt.Errorf("cookie at index %d is nil", i)
		}
		if err := validation.ValidateCookie(cookie); err != nil {
			return fmt.Errorf("invalid cookie at index %d: %w", i, err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate all cookies for security before storing any (atomic write)
	for _, cookie := range cookies {
		if err := s.validateCookieSecurity(cookie); err != nil {
			return fmt.Errorf("cookie security validation failed for %s: %w", cookie.Name, err)
		}
	}

	// All passed, store cookies
	for _, cookie := range cookies {
		s.cookies[cookie.Name] = cookie
	}
	return nil
}

// DeleteCookie removes a cookie from the session by name.
func (s *SessionManager) DeleteCookie(name string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.cookies, name)
}

// ClearCookies removes all cookies from the session.
func (s *SessionManager) ClearCookies() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cookies = make(map[string]*http.Cookie)
}

// GetCookies returns a copy of all session cookies.
// Optimized to reduce allocations by pre-allocating slice with exact capacity.
func (s *SessionManager) GetCookies() []*http.Cookie {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.cookies)
	if n == 0 {
		return nil
	}
	cookies := make([]*http.Cookie, 0, n)
	for _, cookie := range s.cookies {
		cookieCopy := *cookie
		cookies = append(cookies, &cookieCopy)
	}
	return cookies
}

// GetCookie returns a copy of a cookie by name, or nil if not found.
func (s *SessionManager) GetCookie(name string) *http.Cookie {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	if cookie, ok := s.cookies[name]; ok {
		cookieCopy := *cookie
		return &cookieCopy
	}
	return nil
}

// prepareOptions creates RequestOptions from the current session state.
// This is used internally by DomainClient to apply session cookies and headers to outgoing requests.
func (s *SessionManager) prepareOptions() []RequestOption {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cookieCount := len(s.cookies)
	headerCount := len(s.headers)

	if cookieCount == 0 && headerCount == 0 {
		return nil
	}

	options := make([]RequestOption, 0, 2)

	if cookieCount > 0 {
		// Batch all cookies into a single option to avoid N closure allocations
		cookies := make([]http.Cookie, 0, cookieCount)
		for _, cookie := range s.cookies {
			cookies = append(cookies, *cookie)
		}
		options = append(options, func(r *engine.Request) error {
			existing := r.Cookies()
			r.SetCookies(append(existing, cookies...))
			return nil
		})
	}

	if headerCount > 0 {
		headersCopy := make(map[string]string, headerCount)
		maps.Copy(headersCopy, s.headers)
		options = append(options, WithHeaderMap(headersCopy))
	}

	return options
}

// validateCookieSecurity checks cookie against the session's security config.
// Returns nil if no security config is set or if the cookie passes validation.
// This is the single entry point for all cookie security checks in SessionManager.
func (s *SessionManager) validateCookieSecurity(cookie *http.Cookie) error {
	if s.cookieSecurity == nil {
		return nil
	}
	return validation.ValidateCookieSecurity(cookie, s.cookieSecurity)
}

// UpdateFromResult updates session cookies from a Result.
// If cookie security is configured, insecure cookies are silently skipped.
func (s *SessionManager) UpdateFromResult(result *Result) {
	if s == nil {
		return
	}
	if result == nil || result.Response == nil || len(result.Response.Cookies) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.storeCookies(result.Response.Cookies)
}

// UpdateFromCookies updates session cookies from a slice of http.Cookie.
// If cookie security is configured, insecure cookies are silently skipped.
func (s *SessionManager) UpdateFromCookies(cookies []*http.Cookie) {
	if s == nil {
		return
	}
	if len(cookies) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.storeCookies(cookies)
}

// storeCookies validates and stores cookies in the session map.
// Caller must hold s.mu.
func (s *SessionManager) storeCookies(cookies []*http.Cookie) {
	for _, cookie := range cookies {
		if cookie != nil {
			if err := s.validateCookieSecurity(cookie); err != nil {
				continue
			}
			s.cookies[cookie.Name] = cookie
		}
	}
}

// captureFromOptions extracts cookies and headers from RequestOptions
// and stores them in the session.
//
// SECURITY: OnRequest/OnResponse callbacks are cleared before and after
// option application to prevent side-effect duplication. Only cookies and
// headers are extracted; callbacks, query params, and body data are discarded.
func (s *SessionManager) captureFromOptions(options []RequestOption) {
	if len(options) == 0 {
		return
	}

	// Use pooled engine.Request to reduce allocations on hot path
	tempReq, ok := tempReqPool.Get().(*engine.Request)
	if !ok || tempReq == nil {
		tempReq = &engine.Request{}
	}
	defer func() {
		*tempReq = engine.Request{}
		tempReqPool.Put(tempReq)
	}()

	// Clear callbacks before applying options to prevent WithOnRequest/
	// WithOnResponse from executing during this capture-only pass.
	tempReq.SetOnRequest(nil)
	tempReq.SetOnResponse(nil)

	for _, opt := range options {
		if opt != nil {
			// Best effort: ignore errors during option capture for session persistence.
			// Errors from individual options are handled during actual request execution.
			_ = opt(tempReq)
		}
	}

	// Immediately clear callbacks set by options to prevent any deferred
	// or lazy evaluation from triggering side effects after capture.
	tempReq.SetOnRequest(nil)
	tempReq.SetOnResponse(nil)

	cookies := tempReq.Cookies()
	headers := tempReq.Headers()

	if len(cookies) == 0 && len(headers) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range cookies {
		cookie := &cookies[i]
		if s.cookieSecurity != nil {
			if err := validation.ValidateCookieSecurity(cookie, s.cookieSecurity); err != nil {
				continue
			}
		}
		s.cookies[cookie.Name] = cookie
	}

	for key, value := range headers {
		if err := validation.ValidateHeaderKeyValue(key, value); err != nil {
			continue
		}
		s.headers[key] = value
	}
}
