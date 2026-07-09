# Changes

All notable changes to the cybergodev/httpc library will be documented in this file.

---

## v1.5.3 - Socks5 Proxy Fix, DoH Crash Guard & Performance (2026-07-10)

### Fixed
- socks5/socks5h proxies now accepted at client creation — the connection pool previously rejected them (http/https only) despite public config validation accepting socks5
- EnableSystemProxy now seeds SSRF-exempt proxy addresses from both http and https probes instead of https-only
- WithQuery/WithQueryMap skip nil values at the API layer — WithQuery("k", nil) emits no param instead of "?k=%3Cnil%3E"
- executeWithRetry releases the discarded retry response before the backoff sleep, freeing the connection slot for the full delay instead of holding it idle
- Windows system-path env patterns fixed from dead "%VAR%" to live "${VAR}" (os.ExpandEnv only expands $VAR/${VAR}); now also protects non-C-drive installs
- examples/04_compression.go: removed an os.Exit(1) that terminated the whole program after the first sub-example
- download.go: response-release defer moved before extractDownloadFields so a panic there can no longer leak the pooled response

### Security
- DoH resolver A/AAAA lookup goroutines now recover panics into a lookup error — a panic previously bypassed the request-path safety nets and could crash the whole process
- Validated-URL cache no longer persists URLs with embedded credentials (user:pass@host) — revalidated per call instead of cached for the cache lifetime

### Performance
- Query-string escaping writes straight into the builder: one-escape values ~-47% time / -50% allocs; BenchmarkMicro_ManyQueryParams 85→80 allocs/op
- Content-Type/Accept-Encoding/User-Agent pre-canonicalized; per-call http.CanonicalHeaderKey skipped on the hot path
- requestProcessor.Build batches per-request header value slices into one backing array (allocs/op geomean -3.34% across benchmarks)
- captureRequestHeaders transfers header ownership to the Result instead of cloning — -1 alloc/op (-4 on the retry path)
- Removed a dead per-dial mutex Lock/Unlock (latency rolling average) and atomic (failed-conn count) from the connection path
- Removed dead PoolManager.sync.RWMutex, acquired only in Close() where it protected no field

### Changed
- WithBody(BodyForm) and WithForm share a single validate-then-encode path (non-breaking; only the WithBody wrong-type error loses a "convert to form data: " text prefix)
- Manual/system proxy branches consolidated onto a single shared ValidateProxyURL validator so the public Config validator and internal pool cannot drift
- validateFormInput no longer re-validates the form key once per value (split into validateFormKey + validateFormValue)
- retryableStatusPrefixes now derived from retryableStatusCodes instead of a hand-maintained parallel slice (prevents silent drift)
- createVerifyPeerCertificate signature simplified (dead InsecureSkipVerify branch removed); doc clarifies pinning + InsecureSkipVerify semantics
- resultBuilderPool.Put gated on Cap() <= 4096, matching the form/error builder cap guards
- mergeNilSubConfigs now copies default sub-configs (fresh headers map) instead of aliasing shared DefaultConfig() pointers
- TimeoutMiddleware godoc documents the streaming/Download caveat (use WithTimeout for Download)
- WithMaxRedirects godoc clarifies 0 ≠ disabled (use WithFollowRedirects(false)); redirect-limit and cookie-scrub comments corrected

### Added
- New examples: certificate pinning (examples/20_certificate_pinning.go) and SSRF protection (examples/21_ssrf_protection.go)
- Test-suite expansion (FIX-001): table-driven tests across client, domain-client, download, retry, transport-security, pools, request, netutil, decompression; tautological mock self-tests removed

### Removed
- Unused hostStats latency/failure fields and their mutex (never surfaced in GetMetrics)
- Unused ValidateIP and parseExemptCIDRs from netutil (referenced only by tests; parseExemptCIDRs relocated as a test helper)
- Dead cfg.Connection == nil branch in NewDomain (mergeNilSubConfigs already guarantees non-nil)

---

## v1.5.2 - Per-Request SSRF Override, Panic Safety Net & Deprecated-API Removal (2026-06-15)

### Breaking
- Removed deprecated package-level download functions (`DownloadFile`, `DownloadWithOptions`, `DownloadFileWithContext`, `DownloadWithOptionsWithContext`) — use the canonical `Download(ctx, url, cfg, options...)`
- Removed exported sentinel `ErrInvalidURL` (was never returned anywhere in the codebase) — delete any `errors.Is(err, httpc.ErrInvalidURL)` checks
- Panics on the public request/download path are now returned as errors instead of crashing the caller (always-on recover guard at each execution boundary; no signature change)

### Added
- `WithAllowPrivateIPs(allow bool)` per-request option — lets a secure-by-default client reach localhost/private IPs on one trusted call without relaxing the whole client
- `Download(ctx, url, cfg, options...)` — single recommended package-level download entry point
- Public certificate-pinning API: `CertificatePinner` type and `NewSPKIHashPinner`/`NewPublicKeyPinner`/`NewCertificatePinnerChain` constructors (no internal-package import needed)
- `CertificatePinner` field on `SecurityConfig` wiring pinning end-to-end via `config_convert`

### Changed
- Per-request SSRF override propagates to the pre-flight validator, the connection dialer, and the redirect-target validator
- `CookieSecurity`/`SessionConfig` field types changed to the exported alias `*CookieSecurityConfig` (callers no longer import `internal/validation`)
- `ProxyURL` validation now requires scheme ∈ {http,https,socks5,socks5h} and a non-empty host
- Default client self-heals: `getDefaultClient` recreates a closed default client instead of returning it
- DoH resolver gains per-host singleflight (coalesces concurrent cache misses) and nearest-Expiry eviction when the cache is full
- SSRF validation DNS lookup now derives its timeout from the caller's context (was `context.Background()`)
- `StrictCookieSecurityConfig()` now sets `RequireSecureForSameSiteNone: true`
- `Client.Request()` returns `ErrClientClosed` directly instead of wrapping it with `fmt.Errorf("%w", ...)`
- `New()`/`NewDomain()` share a single `prepareConfig` helper so the two constructors cannot drift

### Security
- Removed attacker-controlled `GO_TEST`/`GOTEST` env branch from `isTestEnvironment()` that could disable certificate pinning
- SSRF validation now blocks legacy integer/hex/octal IPv4 notation (e.g. `2130706433`, `0x7f000001`) that bypasses `net.ParseIP` on cgo builds
- Cert-pin cache key widened from an 8-byte prefix to the full 32-byte SHA-256 fingerprint (removes prefix-collision risk)
- Cookie `Value`/`Domain`/`Path` no longer leak across requests via pooled memory (RoundTrip jar-merge + `SessionManager.captureFromOptions` paths)
- Validated-URL cache is bypassed (read and write) when a per-request SSRF override is present, preventing cache poisoning

### Fixed
- `RoundTrip` cookie-jar scrub now clears the populated merged slice (previously iterated an empty pooled header, leaking cookie fields)
- `SessionManager.captureFromOptions` now copies each cookie before storing (`&cookies[i]` aliased pooled memory released on return)
- `PoolManager.Close()` resets `activeConns`/`totalConns` (left phantom counts when connections arrived during close)
- `evictStaleHosts()` hostCount compensation was inverted — bumped on the losing `LoadOrStore` path, causing a steady under-count
- `sleepWithContext` drains the pooled timer channel to stop a stale timer firing on reuse
- Config-apply and validation errors no longer call `metrics.recordRequest()` (no longer skew connection-health metrics)
- Download validates `ChecksumAlgorithm` before `os.OpenFile` and removes the partial file on Sync/Close failure (non-resume path)
- `examples/17_file_operations.go`: restored 11 corrupted `✓` glyphs, fixed a checksum-demo logic no-op, migrated to canonical `Download`

### Performance
- `Result` + its three nested info structs co-located in one heap block via `resultBundle` (−3 allocs/op on every request result)
- Map pools store map values directly instead of `*map` pointers; response headers transfer directly (drops a defensive `CloneHeader`) — −6 allocs/op steady state
- `queryValueLength` formats numeric/bool values into a stack buffer instead of heap-allocating (−1–2 allocs/op for typed query params)
- `SimpleGET`: 87 → 78 allocs/op combined; consistent reductions across all end-to-end benchmarks

---

## v1.5.1 - Config Pointer Types, Performance & Documentation (2026-05-31)

### Breaking
- Config sub-configs changed to pointer types (*TimeoutConfig, etc.) — nil sub-configs auto-filled with defaults in New()
- Migration: `httpc.Config{Timeouts: TimeoutConfig{...}}` → `httpc.Config{Timeouts: &TimeoutConfig{...}}` for all sub-config literals
- Partial configs now work: nil sub-configs receive defaults automatically

### Changed
- Performance: pooled getLimitReader (-1 alloc/op), pooled time.Timer (-1 alloc/retry), readBody fast path threshold 16KB→512KB, buffer steal threshold 16KB→32KB
- ValidateConfig no longer mutates caller's Config — CIDR parsing deferred to parseSSRFExemptCIDRs after deep copy
- Renamed maxRetries constant to maxRetryAttempts; added maxRedirectLimit constant (was magic number 50)
- Exported formatBytes→FormatBytes and formatSpeed→FormatSpeed for documentation example compilation
- Removed dead Result sync.Pool (releaseResult was never called in production)

### Fixed
- Content-Encoding comparison now case-insensitive per RFC 7231
- README/README_zh-CN/docs: sub-config examples now use pointer syntax (&httpc.TimeoutConfig{...})
- Removed non-existent ReleaseResult references from README, README_zh-CN, and all docs
- storeCookies() now copies cookie value structs preventing use-after-pool-return
- TestParseExemptCIDRs_TableDriven now calls parseSSRFExemptCIDRs() instead of ValidateConfig()
- download.go error message improved for non-engine ResponseMutator from middleware wrapping
- doc.go Close() example now handles error properly in defer

---

## v1.5.0 - Security Hardening, Brotli & Performance (2026-05-25)

### Breaking
- Removed Brotli (br) decompression support — library is now zero third-party dependency
- Removed BrowserFingerprint field from ConnectionConfig and TLS fingerprinting feature
- Removed all third-party dependencies (utls, brotli, circl)

### Added
- Interfaces section in README: Doer, Client, DomainClienter with mock examples
- Bounded LRU URL validation cache (maxSize=1024) replacing unbounded sync.Map
- Exported HasSensitiveQueryParams for cross-package reuse of sensitive param detection
- Exported engine.QueryEscape for pooled query escaping in form encoding
- Boundary tests for nil-pointer targets, non-UTF8 bodies, int64 min, control chars, zero timeout
- TestClient_Lifecycle_AfterClose verifying closed client rejects requests
- Test coverage: connection 54.9%→81.1%, validation 92.8%→96.1%, overall 86.7%→88.8%

### Changed
- Config deep-copied in New() to prevent caller mutation affecting client
- AuditMiddleware returns no-op when onAudit is nil
- Security warning output configurable via SetSecurityWarnOutput() with RWMutex protection
- Deduplicated hasSensitiveContent — replaced 30-line inline scan with HasSensitiveQueryParams()
- Pool ClientError objects to reduce heap allocations in error classification paths
- Stack-allocated buffer in captureRequestHeaders for Content-Length formatting
- Replaced stdlib url.QueryEscape with pooled engine.QueryEscape in encodeFormFields
- Converted 6+ test suites to table-driven style (retry, response, middleware, download, request)

### Fixed
- Response.Body race — replaced sync.Once + RLock with bodyReady flag + double-check locking
- Added bodyMu synchronization to SetRawBody() and SetRawBodyReader()
- Closed-client check in Request() and executeRequest()
- Trailing slash preservation in DomainClient buildURL()
- AcquireRequest fallback returns maxRetries=-1 instead of 0 (disabled)
- Context cancellation transferred to lastResp in retry fallback
- Download resume total calculation when Content-Length is unknown
- Download directory check before resume attempt
- Circular error unwrap chain in classifyErrorWithSanitizedURL

### Performance
- SimpleGET: -6.5% memory (8166→7635 B/op), -4.4% allocs (90→86)
- POST JSON: -3.9% memory (10618→10209 B/op), -3.3% allocs (121→117)
- Concurrent (c=10): -9.3% memory (9207→8353 B/op), -5.6% allocs (89→84)
- ResultReuse: -7.1% memory (8027→7461 B/op), -4.6% allocs (87→83)
- SanitizeURL: -25% latency, -100% allocs for URLs with query params
- Gzip decompression: 14.4μs/op (was 18.0μs), ~20% improvement
- Deflate decompression: 6.9μs/op (was 8.1μs), ~15% improvement
- WithTimeout: 79 allocs/op (was 80), ~150 bytes/op reduction
- Pooled ClientError reduces GC pressure under retry/error scenarios
- sync.Pool for HTTP headers, query params, url.URL, string builders, and query escaping
- Header ownership transfer instead of double-clone per request
- ASCII lowercase for sensitive param lookups, stack-buffered float formatting

### Removed
- Brotli decompression support and related pools from response.go
- BrowserFingerprint from ConnectionConfig, engine Config, and connection pool
- Duplicate test functions across engine, security, and public packages
- BenchmarkMicro_URLCache and BenchmarkJSONMarshal (tested stdlib, not httpc)
- Dead pm.metrics field and unused pool test assertion

---

## v1.4.4 - Bug Fixes, Performance & Code Quality (2026-05-18)

### Fixed
- Timeout not shared across retry attempts — each retry got a fresh timeout, allowing ~3x configured duration
- io.Reader request body consumed on first retry attempt, causing subsequent attempts to silently send empty body
- Default ResponseHeaderTimeout (30s) overriding per-request WithTimeout values > 30s, disconnecting slow servers
- Request headers capture missing Content-Length and Host (Go stores these as separate struct fields)
- Download path discarding all response headers and request metadata
- unsafe pointer cast sharing memory between Result.Body and Result.RawBody, corrupting Body after ReleaseResult
- Unbounded memory growth in retry body buffering — 100MB cap added
- DownloadConfig.ChecksumAlgorithm silently ignored, always defaulting to SHA-256
- Nil pointer dereference on Close() for zero-value Client and DomainClient
- Float64 overflow in exponential retry delay at high attempt counts
- Idle connections exceeding MaxConnsPerHost when MaxConnsPerHost < 2
- ValidateConfig header errors wrapped with %v instead of %w, preventing errors.As/Is matching
- DNS resolution and proxy SSRF validation blocking indefinitely — 10s timeout added
- O(n) sync.Map.Range host counting replaced with O(1) atomic counter for maxHostEntries enforcement
- DoH cache insertion CAS loop unbounded under extreme contention — max 3 retries added
- Reduced redundant "transport failed"/"build request failed" error wrappers causing verbose duplicate-URL chains

### Changed
- Default request timeout: 30s → 180s (better for AI/LLM and large upload scenarios)
- Default ResponseHeader timeout: 30s → 0 (context timeout now sole mechanism; SecureConfig retains 10s)
- Added MaxRetryDelay field to RetryConfig (default: 30s, previously opaque formula)
- Added Proto, ResponseHeaders, RequestURL, RequestMethod, RequestHeaders to DownloadResult
- Exported EqualFold and added ContainsFold as shared ASCII case-insensitive utilities
- Replaced unsafe.Pointer + reflect context setting with http.Request.WithContext() (Header map empty at construction)
- Extracted checkInit(), downloadWithContext(), prepareResumeState(), ensureCookieCapacity() helpers reducing duplication
- Consolidated 7 redundant/low-value tests into table-driven alternatives with better coverage
- README, README_zh-CN, docs, and examples corrected for timeout defaults and field documentation

### Performance
- Result.String(): 3→1 allocs/op (−67%), 248→240 B/op (−3.2%)
- Pooled strings.Builder for SanitizeURL() and Config.String() eliminating per-call allocations
- Lazy sanitizeOnce() closure in executeRequest() avoiding sanitization allocation on success path
- Optimized cloneHeader() with switch-based value copying and shared empty slice for single-value headers
- strconv.AppendInt replacing strconv.Itoa in ClientError.Error() and Result.String()
- Cached sensitiveHeaderNames set eliminating map iteration per DefaultAuditMiddlewareConfig() call

### Removed
- reflect and unsafe imports from request context setting
- 7 redundant test functions replaced by table-driven versions with proper assertions

---

## v1.4.3 - Performance, Bug Fixes & Code Quality (2026-05-11)

### Added
- `WithCookies(cookies []http.Cookie)` batch request option for setting multiple cookies in one call
- Boundary condition tests for 15+ low-coverage functions (checkParentDirSymlinks, isTestEnvironment, getMIMEHeader, SetRawBodyReader, etc.)
- Benchmarks for hasSensitiveContent (NoQuery, WithQuery, WithSensitiveQuery, WithCredentials)

### Changed
- `hasSensitiveContent()` rewritten with stack-allocated buffer for zero allocations in all cases
- `validateSameSite()` uses zero-allocation `equalFold()` instead of `strings.ToLower()`
- `AuditMiddleware` pre-computes mask set at creation time instead of per-request
- `WithCookieString()` pre-allocates combined cookie slice with exact capacity
- `WithCookie` simplified to use plain append instead of manual slice capacity check
- `WithQuery` eliminates redundant `SetQueryParams()` call when params map already exists
- `httpReq.WithContext()` replaced with direct reflect-based context setting to avoid Header map clone (~2KB saved per request)
- `SanitizeURL` fast path skips `url.Parse` for URLs with non-sensitive query params
- Header validation uses zero-allocation `asciiEqualFold` instead of `strings.EqualFold`
- `convertResponseToResult` uses unsafe string conversion to avoid body copy
- `WithForm` uses unified `convertToForm` encoding path and validates field keys/values for control characters
- `ReleaseResult` now clears entire response body instead of only first 64KB
- Streaming responses now capture redirect metadata and invoke `OnResponse` callback
- `writeDownloadBody` accepts `filePath` as explicit parameter instead of mutating `DownloadConfig`
- `captureFromOptions` clears `OnRequest`/`OnResponse` callbacks before AND after option application
- `executeRequest` releases middleware chain response on error to prevent pool leaks
- `getDefaultClient` closes client on type assertion failure, preventing resource leak
- Multiple test suites refactored to table-driven style (6 test files consolidated)
- Examples updated with `WithCookies()` batch method demonstration
- README/README_zh-CN synchronized with WithCookies docs, missing DownloadConfig fields, and fixed example run command

### Fixed
- Concurrency safety claim corrected — Result objects are NOT safe for concurrent access
- Example uses `StrictCookieSecurityConfig()` instead of `DefaultCookieSecurityConfig()`
- Missing `Retry.EnableJitter: true` added to configuration documentation
- Removed incorrect `MaxRequestBodySize` to `MaxResponseBodySize` fallback in `validateRequestBodySize`
- Removed inaccurate `io.Reader` consumption warning from `captureFromOptions` doc comment
- Duplicate test functions removed across 5 test files

### Performance
- Memory: -4.3% to -5.0% reduction across all benchmarks
- Allocations: -1.0% to -2.4% reduction (2 fewer allocs per request)
- `hasSensitiveContent`: 0 allocs (was 1 with query params), ~50-64 ns/op
- `validateSameSite`: -2 allocs per cookie validation
- `AuditMiddleware`: -1 map allocation + fewer CanonicalHeaderKey calls per request

### Removed
- Unused `httpReqCtxField` global variable and `init()` function from engine/request.go
- Unused `ValidateURL()` wrapper from validation/netutil.go

---

## v1.4.2 - Bug Fixes, Concurrency Safety & Code Quality (2026-05-07)

### Fixed
- ErrClientClosed sentinel not detectable via `errors.Is()` — bare string wrapping replaced with `%w`
- URL cache storing sensitive query parameter values (token, api_key, password, etc.) as raw map keys
- Custom TLS configurations (CA certs, client certs, cipher suites) silently ignored — TLSConfig not forwarded to connection pool
- Non-transactional `GetMetrics()` producing inconsistent snapshots (e.g., activeConns > totalConns) under concurrent reads
- hostStats eviction race orphaning entries when connections acquired during eviction window
- Nil pointer dereference in security request pool test when `getSecurityRequest` returns nil
- Duplicate sensitive query param map in engine missing entries (`idtoken`, `private-key`)
- Misaligned indentation in streaming response block (merge artifact)
- Misleading "Exported" comment on unexported `noOpPinner`

### Changed
- Replaced custom `roundTripper` interface with stdlib `http.RoundTripper` in transport manager
- Added `maxDepth=32` guard to symlink directory check preventing unbounded recursion
- Removed hardcoded function count from `doc.go` to prevent staleness
- Consolidated test coverage: removed duplicates, added boundary and nil-receiver tests
- Applied `gofmt` formatting across all `.go` files

### Removed
- 7 unused engine verb methods (get/post/put/patch/delete/head/options) — tests use `client.Request` directly
- 2 redundant test files (`coverage_gap_test.go`, `response_test.go`) merged into `coverage_test.go`

---

## v1.4.1 - Bug Fixes, Concurrency Safety & Performance (2026-04-28)

### Fixed
- Path traversal bypass in DomainClient buildURL allowing escape to sibling paths (e.g., base "/api" + "../apix")
- Nil pointer dereference panics on nil `*SessionManager` (all 14 exported methods) and nil Result sub-structs
- Permanent `ErrPoolExhausted` after `MaxTotalConns` lifetime connections (`totalConns` not decremented on close)
- New connections accepted after `PoolManager.Close()` due to missing closed check at dialer entry
- DNS cache counter going negative under concurrent eviction in DoH resolver
- `MaxResponseHeaderBytes` security limit validated but never applied to connection pool
- `SetDefaultClient` closing client when called with the same instance
- Closed-client requests reaching middleware path before failing fast
- `EnableCookies` mutation in `NewDomain` leaking to caller's Config via shallow copy
- `SetCookies` storing cookies before completing full security validation
- Decompressed body size checked against fixed `maxCompressedSize` instead of user-configured `maxSize`
- Resume download silently truncating file when server returns 200 instead of expected 206
- Download `Duration` measuring only header-receipt time instead of full body transfer
- Response pool leak on `engine.Response` type assertion failure in download
- `MetricsMiddleware` exposing credentials in URL from non-ClientError errors (e.g., stdlib `*url.Error`)
- File handle management in download body write for Windows compatibility
- Redundant `nil` check before `len()` on nil slice (staticcheck S1009)
- Unused `nopCancelFunc` and `createDefaultContext` dead code in engine client
- Redundant embedded field selectors (QF1008) in DomainClient and Response
- Tautological `err == nil` check in download Sync error path
- `isRetryableResponseReadError` returning inconsistent result for nil Cause

### Changed
- Cached `context.Background()` as package-level variable to reduce allocations
- Moved test-only pool/cache functions from production code to `testing.go`
- Documented `WithSecureCookie` ordering requirement (must be after `WithCookie`/`WithCookieMap`)
- Removed redundant `ValidateConfig`/`deepCopyConfig` before `New()` (already handled internally)
- Extracted `writeQueryParamValue` helper and `requestPool` type to eliminate duplicated code patterns
- Replaced multiple `strings.Contains` with `ContainsAny`, hoisted slice literals to package-level vars
- Pre-computed wildcard suffix at `DomainWhitelist` creation for zero-alloc matching
- Replaced `fmt.Sprintf` with `strconv.FormatFloat` and rune iteration with byte iteration for ASCII
- Clarified `AllowPrivateIPs` documentation — explicitly states it disables ALL SSRF protection
- Applied `gofmt` and `goimports` formatting across 33 previously unformatted files

### Security
- Redacted IP addresses from SSRF block error messages to prevent network topology disclosure
- Path traversal protection in DomainClient `buildURL` preventing `..` segments from escaping base URL scope
- govulncheck identified 4 stdlib vulnerabilities (GO-2026-4947, GO-2026-4946, GO-2026-4870, GO-2026-4601) fixed in Go 1.25.9

### Performance
- Allocation-free numeric formatting via `strconv.FormatFloat`
- Zero-alloc wildcard suffix matching in domain whitelist
- Direct length calculation replacing `url.Values.Encode()` for body size validation
- Cached sanitized URL in `executeRequest` reused across all error paths
- `cleanPath` normalization hoisted outside system path comparison loop

---

## v1.4.0 - Security Hardening, Performance & API Unification (2026-04-24)

### Breaking
- Config restructured from 39 flat fields to 5 sub-structs (Timeouts, Connection, Security, Retry, Middleware) — all field paths changed (e.g. `cfg.Timeout` → `cfg.Timeouts.Request`)
- NewDomain returns DomainClienter interface instead of *DomainClient
- NewSessionManager() merged with NewSessionManagerWithConfig() into NewSessionManager(config ...*SessionConfig) returning (*SessionManager, error)
- ClassifyError removed from public API
- AuditMiddlewareJSON removed — use AuditMiddlewareWithConfig with Format:"json"
- AllowPrivateIPs default changed from true to false (SSRF protection enabled by default)

### Added
- WithStreamBody() option for streaming response mode (avoids OOM on large downloads)
- SSRFExemptCIDRs field in SecurityConfig for granular SSRF bypass (VPN/VPC CIDR ranges)
- CookieSecurityConfig type alias with DefaultCookieSecurityConfig()/StrictCookieSecurityConfig() helpers
- IsSensitiveQueryParam() helper and BodyAuto/BodyMultipart constants
- Context-aware download methods: DownloadFileWithContext, DownloadWithOptionsWithContext
- DownloadResult.ResponseCookies field for download cookie access
- SessionManager.UpdateFromCookies() method and IsClosed() client method
- PerformanceConfig() and MinimalConfig() config presets
- Comprehensive docs/ directory (9 files) and new examples for session, retry, dynamic methods, context downloads

### Changed
- ~34-38% memory reduction and 2-16% latency improvement across all benchmarks
- Downloads use streaming io.Copy instead of full-body buffering
- Error classification unwraps *url.Error for accurate DNS/TLS/network error types
- DNS rebinding protection: resolve→validate→dial-by-IP replaces TOCTOU-vulnerable hostname dialing
- Redirect limit off-by-one fixed: MaxRedirects=2 now correctly allows 2 redirects
- Retry-After header delay capped at 60s to prevent indefinite waits
- Cookie security enforced in UpdateFromResult/UpdateFromCookies (was bypassable)
- Redirect errors classified as non-retryable; URL cache auto-compacts when oversized

### Fixed
- Data races: ClientError mutation in retry loop, metrics torn reads, DNS cache TOCTOU, session pool type assertion
- Resource leaks: response pool in retry loop, time.After timer leak, streaming goroutine leak, download Result never returned to pool
- SSRF blocking configured proxy connections — proxy addresses now auto-exempted from validation
- SSRF over-blocking: removed 198.18.0.0/15 (Clash/Surge) and CGNAT 100.64.0.0/10 (Tailscale/WireGuard) from blocklist
- DNS wire parser variable shadowing causing wrong answer section offset
- Compressed response size check comparing decompressed size against wrong limit
- Downloads bypassing middleware chain entirely
- WithMaxRetries(0) semantic ambiguity — 0 now means "disabled", -1 means "not set"
- Cookie pool sensitive data residual between requests

### Performance
- SimpleGET: 93→91 allocs/op, POST_JSON: 130→122 allocs/op (-6.2%) and ns/op -5.0%
- WithRetry: memory -38%, QueryParams: allocs -3.2% and ns/op -6.2%
- Large response: -32% memory, Deflate decompression: -12% latency / -22% memory
- Concurrent benchmarks: -6% latency improvement across the board

---

## v1.3.9 - API Unification & Performance Optimization (2026-03-24)

### Breaking Changes
- `DownloadOptions` type alias removed: Use `DownloadConfig` directly
- `DefaultDownloadOptions(filePath)` removed: Use `DefaultDownloadConfig()` and set `FilePath` manually
- `NewSessionManagerWithSecurity(security)` removed: Use `NewSessionManagerWithConfig(config)` instead

### Added
- `BodyKind` type and `WithBody(data, kind...)` for unified body type handling with auto-detection
- `DownloadConfig` type and `DefaultDownloadConfig()` following Config pattern
- `SessionConfig` type and `DefaultSessionConfig()` for session manager configuration
- `NewSessionManagerWithConfig(config)` config-based constructor for SessionManager
- Component-level benchmarks: header copy, JSON marshal, query encode, multipart build, concurrent URL cache

### Changed
- `CopyHeader()` and `CloneHeader()` use batch allocation strategy (~83% allocation reduction for headers)
- `cloneURL()` uses pooled `url.URL` objects
- `EncodeQueryParams()` and `AppendQueryParams()` use custom `queryEscape()` with zero-allocation fast path
- Content-Disposition header building uses `strings.Builder` instead of `fmt.Sprintf`
- Updated documentation to recommend `DomainClienter` interface usage

### Fixed
- Memory leak in `CopyHeader()`: pooled slices now properly allocated for long-lived references
- TOCTOU race condition in DNS cache size limit check using atomic CAS
- Pool reuse issue in `parseCookieHeader()` returning corrupted data
- Metrics update reliability under high contention using mutex instead of CAS loop
- Static analysis issues: context key types, nil context, potential nil pointer dereference

### Performance
- Header operations: 83% reduction in allocations (6 → 1 allocs/op for 7 headers)
- Query encoding: ~6% reduction for strings without special characters
- Multipart uploads: Reduced allocations via `mimeHeaderPool` and `urlPool`

### Removed
- Unused `clearAllPools()`, `getCacheStats()`, `cacheStats` type from `client.go`
- Unused `WithTransport()` from `internal/engine/client.go`

---

## v1.3.8 - Security Hardening & Performance Optimization (2026-03-17)

### Added
- **Cookie Security Validation**: New `CookieSecurityConfig` for enforcing Secure, HttpOnly, SameSite attributes
- **Certificate Pinning**: SPKI and public key pinning support for TLS connections
- **Redirect Domain Whitelist**: `DomainWhitelist` for controlling allowed redirect targets
- **Audit Middleware JSON**: Structured JSON output for security audit logging
- **`WithCookieMap()`**: Batch set multiple cookies from a map
- **`WithSecureCookie()`**: Request option for cookie security validation
- **Memory Management API**: `ClearURLCache()` for long-running applications
- **DoHResolver.Close()**: Proper resource cleanup for DNS-over-HTTPS resolver

### Changed
- **Performance**: ~34% memory reduction in response handling, ~45% faster deflate decompression
- **Concurrency**: DoHResolver cacheTTL now uses `atomic.Int64` for thread-safe access
- **Documentation**: Complete README rewrite with improved structure and examples

### Fixed
- **CRITICAL**: URL cache TOCTOU race condition preventing potential panic under high concurrency
- **CRITICAL**: DoH cache size counter race condition
- **CRITICAL**: `pooledFlateReader.Close()` resource leak
- **CRITICAL**: Symlink attack prevention in file download
- **MEDIUM**: Cookie pool sensitive data residual between requests
- **MEDIUM**: SessionManager TOCTOU race with `SetCookieSecurity()`
- **MEDIUM**: DNS compression pointer recursion depth limit (DoS protection)
- Expanded system path protection for Linux (`/lib32/`, `/lib64/`, `/usr/lib/`, `/bin/`, `/sbin/`)

### Breaking Changes
- `DoHResolver` now implements `io.Closer`; callers should call `Close()` for proper cleanup

---

## v1.3.7 - DNS-over-HTTPS, Proxy Detection & Code Quality (2026-01-22)

### Added
- **DNS-over-HTTPS (DoH) Resolver**: Encrypted DNS resolution with multiple providers (Cloudflare, Google, AliDNS)
  - Built-in caching with configurable TTL (default: 5 minutes)
  - Automatic fallback to system DNS when DoH fails
  - Helps bypass DNS pollution and prevents DNS hijacking
  - Configurable via `EnableDoH` and `DoHCacheTTL` options
- **Configurable System Proxy Detection**: New `EnableSystemProxy` option for explicit control over automatic system proxy detection
  - Supports Windows Registry, macOS system settings, and environment variables
  - Proxy priority: Manual ProxyURL > System Proxy > Direct Connection
  - Default: `false` (requires explicit opt-in)
- **Cross-Platform System Proxy Detection**: Automatic detection across Windows, macOS, and Linux platforms
  - Windows: Reads from Registry (`Internet Settings`)
  - All platforms: Falls back to `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` env vars
- **New `internal/netutil` Package**: Shared IP validation utilities
  - `IsPrivateOrReservedIP()` for private/reserved IP detection
  - `ValidateIP()` for SSRF protection
  - `IsLocalhost()` for localhost detection
  - Single source of truth for network security checks

### Changed
- **IP Validation Logic**: Consolidated duplicate IP validation code (~60 lines) into shared `netutil` package
- **Cookie Validation**: Centralized in `internal/validation/common.go`, removed duplication from `public_options.go` and `domain_client.go`
- **Cross-Platform Path Validation**: Enhanced `isSystemPath()` with platform-specific system paths for Windows, macOS, and Linux
  - Environment variable expansion on Windows (`%SystemRoot%`, `%windir%`)
  - Proper case-insensitive comparison on Windows, case-sensitive on Unix
- **FormData Performance**: Replaced JSON serialization/deserialization with type reflection-based detection
- **Constants**: Added `maxURLLen` constant, replaced hard-coded timeout values with named constants
- **Metrics**: Removed unused `idleConns` field and `IdleConnections` metric

### Fixed
- **Windows Proxy Detection**: Replaced deprecated `syscall.StringToUTF16Ptr()` with `windows.UTF16PtrFromString()` from `golang.org/x/sys/windows`
- **Dead Code**: Removed unused `isValidHeaderByte()` function from `types.go`

### API Compatibility
- **Breaking Change**: System proxy detection no longer automatic by default
  - Set `EnableSystemProxy: true` to restore old behavior
  - Code relying on implicit system proxy detection needs migration
- **No Breaking Changes to Public API**: All modifications are internal refactoring except `EnableSystemProxy` default behavior

### Impact
- **Maintainability**: Reduced code duplication by ~150 lines through package consolidation
- **Cross-Platform**: System path detection works correctly on Windows, macOS, and Linux
- **Testability**: `GetOS` variable allows OS mocking for unit tests
- **Security**: Consistent IP and cookie validation across all code paths

---

## v1.3.6 - Code Quality, Cross-Platform Compatibility & Documentation (2026-01-19)

### Security
- **Fixed SSRF Protection Cross-Platform Compatibility**: Replaced Windows-incompatible `syscall.RawConn.Control` implementation with cross-platform DNS resolution validation
  - `validateAddressBeforeDial()` now performs comprehensive address validation before connection
  - Validates all resolved IPs for domain names (defense against DNS rebinding attacks)
  - Consistent behavior across Windows, Linux, and macOS
- **Enhanced Validation**: Direct IP validation for IP address targets, DNS resolution with full IP range checking

### Performance
- **Code Deduplication**: Removed ~30 lines of duplicate string trimming code by using `strings.TrimSpace`
- **Helper Functions**: Added `isValidHeaderByte()` for byte-based header validation
- **Optimized Imports**: Removed unused imports (`syscall`, `strings`)

### Code Quality
- **Fixed Race Conditions**:
  - `prepareManagedOptions()` now holds read lock for entire operation
  - Previously acquired lock twice separately, allowing state to change between reads
- **Improved Default Client Safety**:
  - `getDefaultClient()` properly checks for nil after loading
  - Simplified `SetDefaultClient()` by removing confusing custom implementation check logic
- **Standard Library Usage**:
  - Replaced custom `pathJoin` with `path.Join` from stdlib
  - Replaced custom trim functions with `strings.TrimSpace`
  - Replaced `fmt.Sprintf` with `strconv.Itoa/FormatInt` for faster integer conversions
- **Removed Unused Code**:
  - Eliminated `autoManage` field (always `true` with no way to toggle)
  - Removed `done` channel (only closed, never used for synchronization)
  - Removed redundant `isValidHeaderChar` function
  - Cleaned up `systemPaths` list
- **Simplified Methods**:
  - Streamlined `doRequest()` by removing unnecessary context extraction
  - Simplified `RoundTrip()` method in transport
  - Reduced complexity in download method implementations

### Bug Fixes
- **DomainClient Documentation**: Fixed inaccurate example claiming domain restriction enforcement
  - Clarified that full URLs bypass domain restriction (by design for flexibility)
  - Added best practice guidance for developers
- **Error Handling**: Fixed ignored error from `url.Parse(dc.baseURL)`
- **Parameter Naming**: Renamed `path` to `pathStr` to avoid naming conflict with package alias

### Documentation
- **Enhanced Example Code** :
  - Updated `demonstrateSecureConfig()` with better error handling
  - Added error messages for RFC 2544 benchmark network environments
  - Added Scenario 7 for private/reserved network configuration
  - Changed example URLs to `httpbin.org` (more reliable)
- **Validation Package**: Exported `IsValidHeaderChar()` for cross-package use
- **Deprecation Handling**: Removed deprecation notice from `isValidHeaderChar()` (used internally)

### API Changes
- **Backward Compatible**: All changes are backward compatible except for `Html()` removal
- No breaking changes to public APIs (except deprecated method removal)

---

## v1.3.5 - Documentation, Code Quality & Performance Enhancement (2026-01-14)

### Documentation
- **Quick Start Enhancement**: Added comprehensive default request headers documentation explaining `httpc.DefaultConfig()` usage and three-level customization (global, client, per-request)
- **Bilingual Support**: Updated both README.md and README_zh-CN.md with structured default headers guide
- **Documentation Accuracy**: Comprehensive verification and corrections across all documentation files (100% accuracy achieved)

### Features
- **DomainClient Download Support**: Added `DownloadFile()` and `DownloadWithOptions()` methods to DomainClient for automatic state management in file downloads
- **Cookie Management**: Enhanced documentation clarifying `EnableCookies` defaults to `false` in `DefaultConfig()`
- **Request Inspection**: Added `Request.Headers` and `Request.Cookies` to Result type for complete request visibility

### Security
- **Context Propagation**: Fixed context handling in `doRequest()` to properly use `WithContext()` for timeout and cancellation
- **URL Scheme Validation**: Added validation to only allow `http` and `https` schemes in DomainClient, preventing SSRF attacks via dangerous protocols (file:, data:, javascript:)
- **Race Condition Prevention**: Limited atomic retry operations to prevent potential CPU thrashing under extreme load
- **CRLF Injection**: Maintained comprehensive protection across all input validation paths

### Code Quality
- **Test Suite Consolidation**: Reduced test files from 32 to 30 by merging duplicate coverage tests
- **Cookie Validation**: Simplified cookie string parsing, reduced complexity by ~30 lines
- **Package Documentation**: Added comprehensive package-level godoc with usage examples
- **Redundant Code Removal**: Eliminated ~200 lines of unnecessary comments and unreachable code
- **URL Building**: Improved DomainClient URL construction using proper URL parsing instead of string manipulation
- **Cookie Security**: Removed hardcoded security-sensitive cookie flags, now uses Go stdlib defaults

### Performance
- **Benchmark Coverage**: 16 comprehensive benchmark categories covering HTTP requests, concurrency, advanced features, memory efficiency, response processing, and decompression
- **Measured Performance**:
  - GET request: ~214μs with 8.7KB memory (93 allocations)
  - POST JSON: ~231μs with 12.7KB memory (146 allocations)
  - Consistent performance across 1-100 concurrent goroutines (~60μs per operation)
  - Zero-copy convenience methods for status code and cookie access
  - Gzip/deflate decompression: ~14μs with 68KB working buffer

### Bug Fixes
- **RequestInfo Fields**: Corrected documentation to only include actual fields (`Headers`, `Cookies`)
- **Error Handling Behavior**: Clarified that HTTPC returns Result for ALL status codes (including 4xx/5xx)
- **Cookie Parsing**: Fixed handling of cookies with empty values (e.g., `empty=`)

### Examples
- **Restructuring**: Major consolidation reducing example files by 60% (30+ files → 12 files)
- **Quality Improvements**: Enhanced error handling, better documentation, reliable testing endpoints
- **Compilation Fixes**: Fixed 6 bugs where method calls were missing parentheses
- **Comprehensive Guides**: Created detailed examples/README.md with learning paths

### Impact
- **Code Quality**: Reduced test files, eliminated code duplication, improved maintainability
- **Features**: DomainClient download parity with Client interface
- **Backward Compatibility**: Zero breaking changes, all tests pass

---

## v1.3.4 - Code Quality, Documentation & Examples Enhancement (2026-01-08)

### Code Quality
- **Eliminated code duplication**: Removed duplicate `validateHeaderKeyValue` function from `types.go`, unified to use `internal/validation` package
- **Performance optimizations**: Replaced `fmt.Sprintf` with `strconv.Itoa/FormatInt` for 2-3x faster integer conversions
- **Memory optimizations**: Changed to fixed-size arrays in `FormatBytes()` and `FormatSpeed()` to eliminate heap allocations
- **Loop optimizations**: Improved iteration patterns in validation and parsing functions
- **Simplified logic**: Streamlined URL building in `domain_client.go`, removed redundant parsing
- **Code cleanup**: Removed redundant comments and verbose validation logic across validation and security packages

### Documentation
- **README improvements**: Fixed variable naming consistency (`resp` → `result`), added missing API documentation
- **API completeness**: Documented `WithXML()`, `WithText()`, `WithBinary()`, `HasCookie()`, `RequestCookies()`, `GetRequestCookie()`, `SaveToFile()`
- **Docs verification**: Comprehensive verification of all 8 docs files, added missing `WithCookieString` documentation
- **Chinese README**: Synchronized all changes to maintain translation consistency
- **Accuracy**: Improved from 98% to 100% documentation accuracy

### Examples
- **Major restructuring**: Reduced from 30+ files across 6 directories to 12 files across 3 directories (60% reduction)
- **Consolidated examples**: Merged related examples into comprehensive files:
  - `request_options.go` (251 lines) - merged 3 files covering body formats, auth, query params
  - `response_handling.go` (216 lines) - merged 3 files covering Result API, parsing, formatting
  - `file_operations.go` (225 lines) - merged 2 files covering upload/download
  - `cookies_advanced.go` (270 lines) - merged 5 files covering all cookie operations
  - `domain_client.go` (165 lines) - merged 4 files covering DomainClient usage
- **Quality improvements**: Enhanced error handling, better documentation, reliable endpoints (httpbin.org)
- **Bug fixes**: Fixed 6 compilation errors where method calls were missing parentheses (`.StatusCode` → `.StatusCode()`)
- **README guides**: Created comprehensive `examples/README.md` with learning paths and directory-specific guides

### Bug Fixes
- Fixed localhost detection logic in `internal/security/validator.go`
- Fixed URL sanitization for fragments in `internal/engine/errors.go`
- Fixed transport error classification patterns
- Fixed API usage bugs in example files (method calls vs field access)

### Impact
- **Code size**: Reduced by ~1,000 lines through consolidation and optimization
- **Performance**: 2-3x faster integer conversions, eliminated heap allocations in hot paths
- **Maintainability**: Single source of truth for validation, better organized tests and examples
- **Developer experience**: Complete and accurate documentation, high-quality consolidated examples
- **Backward compatibility**: Zero breaking changes, all tests pass

---

## v1.3.3 - Code Quality & Security Enhancement (2025-12-31)

### Security
- Enhanced SSRF protection with secure defaults (blocks private IP ranges by default)
- Maintained backward compatibility for existing `AllowPrivateIPs: true` configurations
- Improved default security posture for new users

### Code Quality
- **NEW**: Created `internal/validation/common.go` package consolidating all validation logic
- **REMOVED**: ~150 lines of duplicate validation code from `public_options.go`
- **CONSOLIDATED**: 8 validation functions into reusable, well-tested utilities
- Enhanced test coverage with 50+ validation test cases
- Unified error message formats across all validators

### Performance
- Optimized retry logic with early returns and priority ordering
- Enhanced file path validation with single-pass character checking
- Improved cookie parsing with better bounds checking
- Reduced allocations in hot paths through optimized string operations

### Changed
- All validation logic centralized in single package for better maintainability
- Consistent CRLF injection prevention and input sanitization
- Zero breaking changes - all public APIs remain unchanged
- Code duplication reduced by ~25% through consolidation

---

## v1.3.1 - Security and Performance Optimization (2025-12-12)

### Security
- Enhanced input validation with CRLF injection prevention
- Strengthened SSRF protection with additional IP range checks
- Improved file path validation with comprehensive security checks
- Enhanced cookie parsing with strict validation rules

### Performance
- Optimized hot path functions for minimal allocations
- Improved connection pool metrics with lock-free operations
- Optimized string operations and trimming functions
- Enhanced domain client URL building and state management

### Error Handling
- Comprehensive error classification improvements with priority-based matching
- Added Unix error code support (ECONNREFUSED, ETIMEDOUT, EHOSTUNREACH, ENETUNREACH)
- Enhanced network error pattern detection
- Fixed HTTP/2 header validation error messages
- Added Connection header value validation (keep-alive, close, upgrade)

### Code Quality
- Added comprehensive comments for security-critical functions
- Improved error context and classification accuracy
- Enhanced test coverage for edge cases and ambiguous patterns
- Optimized error classification with early returns for better performance

---

## v1.3.0 - Performance and Quality Improvements (2025-12-09)

> **⚠️ BREAKING CHANGES**: This version includes internal optimizations that may affect behavior in edge cases. While the public API remains unchanged, applications relying on specific internal timing or nil-handling behavior should test thoroughly before upgrading.

### ⚠️ Migration Notes
- **Nil Response Handling**: Removed redundant nil checks in hot paths. Ensure your code doesn't pass nil Response/Result objects to methods.
- **Validation Changes**: Stricter input validation may reject previously accepted (but invalid) inputs. Review error handling for header/cookie/URL validation.
- **Decompression**: Responses with `Content-Encoding: gzip/deflate` are now automatically decompressed. If you were manually handling decompression, remove that code.
- **Redirect Tracking**: New redirect chain tracking is enabled by default. Use `WithFollowRedirects(false)` to disable if needed.

### Performance
- Optimized hot path execution by removing redundant nil checks in Result and Response methods
- Improved status code checks with local variable caching
- Enhanced localhost detection using switch statement for better performance
- Optimized URL building in DomainClient (prioritize https:// check)
- Accelerated file path validation by moving UNC path check earlier
- Reduced allocations in cookie parsing with custom trim functions
- Added integer lookup table (0-99) for common conversions
- Optimized String() methods with pre-allocated strings.Builder

### Code Quality
- Consolidated duplicate cookie parsing logic between cookie_utils.go and public_options.go
- Added shared trimSpace helper functions to eliminate code duplication
- Unified character validation patterns (control char checks: c < 0x20 || c == 0x7F)
- Simplified validation logic across all input validators
- Enhanced prepareFilePath with single-pass validation
- Improved whitespace-only header key validation
- Optimized option processing in Request method
- Enhanced code readability and maintainability

### Added
- Automatic decompression for gzip and deflate encoded responses
- Redirect chain tracking (RedirectChain, RedirectCount in Result)
- Per-request redirect control (WithFollowRedirects, WithMaxRedirects)
- WithCookieString for parsing cookie strings from browser/server
- WithCookieValue for simple cookie creation
- DomainClient for automatic cookie/header management per domain

### Security
- Enhanced header validation to detect CRLF injection
- Comprehensive URL validation with scheme checking
- Strengthened cookie validation with improved error messages
- Added size limits for all user inputs

### Changed
- All optimizations maintain thread safety and existing functionality
- Zero breaking changes to public API
- Test coverage maintained at >72%
- Backward compatibility preserved with deprecated Response type

---


## v1.2.2 - Response and Cookie Enhancement (2025-12-04)

### Added
- String() method for Response type providing concise text representation
- Html() method as alias for Response.Body property
- `WithCookieString()` method for automatic cookie string parsing
- Support for browser-style cookie strings (e.g., "name1=value1; name2=value2")
- Comprehensive cookie string validation and error handling
- Cookie methods documentation in request options sections
- Enhanced Cookie Management examples in both English and Chinese README
- Thread-safe formatted output with nil response handling

### Changed
- Updated documentation with manual cookie setting examples
- Expanded cookie usage examples for better developer experience

---

## v1.2.1 - Code Quality, Security & Performance (2025-12-01)

### Security
- Fixed header injection vulnerability by rejecting all control characters (0x00-0x1F, 0x7F)
- Fixed path traversal validation using filepath.Rel() for robust cross-platform checking
- Fixed silent cookie jar error handling with proper error propagation
- Fixed file close error handling to prevent silent data loss
- Enhanced control character validation across all input paths

### Performance
- Fixed race condition in latency metrics using atomic.CompareAndSwap
- Optimized retry jitter generation (~10x faster using math/rand)
- Optimized header validation with fast path for managed headers
- Optimized localhost detection with fast path for common cases
- Simplified response body drain logic for better connection reuse
- Optimized header copying using shallow copy (reduced allocations)
- Removed unnecessary HEAD request in download operations (~30-50% faster)
- Reduced validation overhead by caching string length calculations

### Code Quality
- Modernized to Go 1.22+ syntax (range over int in loops)
- Consolidated validation logic into reusable helper functions
- Eliminated ~250 lines of duplicate validation code
- Extracted magic numbers to named constants across all files
- Refactored config presets to build from DefaultConfig() base
- Removed obsolete closure capture patterns
- Enhanced error messages with better context
- Improved thread-safety documentation for Response and Config types
- Removed unused HTTP2MaxStreams config field

### Changed
- Test coverage improved to 77.2% (main), 88.1% (security)
- Reduced validation code by 25% through consolidation
- Reduced config preset initialization by ~50%
- Binary size reduced through code deduplication
- All validation functions now use consistent error formats

### Fixed
- Race condition in concurrent latency metric updates
- Silent failures in cookie jar creation
- Incomplete response body draining causing connection leaks
- Redundant string operations in error classification
- Inconsistent validation behavior across duplicate code paths

---

## v1.2.0 - Optimize the core logic (2025-11-24)

### Added
- 50+ new test cases targeting previously untested code paths
- Config preset tests (SecureConfig, PerformanceConfig, MinimalConfig, TestingConfig)
- Package-level HTTP methods tests
- Request options completeness tests
- Response handling edge case tests
- Download package-level function tests
- Comprehensive validation (URL, header, cookie, query, file path)
- SSRF protection with pre/post-DNS validation
- Retry-After header support
- Panic recovery mechanism
- Thread safety documentation

### Changed
- Context cancellation/timeout no longer retries
- Smart network error classification
- Exponential backoff with secure random jitter
- Precise retryable status codes (408, 429, 500, 502, 503, 504)
- Config and Response deep copy for thread safety
- Atomic operation optimization
- Default client double-checked locking
- Connection pool health checks
- Rich error context with wrapping
- Windows path handling improvements
- Test coverage improved from ~70% to ~95%

### Fixed
- Retry after context cancellation
- Windows path traversal detection false positives
- Race conditions from concurrent Config modifications
- Connection leaks from incomplete response body reads
- Incomplete cookie validation security issues
- Race conditions in default client initialization

---

## v1.1.0 - Optimization and Enhancement (2025-11-02)

### Added
- internal/engine core engine package
- internal/monitoring package for real-time metrics
- Adaptive semaphore control with request queuing
- Three-tier buffer pool system (4KB/32KB/256KB)
- Thread-safe LRU response cache with TTL
- Per-host connection pool statistics
- HTTP/2 optimization
- Enhanced input validation with CRLF protection
- Token bucket rate limiting
- USAGE_GUIDE.md documentation

### Changed
- Optimized request/response processing pipeline
- Improved retry logic and error handling
- Memory allocations reduced by ~90%
- Average latency improved by ~30%
- Connection reuse efficiency improved by ~40%

### Fixed
- Connection pool memory leaks
- Concurrent race conditions
- Context cancellation propagation issues
- Resource cleanup edge cases

---

## v1.0.0 - Initial Release (2025-10-02)

### Added
- Full HTTP methods support
- 25+ request options
- Rich response handling with JSON/XML parsing
- Advanced file upload/download with progress tracking
- Automatic cookie management
- TLS 1.2-1.3 with configurable cipher suites
- Three security presets
- Connection pooling with HTTP/2 support
- Circuit breaker for fault protection
- Intelligent retry with exponential backoff
- Input validation and CRLF protection
- SSRF prevention
- Buffer pooling
- Secure defaults
