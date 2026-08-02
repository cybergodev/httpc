# HTTPC - 安全的 Go HTTP 客户端

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://golang.org)
[![Go Reference](https://pkg.go.dev/badge/github.com/cybergodev/httpc.svg)](https://pkg.go.dev/github.com/cybergodev/httpc)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardened-red.svg)](SECURITY.md)
[![Dependencies](https://img.shields.io/badge/deps-minimal-brightgreen.svg)](go.mod)
[![Thread Safe](https://img.shields.io/badge/thread%20safe-%E2%9C%93-brightgreen.svg)](docs/09_concurrency-safety.md)

一个快速、安全的 Go HTTP 客户端库，具备合理的默认配置、极简依赖和内置弹性机制。

**[English Documentation](README.md)** | **[www.cybergo.dev/httpc](https://www.cybergo.dev/httpc)**

---

## 目录

- [特性](#特性)
- [安装](#安装)
- [快速开始](#快速开始-5-分钟)
- [HTTP 方法](#http-方法)
- [请求选项](#请求选项)
- [响应处理](#响应处理)
- [Context 与取消](#context-与取消)
- [文件下载](#文件下载)
- [域名客户端 (会话管理)](#域名客户端-会话管理)
- [会话管理器](#会话管理器)
- [配置](#配置)
- [中间件](#中间件)
- [代理配置](#代理配置)
- [安全特性](#安全特性)
- [错误处理](#错误处理)
- [并发安全](#并发安全)
- [接口](#接口)
- [文档](#文档)
- [许可证](#许可证)

---

## 特性

| 特性 | 描述 |
|------|------|
| **默认安全** | TLS 1.2+、SSRF 防护、CRLF 注入防护、路径遍历阻断 |
| **高性能** | 连接池、HTTP/2、goroutine 安全、`sync.Pool` 优化 |
| **内置弹性** | 智能重试，支持指数退避和抖动 |
| **自动解压缩** | 透明的 gzip/deflate 处理，带 Zip 炸弹防护 |
| **开发者友好** | 简洁的 API、直观的选项模式、完善的文档 |
| **极简依赖** | 1 个直接依赖 (golang.org/x/sys)，纯 Go 实现 |
| **Cookie 管理** | 完整的 Cookie Jar 支持，带安全验证 |
| **文件操作** | 安全的文件下载，支持进度跟踪和断点续传 |

---

## 安装

```bash
go get -u github.com/cybergodev/httpc
```

**环境要求：** Go 1.25+

---

## 快速开始 (5 分钟)

### 简单 GET 请求

```go
package main

import (
    "fmt"
    "log"

    "github.com/cybergodev/httpc"
)

func main() {
    // 包级函数 - 适用于简单请求
    result, err := httpc.Get("https://httpbin.org/get")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("状态码: %d, 耗时: %v\n", result.StatusCode(), result.Meta.Duration)
}
```

### 带认证的 POST JSON 请求

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/cybergodev/httpc"
)

func main() {
    user := map[string]string{"name": "John", "email": "john@example.com"}
    result, err := httpc.Post("https://httpbin.org/post",
        httpc.WithJSON(user),
        httpc.WithBearerToken("your-token"),
        httpc.WithTimeout(30*time.Second),
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("响应: %s\n", result.Body())
}
```

### 使用客户端实例 (推荐)

```go
package main

import (
    "fmt"
    "log"

    "github.com/cybergodev/httpc"
)

func main() {
    // 创建可复用的客户端 (使用默认配置)
    client, err := httpc.NewDefault()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // 发起多个请求
    result, err := client.Get("https://api.example.com/users",
        httpc.WithQuery("page", 1),
        httpc.WithQuery("limit", 20),
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("状态码: %d\n", result.StatusCode())
}
```

---

## HTTP 方法

```go
// GET 带查询参数
result, _ := httpc.Get("https://api.example.com/users",
    httpc.WithQuery("page", 1),
    httpc.WithQueryMap(map[string]any{"limit": 20}),
)

// POST JSON 请求体
result, _ := httpc.Post("https://api.example.com/users",
    httpc.WithJSON(map[string]string{"name": "John"}),
)

// PUT / PATCH / DELETE
result, _ := httpc.Put(url, httpc.WithJSON(data))
result, _ := httpc.Patch(url, httpc.WithJSON(partialData))
result, _ := httpc.Delete(url)

// HEAD / OPTIONS
result, _ := httpc.Head(url)
result, _ := httpc.Options(url)

// 自定义方法的通用请求
result, _ := httpc.Request(ctx, "PROPFIND", url)
```

---

## 请求选项

### 请求头

```go
// 单个请求头
httpc.WithHeader("Authorization", "Bearer token")

// 多个请求头
httpc.WithHeaderMap(map[string]string{
    "X-Custom":      "value",
    "X-Request-ID":  "123",
})

// User-Agent
httpc.WithUserAgent("my-app/1.0")
```

### 认证

```go
// Bearer 令牌
httpc.WithBearerToken("your-jwt-token")

// Basic 认证
httpc.WithBasicAuth("username", "password")
```

### 查询参数

```go
// 单个参数
httpc.WithQuery("page", 1)

// 多个参数
httpc.WithQueryMap(map[string]any{"page": 1, "limit": 20})
```

### 请求体

```go
// JSON
httpc.WithJSON(data)

// XML
httpc.WithXML(data)

// 表单数据 (application/x-www-form-urlencoded)
httpc.WithForm(map[string]string{"key": "value"})

// Multipart 表单数据 (文件上传)
formData := &httpc.FormData{
    Fields: map[string]string{"key": "value"},
    Files: map[string]*httpc.FileData{
        "upload": {Filename: "doc.pdf", Content: fileBytes, ContentType: "application/pdf"},
    },
}
httpc.WithFormData(formData)

// 或使用快捷方式上传单个文件
httpc.WithFile("file", "document.pdf", fileBytes)

// 原始请求体 (自动检测 Content-Type)
httpc.WithBody([]byte("raw data"))
httpc.WithBody(data, httpc.BodyJSON) // 显式指定 BodyKind

// BodyKind 常量: BodyAuto, BodyJSON, BodyXML, BodyForm, BodyBinary, BodyMultipart

httpc.WithBinary(binaryData, "application/pdf")

// 流式请求体 (用于大型请求体)
httpc.WithStreamBody(true)
```

### Cookie

```go
// 单个 Cookie
httpc.WithCookie(http.Cookie{Name: "session", Value: "abc123"})

// 批量设置多个 Cookie (高效，预分配容量)
httpc.WithCookies([]http.Cookie{
    {Name: "session_id", Value: "abc123"},
    {Name: "user_pref", Value: "dark_mode"},
})

// 从 Map 设置多个 Cookie
httpc.WithCookieMap(map[string]string{
    "session_id": "abc123",
    "user_pref":  "dark_mode",
})

// Cookie 字符串
httpc.WithCookieString("session=abc123; token=xyz")

// 安全 Cookie 验证 (验证 Cookie 安全属性)
cfg := httpc.DefaultCookieSecurityConfig()
cfg.RequireSecure = true
httpc.WithSecureCookie(cfg)
```

### 请求控制

```go
// Context 用于取消请求
httpc.WithContext(ctx)

// 超时设置
httpc.WithTimeout(30 * time.Second)

// 重试配置
httpc.WithMaxRetries(3)

// 重定向控制
httpc.WithFollowRedirects(false)
httpc.WithMaxRedirects(5)

// 单次请求的 SSRF 覆盖 (针对一个受信任的内部 URL 的逃生舱)
httpc.WithAllowPrivateIPs(true)
```

### 回调函数

```go
// 请求发送前
httpc.WithOnRequest(func(req httpc.RequestMutator) error {
    log.Printf("发送 %s %s", req.Method(), req.URL())
    return nil
})

// 响应接收后
httpc.WithOnResponse(func(resp httpc.ResponseMutator) error {
    log.Printf("收到状态码 %d", resp.StatusCode())
    return nil
})
```

### 完整选项参考

| 类别 | 选项 |
|------|------|
| **请求头** | `WithHeader(key, value)`, `WithHeaderMap(map)`, `WithUserAgent(ua)` |
| **认证** | `WithBearerToken(token)`, `WithBasicAuth(user, pass)` |
| **查询参数** | `WithQuery(key, value)`, `WithQueryMap(map)` |
| **请求体** | `WithJSON(data)`, `WithXML(data)`, `WithForm(map)`, `WithFormData(*FormData)`, `WithFile(field, filename, content)`, `WithBody(data, ...BodyKind)`, `WithBinary([]byte, ...contentType)`, `WithStreamBody(bool)` |
| **Cookie** | `WithCookie(cookie)`, `WithCookies([]Cookie)`, `WithCookieMap(map)`, `WithCookieString("a=1; b=2")`, `WithSecureCookie(config)` |
| **控制** | `WithTimeout(dur)`, `WithMaxRetries(n)`, `WithContext(ctx)`, `WithAllowPrivateIPs(bool)` |
| **重定向** | `WithFollowRedirects(bool)`, `WithMaxRedirects(n)` |
| **回调** | `WithOnRequest(fn)`, `WithOnResponse(fn)` |

---

## 响应处理

```go
result, _ := httpc.Get("https://api.example.com/users/123")

// Result 结构组成:
// result.Request  -> *RequestInfo  (URL, Method, Headers, Cookies)
// result.Response -> *ResponseInfo (StatusCode, Status, Proto, Headers, Body, RawBody, ContentLength, Cookies)
// result.Meta     -> *RequestMeta  (Duration, Attempts, RedirectCount, RedirectChain)

// 快速访问方法 (nil 安全)
fmt.Println(result.StatusCode())     // 200
fmt.Println(result.Proto())          // "HTTP/1.1" 或 "HTTP/2.0"
fmt.Println(result.RawBody())        // 响应体 ([]byte)
fmt.Println(result.Body())           // 响应体 (string)

// 状态检查
if result.IsSuccess() { }            // 2xx
if result.IsRedirect() { }           // 3xx
if result.IsClientError() { }        // 4xx
if result.IsServerError() { }        // 5xx

// 解析 JSON 响应
var data map[string]interface{}
if err := result.Unmarshal(&data); err != nil {
    log.Fatal(err)
}

// Cookie 访问
cookie := result.GetCookie("session")
if result.HasCookie("session") { }

// 获取请求时发送的 Cookie
reqCookie := result.GetRequestCookie("token")
if result.HasRequestCookie("token") { }

// 获取所有 Cookie
allResponse := result.ResponseCookies()
allRequest := result.RequestCookies()

// 保存响应到文件
if err := result.SaveToFile("response.json"); err != nil {
    log.Fatal(err)
}

// 元数据
fmt.Println(result.Meta.Duration)      // 请求耗时
fmt.Println(result.Meta.Attempts)      // 重试次数
fmt.Println(result.Meta.RedirectCount) // 重定向次数
fmt.Println(result.Meta.RedirectChain) // 重定向 URL 链

// 字符串表示 (安全日志 - 敏感请求头已遮蔽)
fmt.Println(result.String())
```

### 自动解压缩

HTTPC 会透明地解压 `gzip` 和 `deflate` 响应。默认会自动发送
`Accept-Encoding: gzip, deflate`（可通过 `WithHeader("Accept-Encoding", ...)`
覆盖或扩展）。解压缩炸弹 (Zip 炸弹) 防护将解压后的大小限制在
`Security.MaxDecompressedBodySize`（默认 100 MB）。

```go
result, _ := httpc.Get("https://httpbin.org/gzip",
    httpc.WithHeaderMap(map[string]string{"Accept-Encoding": "gzip, deflate"}),
)
fmt.Println(result.Body()) // 已自动解压
```

> **注意：** Brotli (`br`) 和 LZW (`compress`) **不受支持**，若服务器返回这些
> 编码会报错。由于 httpc 不会主动声明它们，仅在你手动设置 `Accept-Encoding`
> 时才会发生。

---

## Context 与取消

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

result, err := httpc.Get("https://api.example.com",
    httpc.WithContext(ctx),
)
if errors.Is(err, context.DeadlineExceeded) {
    fmt.Println("请求超时")
}
```

---

## 文件下载

### 简单下载

文件下载内置安全防护：
- **UNC 路径阻断** - 防止访问 Windows 网络路径
- **系统路径保护** - 禁止写入关键系统目录
- **路径遍历检测** - 防止目录逃逸攻击
- **断点续传支持** - 自动恢复中断的下载

```go
result, _ := httpc.Download(context.Background(),
    "https://example.com/file.zip",
    &httpc.DownloadConfig{FilePath: "downloads/file.zip"},
)
fmt.Printf("已下载: %s，速度: %s/s\n",
    httpc.FormatBytes(result.BytesWritten),
    httpc.FormatSpeed(result.AverageSpeed))
```

### 带进度的下载

```go
opts := httpc.DefaultDownloadConfig()
opts.FilePath = "downloads/large.zip"
opts.ProgressCallback = func(downloaded, total int64, speed float64) {
    pct := float64(downloaded) / float64(total) * 100
    fmt.Printf("\r%.1f%% - %s/s", pct, httpc.FormatSpeed(speed))
}
result, _ := httpc.Download(context.Background(), url, opts)
```

### 断点续传下载

```go
opts := httpc.DefaultDownloadConfig()
opts.FilePath = "downloads/large.zip"
opts.ResumeDownload = true
result, _ := httpc.Download(context.Background(), url, opts)
if result.Resumed {
    fmt.Println("下载已从上次位置恢复")
}
```

### 带 Context 的下载

`Download` 直接接收 `context.Context`，因此取消和超时开箱即用 — 无需单独的 "WithContext" 入口：

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()

result, _ := httpc.Download(ctx,
    "https://example.com/large.zip",
    &httpc.DownloadConfig{FilePath: "downloads/large.zip"},
)

// 完全控制：下载配置 + Context + 请求选项
result, _ := httpc.Download(ctx, url, opts,
    httpc.WithBearerToken("your-token"),
)
```

### DownloadConfig 字段

| 字段 | 类型 | 描述 |
|------|------|------|
| `FilePath` | `string` | 下载文件保存路径 |
| `ProgressCallback` | `DownloadProgressCallback` | 进度回调: `func(downloaded, total int64, speed float64)` |
| `Overwrite` | `bool` | 覆盖已存在文件 (默认: `false`) |
| `ResumeDownload` | `bool` | 断点续传 (默认: `false`) |
| `Checksum` | `string` | 用于校验的预期校验和 |
| `ChecksumAlgorithm` | `ChecksumAlgorithm` | 校验算法 (如 `httpc.ChecksumSHA256`) |

### 下载函数

| 函数 | 描述 |
|------|------|
| `Download(ctx, url, cfg, ...options)` | **规范入口** — 包级别下载的单一函数 |

### DownloadResult 字段

| 字段 | 类型 | 描述 |
|------|------|------|
| `FilePath` | `string` | 本地文件路径 |
| `BytesWritten` | `int64` | 总写入字节数 |
| `Duration` | `time.Duration` | 下载耗时 |
| `AverageSpeed` | `float64` | 平均下载速度 (字节/秒) |
| `StatusCode` | `int` | HTTP 状态码 |
| `ContentLength` | `int64` | 服务器返回的 Content-Length |
| `Resumed` | `bool` | 是否从断点恢复 |
| `ResponseCookies` | `[]*http.Cookie` | 响应中的 Cookie |
| `ActualChecksum` | `string` | 下载文件的实际校验和 |
| `Proto` | `string` | HTTP 协议版本 (如 "HTTP/1.1", "HTTP/2.0") |
| `ResponseHeaders` | `http.Header` | 响应头 |
| `RequestURL` | `string` | 实际请求 URL |
| `RequestMethod` | `string` | 使用的 HTTP 方法 |
| `RequestHeaders` | `http.Header` | 发送的请求头 |

---

## 域名客户端 (会话管理)

用于对同一域名发起多次请求，自动管理 Cookie 和请求头：

```go
client, _ := httpc.NewDomainDefault("https://api.example.com")
defer client.Close()

// 登录 - 服务器设置 Cookie
client.Post("/login", httpc.WithJSON(credentials))

// 设置持久请求头 (所有请求都会携带)
client.SetHeader("Authorization", "Bearer "+token)

// 后续请求自动携带 Cookie 和请求头
profile, _ := client.Get("/profile")
data, _ := client.Get("/data")
```

### Cookie 管理

```go
// 单个 Cookie
client.SetCookie(&http.Cookie{Name: "session", Value: "abc"})

// 多个 Cookie
client.SetCookies([]*http.Cookie{
    {Name: "session", Value: "abc"},
    {Name: "token", Value: "xyz"},
})

// 读取 Cookie
cookie := client.GetCookie("session")   // 单个 Cookie
allCookies := client.GetCookies()        // 所有 Cookie

// 删除 Cookie
client.DeleteCookie("session")
client.ClearCookies()
```

### 请求头管理

```go
client.SetHeader("X-Custom", "value")
client.SetHeaders(map[string]string{"X-App": "v1", "X-Version": "1.0"})
headers := client.GetHeaders()
client.DeleteHeader("X-Old")
client.ClearHeaders()
```

### 访问器

```go
client.URL()     // 完整基础 URL
client.Domain()  // 仅域名
client.Session() // 底层 SessionManager
```

### 文件下载 (相对路径)

```go
result, _ := client.Download(ctx, "/files/data.csv", &httpc.DownloadConfig{FilePath: "data.csv"})
result, _ := client.Download(ctx, "/files/large.zip", downloadOpts)
```

### 所有 HTTP 方法

```go
result, _ := client.Get("/users")
result, _ := client.Post("/users", httpc.WithJSON(data))
result, _ := client.Put("/users/1", httpc.WithJSON(data))
result, _ := client.Patch("/users/1", httpc.WithJSON(data))
result, _ := client.Delete("/users/1")
result, _ := client.Head("/users")
result, _ := client.Options("/users")
result, _ := client.Request(ctx, "PROPFIND", "/resource")
```

---

## 会话管理器

`SessionManager` 提供线程安全的 Cookie 和请求头管理，内部被 `DomainClient` 使用，也可独立使用：

```go
// 创建会话管理器
sm, _ := httpc.NewSessionManagerDefault()

// 或带 Cookie 安全验证
cfg := httpc.DefaultSessionConfig()
cfg.CookieSecurity = httpc.StrictCookieSecurityConfig()
sm, _ := httpc.NewSessionManager(cfg)

// 管理 Cookie
sm.SetCookie(&http.Cookie{Name: "session", Value: "abc"})
sm.SetCookies([]*http.Cookie{{Name: "token", Value: "xyz"}})
cookie := sm.GetCookie("session")
allCookies := sm.GetCookies()
sm.DeleteCookie("session")
sm.ClearCookies()

// 管理请求头
sm.SetHeader("Authorization", "Bearer token")
sm.SetHeaders(map[string]string{"X-App": "v1"})
headers := sm.GetHeaders()
sm.DeleteHeader("X-Old")
sm.ClearHeaders()

// 从响应更新
sm.UpdateFromResult(result)
sm.UpdateFromCookies(responseCookies)

// Cookie 安全设置
sm.SetCookieSecurity(httpc.StrictCookieSecurityConfig())
```

---

## 配置

### 预设配置

```go
// 推荐的默认配置
client, _ := httpc.NewDefault()

// 最高安全性 (启用 SSRF 防护)
client, _ := httpc.New(httpc.SecureConfig())

// 高吞吐量
client, _ := httpc.New(httpc.PerformanceConfig())

// 轻量级 (无重试)
client, _ := httpc.New(httpc.MinimalConfig())

// 仅限测试 - 禁用安全特性!
client, _ := httpc.New(httpc.TestingConfig())
```

### 自定义配置

```go
config := httpc.Config{
    // 超时设置
    Timeouts: httpc.TimeoutConfig{
        Request:        30 * time.Second,
        Dial:           10 * time.Second,
        TLSHandshake:   10 * time.Second,
        ResponseHeader: 30 * time.Second,
        IdleConn:       90 * time.Second,
    },

    // 连接设置
    Connection: httpc.ConnectionConfig{
        MaxIdleConns:    100,
        MaxConnsPerHost: 20,
        EnableHTTP2:     true,
        EnableCookies:   false,
    },

    // 安全设置
    Security: httpc.SecurityConfig{
        MinTLSVersion:       tls.VersionTLS12,
        MaxTLSVersion:       tls.VersionTLS13,
        MaxResponseBodySize: 50 * 1024 * 1024, // 50 MB
        AllowPrivateIPs:     false,
    },

    // 重试设置
    Retry: httpc.RetryConfig{
        MaxRetries:    3,
        Delay:         1 * time.Second,
        BackoffFactor: 2.0,
        EnableJitter:  true,
    },

    // 默认设置 (每次请求的默认值：User-Agent、请求头、重定向策略)
    Defaults: httpc.RequestDefaults{
        UserAgent:       "MyApp/1.0",
        FollowRedirects: true,
        MaxRedirects:    10,
    },
}

// 创建客户端前验证配置 (New() 内部也会自动验证)
if err := httpc.ValidateConfig(&config); err != nil {
    log.Fatal(err)
}

client, _ := httpc.New(config)

// 检查配置 (敏感值自动遮蔽)
fmt.Println(config.String())
```

### 配置选项

| 函数 | 描述 |
|------|------|
| `DefaultConfig()` | 推荐的默认配置 |
| `SecureConfig()` | 最高安全性 (启用 SSRF 防护) |
| `PerformanceConfig()` | 高吞吐量 |
| `MinimalConfig()` | 轻量级 (无重试) |
| `TestingConfig()` | 仅限测试 - 禁用安全特性 |
| `ValidateConfig(cfg)` | 验证配置，返回错误 |
| `Config.String()` | 安全字符串表示 (敏感值已遮蔽) |

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| **超时设置** (`Timeouts`) ||||
| `Timeouts.Request` | `time.Duration` | `180s` | 整体请求超时 |
| `Timeouts.Dial` | `time.Duration` | `10s` | TCP 连接超时 |
| `Timeouts.TLSHandshake` | `time.Duration` | `10s` | TLS 握手超时 |
| `Timeouts.ResponseHeader` | `time.Duration` | `0` | 响应头超时 (0 = 禁用，使用 Context 超时) |
| `Timeouts.IdleConn` | `time.Duration` | `90s` | 空闲连接超时 |
| **连接设置** (`Connection`) ||||
| `Connection.MaxIdleConns` | `int` | `50` | 最大空闲连接数 |
| `Connection.MaxConnsPerHost` | `int` | `10` | 每个主机最大连接数 |
| `Connection.ProxyURL` | `string` | `""` | 代理 URL (http/https/socks5/socks5h) |
| `Connection.EnableSystemProxy` | `bool` | `false` | 自动检测系统代理 |
| `Connection.ProxyPool` | `[]string` | `nil` | 用于轮换的代理 URL（见[代理配置](#代理配置)） |
| `Connection.ProxyPoolStrategy` | `ProxyStrategy` | `ProxyStrategyRoundRobin` | 代理选择算法（`ProxyStrategyRoundRobin` 或 `ProxyStrategyRandom`） |
| `Connection.ProxyFailureThreshold` | `int` | `3` | 触发熔断前的连续连接失败次数 |
| `Connection.ProxyCooldown` | `time.Duration` | `30s` | 被熔断的代理退出轮换的时长 |
| `Connection.ProxyRotateOnStatus` | `[]int` | `nil` | 触发代理轮换的 HTTP 状态码（如 `[]int{403}`） |
| `Connection.EnableHTTP2` | `bool` | `true` | 启用 HTTP/2 |
| `Connection.EnableCookies` | `bool` | `false` | 启用 Cookie Jar |
| `Connection.EnableDoH` | `bool` | `false` | 启用 DNS-over-HTTPS |
| `Connection.DoHCacheTTL` | `time.Duration` | `5m` | DoH 缓存时长 |
| `Connection.MaxResponseHeaderBytes` | `int64` | `0` | 最大响应头大小 (0 = Go 标准库默认 10MB) |
| **安全设置** (`Security`) ||||
| `Security.TLSConfig` | `*tls.Config` | `nil` | 自定义 TLS 配置 |
| `Security.MinTLSVersion` | `uint16` | `TLS 1.2` | 最低 TLS 版本 |
| `Security.MaxTLSVersion` | `uint16` | `TLS 1.3` | 最高 TLS 版本 |
| `Security.InsecureSkipVerify` | `bool` | `false` | 跳过 TLS 验证 (仅限测试！) |
| `Security.CertificatePinner` | `CertificatePinner` | `nil` | 证书固定 — 即使 CA 被攻破也拒绝 MITM |
| `Security.MaxResponseBodySize` | `int64` | `10MB` | 最大响应体大小 |
| `Security.MaxRequestBodySize` | `int64` | `0` | 最大请求体大小 (0 = 不限制；不会回退到 MaxResponseBodySize) |
| `Security.AllowPrivateIPs` | `bool` | `false` | 允许私有 IP (默认启用 SSRF 防护) |
| `Security.ValidateURL` | `bool` | `true` | 启用 URL 验证 |
| `Security.ValidateHeaders` | `bool` | `true` | 启用请求头验证 |
| `Security.StrictContentLength` | `bool` | `true` | 严格 Content-Length 检查 |
| `Security.RedirectWhitelist` | `[]string` | `nil` | 允许的重定向域名 |
| `Security.MaxDecompressedBodySize` | `int64` | `100MB` | 最大解压响应体大小 (Zip 炸弹防护) |
| `Security.SSRFExemptCIDRs` | `[]string` | `nil` | 豁免 SSRF 阻断的 CIDR 范围 |
| `Security.CookieSecurity` | `*CookieSecurityConfig` | `nil` | Cookie 安全验证规则 |
| **重试设置** (`Retry`) ||||
| `Retry.MaxRetries` | `int` | `3` | 最大重试次数 |
| `Retry.Delay` | `time.Duration` | `1s` | 初始重试延迟 |
| `Retry.BackoffFactor` | `float64` | `2.0` | 退避乘数 |
| `Retry.EnableJitter` | `bool` | `true` | 重试添加抖动 |
| `Retry.MaxRetryDelay` | `time.Duration` | `30s` | 最大重试延迟上限 |
| `Retry.CustomPolicy` | `RetryPolicy` | `nil` | 自定义重试逻辑 |
| **中间件设置** (`Middleware: httpc.MiddlewareConfig{...}`) ||||
| `Middleware.Middlewares` | `[]MiddlewareFunc` | `nil` | 中间件链 |
| **默认设置** (`Defaults: httpc.RequestDefaults{...}`) ||||
| `Defaults.UserAgent` | `string` | `"httpc/1.0"` | 默认 User-Agent |
| `Defaults.Headers` | `map[string]string` | `{}` | 默认请求头 |
| `Defaults.FollowRedirects` | `bool` | `true` | 跟随重定向 |
| `Defaults.MaxRedirects` | `int` | `10` | 最大重定向次数 |

---

## 中间件

每个可配置中间件遵循相同模式：`XxxConfig` 结构体、`DefaultXxxConfig()`
构造函数，以及 `XxxMiddleware(cfg)` 工厂函数。传入 `nil` 使用默认值。

### 内置中间件

```go
// 请求日志
httpc.LoggingMiddleware(&httpc.LoggingConfig{LogFunc: log.Printf})

// Panic 恢复（无需配置）
httpc.RecoveryMiddleware()

// 请求 ID（nil 配置 = 默认值："X-Request-ID" 头，crypto/rand 生成器）
httpc.RequestIDMiddleware(&httpc.RequestIDConfig{HeaderName: "X-Request-ID"})

// 超时强制执行
httpc.TimeoutMiddleware(&httpc.TimeoutMiddlewareConfig{Duration: 30 * time.Second})

// 静态请求头
httpc.HeaderMiddleware(&httpc.HeaderConfig{
    Headers: map[string]string{"X-App-Version": "1.0.0"},
})

// 指标收集
httpc.MetricsMiddleware(&httpc.MetricsConfig{
    OnMetrics: func(method, url string, statusCode int, duration time.Duration, err error) {
        metrics.Record(method, url, statusCode, duration)
    },
})

// 安全审计
auditCfg := httpc.DefaultAuditConfig()
auditCfg.OnAudit = func(a httpc.AuditEvent) {
    log.Printf("[AUDIT] %s %s -> %d (%v)", a.Method, a.URL, a.StatusCode, a.Duration)
}
httpc.AuditMiddleware(auditCfg)

// 带自定义配置的审计（JSON 格式，包含请求头）
auditCfgJSON := httpc.DefaultAuditConfig()
auditCfgJSON.OnAudit = func(a httpc.AuditEvent) { log.Printf("[AUDIT] %v", a) }
auditCfgJSON.IncludeHeaders = true
auditCfgJSON.Format = "json"
httpc.AuditMiddleware(auditCfgJSON)
```

### AuditEvent 字段

| 字段 | 类型 | 描述 |
|------|------|------|
| `Timestamp` | `time.Time` | 请求时间戳 |
| `Method` | `string` | HTTP 方法 |
| `URL` | `string` | 请求 URL |
| `StatusCode` | `int` | 响应状态码 |
| `Duration` | `time.Duration` | 请求耗时 |
| `Attempts` | `int` | 重试次数 |
| `Error` | `error` | 错误信息 |
| `SourceIP` | `string` | 来源 IP (通过上下文键 `SourceIPKey` 设置) |
| `UserID` | `string` | 用户 ID (通过上下文键 `UserIDKey` 设置) |
| `RedirectChain` | `[]string` | 重定向 URL 链 |
| `ReqHeaders` | `map[string][]string` | 请求头 (当 `IncludeHeaders: true` 时) |
| `RespHeaders` | `map[string][]string` | 响应头 (当 `IncludeHeaders: true` 时) |

`AuditEvent` 支持通过 `MarshalJSON()` 进行 JSON 序列化。

### 链式中间件

```go
chainedMiddleware := httpc.Chain(
    httpc.RecoveryMiddleware(),
    httpc.LoggingMiddleware(&httpc.LoggingConfig{LogFunc: log.Printf}),
    httpc.RequestIDMiddleware(nil),
    httpc.HeaderMiddleware(&httpc.HeaderConfig{Headers: map[string]string{"X-App": "v1"}}),
)
config.Middleware.Middlewares = []httpc.MiddlewareFunc{chainedMiddleware}
```

### 自定义中间件

```go
func CustomMiddleware() httpc.MiddlewareFunc {
    return func(next httpc.Handler) httpc.Handler {
        return func(ctx context.Context, req httpc.RequestMutator) (httpc.ResponseMutator, error) {
            // 请求发送前
            req.SetHeader("X-Custom", "value")

            // 调用下一个处理器
            resp, err := next(ctx, req)

            // 响应接收后
            return resp, err
        }
    }
}
```

---

## 代理配置

```go
// 手动代理
config := httpc.DefaultConfig()
config.Connection.ProxyURL = "http://127.0.0.1:8080"
// 或 HTTPS 代理: "https://proxy.example.com:8443"

// 系统代理自动检测 (Windows/macOS/Linux)
config := httpc.DefaultConfig()
config.Connection.EnableSystemProxy = true  // 从环境变量和系统设置读取
```

### 代理池（轮换 + 熔断）

在多个代理之间分发请求，支持自动故障转移和基于状态码的轮换：

```go
config := httpc.DefaultConfig()
config.Connection.ProxyPool = []string{
    "http://proxy1.example.com:7070",
    "http://proxy2.example.com:8080",
    "socks5://proxy3.example.com:1080",
}
// 策略：ProxyStrategyRoundRobin（默认）或 ProxyStrategyRandom
config.Connection.ProxyPoolStrategy = httpc.ProxyStrategyRoundRobin

// 熔断：连续 5 次连接失败后跳过该代理 60 秒，然后重试（半开探测）。
// 默认值：阈值=3，冷却=30s。
config.Connection.ProxyFailureThreshold = 5
config.Connection.ProxyCooldown = 60 * time.Second

// 遇到 403 时轮换代理（Cloudflare/WAF IP 封锁）。请求会通过不同的代理 IP 重试。
// 需要 Retry.MaxRetries > 0。
// 与连接失败不同，基于状态码的轮换不会触发熔断——封锁通常是目标相关的。
config.Connection.ProxyRotateOnStatus = []int{403}
config.Retry.MaxRetries = 3
```

**优先级：** `ProxyURL` > `ProxyPool` > `EnableSystemProxy` > 直连。

---

## 安全特性

| 特性 | 描述 |
|------|------|
| **TLS 1.2+** | 默认使用现代加密标准 |
| **证书固定** | 即使 CA 被攻破也能防御中间人攻击 (MITM) |
| **SSRF 防护** | 双层 DNS 验证阻断私有 IP |
| **CRLF 注入防护** | 请求头和 URL 验证 |
| **路径遍历防护** | 安全的文件操作 |
| **域名白名单** | 限制重定向到允许的域名 |
| **响应大小限制** | 可配置限制，防止内存耗尽 |

### 重定向域名白名单

```go
config := httpc.DefaultConfig()
config.Security.RedirectWhitelist = []string{"api.example.com", "secure.example.com"}
```

### SSRF 防护

默认情况下，`AllowPrivateIPs` 为 `false`（SSRF 防护已启用），阻止连接到私有/保留 IP 地址。仅在连接内部服务时设为 `true`：

```go
// SSRF 防护默认已启用
client, _ := httpc.New(httpc.DefaultConfig())

// 允许私有 IP 用于内部服务访问
cfg := httpc.DefaultConfig()
cfg.Security.AllowPrivateIPs = true
client, _ := httpc.New(cfg)

// 或豁免特定 CIDR 范围（如 VPN/VPC）
cfg := httpc.DefaultConfig()
cfg.Security.SSRFExemptCIDRs = []string{"10.0.0.0/8", "100.64.0.0/10"}
client, _ := httpc.New(cfg)
```

如果只需对单个受信任的内部地址发起调用，而不想放宽整个客户端的安全策略，
可使用单次请求的 `WithAllowPrivateIPs` 选项（仅对该次请求覆盖客户端的 SSRF 策略）：

```go
// 默认客户端会阻断私有 IP；此处仅对这一次请求放行
result, err := httpc.Get("http://localhost:8080/health",
    httpc.WithAllowPrivateIPs(true),
)
```

### 证书固定

证书固定 (Certificate Pinning) 即使在受信任的证书颁发机构 (CA) 被攻破时也能防御中间人攻击：除非服务器提供已固定的公钥，否则 TLS 握手将被拒绝。通过将 `CertificatePinner` 赋值给 `Security.CertificatePinner` 来启用。

```go
// 按 SubjectPublicKeyInfo (SPKI) 的 base64 编码 SHA-256 哈希固定。
// 提供多个哈希以支持密钥轮换（任一匹配即通过）。
pinner, err := httpc.NewSPKIHashPinner(
    "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2fuihg=", // 当前密钥
    "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=", // 备用密钥（轮换）
)
if err != nil {
    log.Fatal(err)
}

cfg := httpc.DefaultConfig()
cfg.Security.CertificatePinner = pinner
client, err := httpc.New(cfg)
```

从证书生成 SPKI 哈希：

```bash
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl enc -base64
```

| 函数 | 描述 |
|------|------|
| `NewSPKIHashPinner(hashes ...string)` | 按 base64 SHA-256 SPKI 哈希固定（推荐；HPKP 格式） |
| `NewPublicKeyPinner(publicKeys ...[]byte)` | 按 DER 编码 PKIX 公钥固定 |
| `NewCertificatePinnerChain(pinners ...CertificatePinner)` | 组合多个固定器（任一匹配即通过） |

### 安全警告输出

默认情况下，使用不安全配置（如 `TestingConfig()`、`InsecureSkipVerify: true`）时会在 stderr 打印安全警告。可重定向或抑制这些警告：

```go
// 抑制安全警告 (如 CI 环境)
httpc.SetSecurityWarnOutput(io.Discard)

// 或重定向到自定义日志
httpc.SetSecurityWarnOutput(os.Stderr)
```

---

## 错误处理

```go
result, err := httpc.Get(url)
if err != nil {
    var clientErr *httpc.ClientError
    if errors.As(err, &clientErr) {
        fmt.Printf("错误: %s (代码: %s)\n", clientErr.Message, clientErr.Code())
        fmt.Printf("可重试: %v\n", clientErr.IsRetryable())
    }
    return err
}

// 检查响应状态
if !result.IsSuccess() {
    return fmt.Errorf("意外的状态码: %d", result.StatusCode())
}
```

### ClientError 字段

| 字段 | 类型 | 描述 |
|------|------|------|
| `Type` | `ErrorType` | 错误分类 |
| `Message` | `string` | 可读的错误描述 |
| `Cause` | `error` | 底层错误 (可用 `%w` 解包) |
| `URL` | `string` | 请求 URL |
| `Method` | `string` | HTTP 方法 |
| `Attempts` | `int` | 重试次数 |
| `StatusCode` | `int` | HTTP 状态码 (如适用) |
| `Host` | `string` | 目标主机 |

### 错误类型

```go
const (
    ErrorTypeUnknown        // 未知或未分类错误
    ErrorTypeNetwork        // 网络级错误 (连接被拒绝, DNS 失败)
    ErrorTypeTimeout        // 请求超时
    ErrorTypeContextCanceled // Context 被取消
    ErrorTypeResponseRead   // 读取响应体错误
    ErrorTypeTransport      // HTTP 传输错误
    ErrorTypeRetryExhausted // 所有重试已耗尽
    ErrorTypeTLS            // TLS 握手错误
    ErrorTypeCertificate    // 证书验证错误
    ErrorTypeDNS            // DNS 解析错误
    ErrorTypeValidation     // 请求验证错误
    ErrorTypeHTTP           // HTTP 级错误 (4xx, 5xx)
)
```

### 哨兵错误

```go
var (
    ErrClientClosed         // 客户端已关闭
    ErrNilConfig            // 提供了 nil 配置
    ErrInvalidHeader        // 请求头验证失败
    ErrInvalidTimeout       // 超时为负数或超出限制
    ErrInvalidRetry         // 重试配置无效
    ErrInvalidConnection    // 连接配置无效
    ErrInvalidSecurity      // 安全配置无效
    ErrInvalidMiddleware    // 中间件配置无效
    ErrEmptyFilePath        // 文件路径为空
    ErrFileExists           // 文件已存在 (且 Overwrite 为 false)
    ErrResponseBodyEmpty    // 响应体为空
    ErrResponseBodyTooLarge // 响应体超过大小限制
)
```

### 错误分类

```go
// 使用 errors.As 检查错误类型
var clientErr *httpc.ClientError
if errors.As(err, &clientErr) {
    fmt.Printf("类型: %s, 可重试: %v\n", clientErr.Code(), clientErr.IsRetryable())
}
```

---

## 并发安全

HTTPC 设计为 goroutine 安全：

```go
client, _ := httpc.NewDefault() // 默认配置
defer client.Close()

var wg sync.WaitGroup
for i := 0; i < 100; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        result, _ := client.Get("https://api.example.com")
        // 处理响应...
    }()
}
wg.Wait()
```

### 默认客户端管理

包级函数 (`Get`, `Post` 等) 使用共享的默认客户端，你可以自定义它：

```go
// 设置自定义默认客户端
customClient, _ := httpc.New(httpc.SecureConfig())
_ = httpc.SetDefaultClient(customClient)

// 关闭并重置默认客户端
_ = httpc.CloseDefaultClient()
```

**线程安全保证：**
- 所有 `Client` 方法均可安全并发使用
- 包级函数安全使用共享的默认客户端
- `Result` 对象不支持并发访问 — 每个 goroutine 应使用各自的 `Result`
- 内部指标使用原子操作

---

## 接口

HTTPC 暴露接口用于测试和扩展。在需要 Mock HTTP 调用时使用这些接口：

### Doer

最简接口 — 仅包含 `Request` 方法：

```go
type Doer interface {
    Request(ctx context.Context, method, url string, options ...RequestOption) (*Result, error)
}
```

### Client

完整客户端接口 — 扩展 `Doer`，提供便捷方法和下载支持：

```go
type Client interface {
    Doer
    Get(url string, options ...RequestOption) (*Result, error)
    Post(url string, options ...RequestOption) (*Result, error)
    Put(url string, options ...RequestOption) (*Result, error)
    Patch(url string, options ...RequestOption) (*Result, error)
    Delete(url string, options ...RequestOption) (*Result, error)
    Head(url string, options ...RequestOption) (*Result, error)
    Options(url string, options ...RequestOption) (*Result, error)
    Download(ctx context.Context, url string, cfg *DownloadConfig, options ...RequestOption) (*DownloadResult, error)
    Close() error
}
```

### DomainClienter

扩展 `Client`，增加域级会话管理：

```go
type DomainClienter interface {
    Client
    URL() string
    Domain() string
    SetHeader(key, value string) error
    SetHeaders(headers map[string]string) error
    DeleteHeader(key string)
    ClearHeaders()
    GetHeaders() map[string]string
    SetCookie(cookie *http.Cookie) error
    SetCookies(cookies []*http.Cookie) error
    DeleteCookie(name string)
    ClearCookies()
    GetCookies() []*http.Cookie
    GetCookie(name string) *http.Cookie
    Session() *SessionManager
}
```

### 测试中使用

```go
type MockClient struct {
    httpc.Client // 嵌入以保持前向兼容性
}

func (m *MockClient) Get(url string, options ...httpc.RequestOption) (*httpc.Result, error) {
    return &httpc.Result{
        Response: &httpc.ResponseInfo{StatusCode: 200, Body: `{"ok": true}`},
    }, nil
}
```

---

## 文档

| 资源 | 描述 |
|------|------|
| [入门指南](docs/01_getting-started.md) | 安装和第一步 |
| [配置](docs/02_configuration.md) | 客户端配置和预设 |
| [请求选项](docs/03_request-options.md) | 完整选项参考 |
| [错误处理](docs/04_error-handling.md) | 错误处理模式 |
| [HTTP 重定向](docs/05_redirects.md) | 重定向处理和跟踪 |
| [Cookie API](docs/06_cookie-api.md) | Cookie 管理 |
| [文件下载](docs/07_file-download.md) | 带进度的文件下载 |
| [请求检查](docs/08_request-inspection.md) | 请求/响应检查 |
| [并发安全](docs/09_concurrency-safety.md) | 线程安全保证 |
| [安全](SECURITY.md) | 安全特性和最佳实践 |

### 示例代码

21 个可运行的示例覆盖所有功能，按从基础到高级排序。
每个示例都是独立的 `package main`，并带有 `//go:build examples` 构建标签（因此不会进入常规构建），需逐个运行：

```bash
go run examples/01_basic_usage.go
```

> 调用真实端点（`httpbin.org`、`example.com`）的示例需要网络访问。
> 证书固定和 SSRF 防护示例是自包含的 — 被拒绝*正是*防护按预期工作的体现。

| 类别 | 示例 |
|------|------|
| **基础** | [01_basic_usage](examples/01_basic_usage.go), [02_http_methods](examples/02_http_methods.go), [03_response_handling](examples/03_response_handling.go), [04_compression](examples/04_compression.go) |
| **核心功能** | [05_request_options](examples/05_request_options.go), [06_error_handling](examples/06_error_handling.go), [07_timeout_retry](examples/07_timeout_retry.go), [08_client_configuration](examples/08_client_configuration.go), [09_redirects](examples/09_redirects.go), [10_cookies_advanced](examples/10_cookies_advanced.go) |
| **有状态客户端** | [11_session](examples/11_session.go), [12_domain_client](examples/12_domain_client.go), [13_proxy_configuration](examples/13_proxy_configuration.go), [14_doh](examples/14_doh.go) |
| **高级** | [15_middleware](examples/15_middleware.go), [16_concurrent_requests](examples/16_concurrent_requests.go), [17_file_operations](examples/17_file_operations.go), [18_rest_api_client](examples/18_rest_api_client.go), [19_advanced_patterns](examples/19_advanced_patterns.go) |
| **安全** | [20_certificate_pinning](examples/20_certificate_pinning.go), [21_ssrf_protection](examples/21_ssrf_protection.go) |

---

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件。

---

如果这个项目对你有帮助，请给一个 Star！
