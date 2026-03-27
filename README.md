<div align="center">

# XSS Auto

Automated XSS vulnerability discovery tool for learning security testing.

[![Deno](https://img.shields.io/badge/deno-2.5.4+-000000?logo=deno&logoColor=white)](https://deno.com) [![Learning](https://img.shields.io/badge/purpose-learning-green)](https://github.com/NeaByteLab/XSS-Auto) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

## Features

- **Auto Discovery** — Intelligent XSS vulnerability detection across multiple contexts
- **Multi-Method Support** — GET and POST request scanning with form analysis
- **Context Detection** — Identifies injection contexts (HTML, JavaScript, DOM, CSS, etc.)
- **Payload Variations** — Multiple encoding methods (URL, HTML, hex, base64, unicode)
- **Evidence Collection** — Detailed vulnerability proof with confidence scoring
- **Severity Assessment** — Risk-based vulnerability classification
- **WAF Bypass** — Advanced payload vectors for security filter evasion
- **Interactive Mode** — Real-time scanning with user feedback

## Installation

> [!NOTE]
> **Prerequisites:** [Deno](https://deno.com/) 2.5.4 or later.

```bash
# Clone and use XSS-Auto locally
git clone https://github.com/NeaByteLab/XSS-Auto.git
cd XSS-Auto
```

## Quick Start

Basic XSS scanning with automatic parameter detection.

```typescript
import XssScanner from '@neabyte/xss-auto'

// Simple URL scan
const results = await XssScanner.scan('https://example.com/search?q=test')

// Advanced configuration
const results = await XssScanner.scan('https://example.com/login', {
  method: 'POST',
  body: { username: 'test', password: 'test' },
  headers: { 'User-Agent': 'XSS-Auto/1.0' },
  delay: 1000,
  stopOnFirst: true
})

// Process results
for (const result of results) {
  console.log(`XSS found in parameter "${result.parameter}"`)
  console.log(`Payload: ${result.payload}`)
  console.log(`Severity: ${result.severity}`)
  console.log(`Evidence: ${result.evidence}`)
}
```

## Advanced Usage

### Custom Parameter Testing

```typescript
const results = await XssScanner.scan('https://example.com/search', {
  parameters: ['q', 'category', 'sort'],
  method: 'GET',
  delay: 500
})
```

### Form-Based Testing

```typescript
const results = await XssScanner.scan('https://example.com/submit', {
  method: 'POST',
  body: 'name=test&email=test@example.com&message=hello',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
})
```

### Interactive Mode

> [!NOTE]
> Interactive mode provides real-time scanning feedback and allows manual confirmation of suspected vulnerabilities.

```typescript
const results = await XssScanner.scan('https://example.com', {
  interactive: true,
  stopOnFirst: false
})
```

## Payload Categories

- **Basic** — Fundamental XSS payloads (`<script>alert(1)</script>`)
- **Advanced** — Sophisticated attack vectors with encoding
- **Bypass** — Filter evasion techniques
- **Modern** — Contemporary XSS methods (DOM-based, template injection)
- **WAF** — Web Application Firewall bypasses

## Context Detection

XSS-Auto automatically identifies injection contexts:

- **HTML** — Direct HTML injection points
- **JavaScript** — Script context injection
- **Attribute** — HTML attribute vectors
- **DOM** — Client-side DOM manipulation
- **Template** — Template engine injection
- **CSS** — Style-based XSS vectors
- **CSP Bypass** — Content Security Policy evasion
- **DOM Clobbering** — DOM property override attacks

## Result Analysis

Each scan result includes:

```typescript
interface XssResult {
  id: string // Unique identifier
  url: string // Target URL
  method: 'GET' | 'POST' // HTTP method used
  parameter: string // Vulnerable parameter
  payload: string // Successful payload
  vector: string // Payload category
  context: XssContext // Injection context
  severity: SeverityLevel // Risk assessment
  reflected: boolean // Payload reflection status
  confirmed: boolean // XSS execution confirmation
  evidence: string // Proof of vulnerability
  remediation: string // Fix recommendations
  confidence: number // Detection confidence (0-100)
}
```

## Build & Test

From the repo root (requires [Deno](https://deno.com/)).

**Check** — format, lint, and typecheck:

```bash
# Format, lint, and typecheck source
deno task check
```

**Test** — run tests (under `tests/`, uses `--allow-read` for fixtures):

```bash
# Run tests in tests/ (uses --allow-read for fixtures)
deno task test
```

**Coverage Testing** — run example test cases:

```bash
# Run coverage examples
deno run --allow-read --allow-net examples/Coverage.ts
```

## Security Considerations

> [!WARNING]
> This tool is designed for **authorized security testing only**. Always obtain proper permission before scanning any target.

- Use only on systems you own or have explicit permission to test
- Respect rate limits and avoid production disruption
- Consider the impact of automated scanning on target systems
- Follow responsible disclosure practices for discovered vulnerabilities

## Limitations

- **False Positive Detection** - Requires improvement for accurate vulnerability identification
- **Limited Auto Discovery** - Does not support advanced automatic vulnerability discovery
- **Learning Purpose Only** - Not suitable for production security assessments
- **Basic Context Analysis** - Limited injection context detection capabilities

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE) for details.
