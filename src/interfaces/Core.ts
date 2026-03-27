/**
 * Encoding type.
 * @description Available payload encoding method types.
 */
export type EncodingType = 'url' | 'double-url' | 'html' | 'hex' | 'unicode' | 'base64'

/**
 * HTTP method type.
 * @description Supported HTTP request method types.
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS'

/**
 * Payload category type.
 * @description XSS payload category classification types.
 */
export type PayloadCategory = 'basic' | 'advanced' | 'modern' | 'waf-bypass' | 'all'

/**
 * Scan configuration options.
 * @description Settings for XSS scanning operation.
 */
export interface ScanConfig {
  /** Target URL to scan */
  url: string
  /** HTTP method for requests */
  method?: 'GET' | 'POST'
  /** Parameters to test */
  parameters: string[]
  /** Form data for POST */
  formData?: Record<string, string>
  /** Payload categories to use */
  vectors?: PayloadCategory[]
  /** Delay between requests */
  delay?: number
  /** Custom user agent */
  userAgent?: string
  /** Additional HTTP headers */
  headers?: Record<string, string>
}

/**
 * Severity level type.
 * @description XSS vulnerability severity level types.
 */
export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical'

/**
 * XSS injection context.
 * @description Possible XSS injection context types.
 */
export type XssContext =
  | 'html'
  | 'javascript'
  | 'attribute'
  | 'dom'
  | 'template'
  | 'css'
  | 'csp-bypass'
  | 'dom-clobbering'
  | 'reflection'

/**
 * Core XSS result data.
 * @description Complete XSS vulnerability detection result.
 */
export interface XssResult {
  /** Unique result identifier */
  id: string
  /** Target URL tested */
  url: string
  /** HTTP method used */
  method: 'GET' | 'POST'
  /** Parameter name tested */
  parameter: string
  /** Payload that triggered vulnerability */
  payload: string
  /** Vector category used */
  vector: string
  /** Injection context detected */
  context: XssContext
  /** Vulnerability severity level */
  severity: SeverityLevel
  /** Whether payload was reflected */
  reflected: boolean
  /** Confirmed XSS execution */
  confirmed: boolean
  /** Evidence of vulnerability */
  evidence: string
  /** Remediation advice */
  remediation: string
  /** Confidence score 0-100 */
  confidence: number
  /** Optional risk score */
  score?: number
}
