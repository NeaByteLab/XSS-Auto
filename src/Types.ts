/** XSS scanner type definitions. */
export type EvidenceType =
  | 'exact-match'
  | 'encoded-match'
  | 'partial-match'
  | 'template-injection'
  | 'event-handler'

/** Available payload encoding methods. */
export type EncodingType = 'url' | 'double-url' | 'html' | 'hex' | 'unicode' | 'base64'

/** Core scanning HTTP methods. */
export type ScanMethod = 'GET' | 'POST'

/** XSS vulnerability severity levels. */
export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical'

/** XSS injection context types. */
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

/** XSS context detection analysis result. */
export interface ContextResult {
  /** Detected injection context */
  context: XssContext
  /** Confidence in context detection */
  confidence: number
  /** Analysis details */
  details: string[]
}

/** Detected XSS vulnerability evidence. */
export interface Evidence {
  /** Evidence match type */
  type: EvidenceType
  /** Evidence content */
  content: string
  /** Evidence context */
  context: string
  /** Line number if applicable */
  line?: number
  /** Evidence confidence score */
  confidence: number
}

/** Payload encoding variation definition. */
export interface EncodingVariation {
  /** Encoding type used */
  type: EncodingType
  /** Encoded payload value */
  value: string
  /** Variation description */
  description: string
}

/** Individual HTML form field definition. */
export interface FormField {
  /** Field name attribute */
  name: string
  /** Field input type */
  type: string
  /** Field current value */
  value: string
  /** Whether field is required */
  required?: boolean
}

/** HTTP response object interface. */
export interface HttpResponse {
  /** Response URL */
  url: string
  /** HTTP status code */
  status: number
  /** Response headers */
  headers: Record<string, string>
  /** Response body text */
  text(): Promise<string>
  /** Success status */
  ok: boolean
  /** Redirect status */
  redirected: boolean
  /** Status text message */
  statusText?: string
  /** Response body stream */
  body?: ReadableStream<Uint8Array> | null
}

/** Complete HTML form analysis result. */
export interface ParsedForm {
  /** Form action URL */
  action: string
  /** Form HTTP method */
  method: string
  /** Array of form fields */
  fields: FormField[]
}

/** XSS payload reflection analysis result. */
export interface ReflectionResult {
  /** Whether payload was reflected */
  reflected: boolean
  /** Confirmed XSS execution */
  confirmed: boolean
  /** Evidence of reflection */
  evidence: string
  /** Reflection confidence score */
  confidence: number
}

/** Analyzes HTTP responses for XSS. */
export interface ResponseAnalyzer {
  /**
   * Analyze response for XSS.
   * @description Detects XSS vulnerability in HTTP response.
   * @param response - HTTP response to analyze
   * @param payload - XSS payload used
   * @param config - Scan configuration
   * @param testedParam - Parameter tested
   * @returns XSS result or null
   */
  analyze(
    response: HttpResponse,
    payload: string,
    config: ScanConfig,
    testedParam?: string
  ): Promise<XssResult | null>
}

/** XSS scanning operation configuration. */
export interface ScanConfig {
  /** Target URL to scan */
  url: string
  /** HTTP method for requests */
  method?: ScanMethod
  /** Parameters to test */
  parameters: string[]
  /** Form data for POST */
  formData?: Record<string, string>
  /** Delay between requests */
  delay?: number
  /** Custom user agent */
  userAgent?: string
  /** Additional HTTP headers */
  headers?: Record<string, string>
}

/** XSS scanning operation settings. */
export interface ScanOptions {
  /** HTTP method (auto-detected if body provided) */
  method?: ScanMethod
  /** Request body for POST/PUT requests */
  body?: Record<string, unknown> | string
  /** Custom HTTP headers */
  headers?: Record<string, string>
  /** Delay between requests (ms) */
  delay?: number
  /** Specific parameters to test (GET only) */
  parameters?: string[]
  /** Stop after first confirmed XSS */
  stopOnFirst?: boolean
  /** Enable interactive mode */
  interactive?: boolean
}

/** XSS vulnerability detection result. */
export interface XssResult {
  /** Unique result identifier */
  id: string
  /** Target URL tested */
  url: string
  /** HTTP method used */
  method: ScanMethod
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
