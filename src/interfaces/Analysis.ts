import type * as Types from '@interfaces/index.ts'

/**
 * Context analysis result.
 * @description Result of XSS context detection analysis.
 */
export interface ContextResult {
  /** Detected injection context */
  context: Types.XssContext
  /** Confidence in context detection */
  confidence: number
  /** Analysis details */
  details: string[]
}

/**
 * XSS evidence data.
 * @description Evidence of detected XSS vulnerability.
 */
export interface Evidence {
  /** Evidence match type */
  type: 'exact-match' | 'encoded-match' | 'partial-match' | 'template-injection' | 'event-handler'
  /** Evidence content */
  content: string
  /** Evidence context */
  context: string
  /** Line number if applicable */
  line?: number
  /** Evidence confidence score */
  confidence: number
}

/**
 * Form field data.
 * @description Individual HTML form field definition.
 */
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

/**
 * HTTP response data.
 * @description HTTP response object interface definition.
 */
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

/**
 * Parsed form structure.
 * @description Complete HTML form analysis result.
 */
export interface ParsedForm {
  /** Form action URL */
  action: string
  /** Form HTTP method */
  method: string
  /** Array of form fields */
  fields: FormField[]
}

/**
 * Reflection detection result.
 * @description XSS payload reflection analysis result.
 */
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

/**
 * Security headers data.
 * @description HTTP security headers found in response.
 */
export interface SecurityHeaders {
  /** Content Security Policy */
  'content-security-policy'?: string
  /** X-Content-Type-Options header */
  'x-content-type-options'?: string
  /** X-Frame-Options header */
  'x-frame-options'?: string
  /** X-XSS-Protection header */
  'x-xss-protection'?: string
  /** Strict Transport Security */
  'strict-transport-security'?: string
  /** Referrer Policy header */
  'referrer-policy'?: string
  /** Permissions Policy header */
  'permissions-policy'?: string
}
