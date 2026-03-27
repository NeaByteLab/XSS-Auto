import type * as Types from '@interfaces/index.ts'

/**
 * XSS Scanner public options.
 * @description Configuration for XSS scanning operation.
 */
export interface XssScanOptions {
  /** HTTP method (auto-detected if body provided) */
  method?: 'GET' | 'POST'
  /** Request body for POST/PUT requests */
  body?: Record<string, unknown> | string
  /** Custom HTTP headers */
  headers?: Record<string, string>
  /** Payload categories to test */
  vectors?: Types.PayloadCategory[]
  /** Delay between requests (ms) */
  delay?: number
  /** Specific parameters to test (GET only) */
  parameters?: string[]
  /** Stop after first confirmed XSS */
  useFirst?: boolean
  /** Enable/disable confirmation dialogs */
  useInteractive?: boolean
}
