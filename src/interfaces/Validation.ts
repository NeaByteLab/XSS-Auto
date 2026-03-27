import type * as Types from '@interfaces/index.ts'

/**
 * Batch test case data.
 * @description Individual batch scan test case definition.
 */
export interface BatchTestCase {
  /** Target URL */
  url: string
  /** HTTP method */
  method: string
  /** Parameter to test */
  parameter?: string
}

/**
 * Encoding variation data.
 * @description Payload encoding variation definition.
 */
export interface EncodingVariation {
  /** Encoding type used */
  type: Types.EncodingType
  /** Encoded payload value */
  value: string
  /** Variation description */
  description: string
}

/**
 * Scan summary statistics.
 * @description XSS scan results summary statistics.
 */
export interface ScanSummary {
  /** Total tests run */
  total: number
  /** Vulnerabilities found */
  vulnerable: number
  /** High severity count */
  high: number
  /** Medium severity count */
  medium: number
  /** Low severity count */
  low: number
  /** Contexts discovered */
  contexts: Record<string, number>
  /** Vectors successful */
  vectors: Record<string, number>
}

/**
 * Scan summary stats.
 * @description XSS scan results summary stats.
 */
export interface ScanSummaryStats {
  /** Total tests run */
  total: number
  /** Vulnerabilities found */
  vulnerable: number
  /** High severity count */
  high: number
  /** Medium severity count */
  medium: number
  /** Low severity count */
  low: number
  /** Contexts discovered */
  contexts: Record<string, number>
  /** Vectors successful */
  vectors: Record<string, number>
}
