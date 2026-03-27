import type * as Types from '@interfaces/index.ts'

/**
 * Response analyzer interface.
 * @description Analyzes HTTP responses for XSS vulnerabilities.
 */
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
    response: Types.HttpResponse,
    payload: string,
    config: Types.ScanConfig,
    testedParam?: string
  ): Promise<Types.XssResult | null>
}

/**
 * Scanner strategy interface.
 * @description Defines XSS scanning strategy implementation.
 */
export interface ScannerStrategy {
  /**
   * Execute scan strategy.
   * @description Runs XSS scan with defined strategy.
   * @param config - Scan configuration
   * @param payloads - Payloads to test
   * @returns Array of XSS results
   */
  scan(config: Types.ScanConfig, payloads: string[]): Promise<Types.XssResult[]>
}
