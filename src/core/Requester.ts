import type * as Types from '@app/Types.ts'
import * as Core from '@core/index.ts'

/**
 * Core HTTP request handler.
 * @description Manages HTTP requests for XSS tests.
 */
export class CoreRequester {
  /**
   * Build test URL.
   * @description Creates URL with payload injection.
   * @param baseUrl - Target base URL
   * @param payload - XSS payload to inject
   * @param config - Scan configuration
   * @param targetParam - Target parameter name
   * @returns Modified test URL
   */
  static buildTestUrl(
    baseUrl: string,
    payload: string,
    config: Types.ScanConfig,
    targetParam?: string
  ): string {
    const url = new URL(baseUrl)
    if (this.isPathBased(url)) {
      return this.buildPathBasedUrl(url, payload, config)
    }
    return this.buildQueryParamUrl(url, payload, targetParam)
  }

  /**
   * Extract URL parameters.
   * @description Gets parameter names from target URL.
   * @param url - URL to analyze
   * @returns Array of parameter names
   */
  static extractParameters(url: string): string[] {
    try {
      const urlObj = new URL(url)
      const queryParams = Array.from(urlObj.searchParams.keys())
      if (this.isPathBased(urlObj)) {
        return ['path']
      }
      return queryParams.length > 0 ? queryParams : ['path']
    } catch {
      return this.extractFromMalformedUrl(url)
    }
  }

  /**
   * Parse forms from HTML.
   * @description Extracts form elements from HTML response.
   * @param html - HTML content string
   * @returns Array of parsed form objects
   */
  static parseForms(html: string): Types.ParsedForm[] {
    return Core.CoreAnalyzer.extractForms(html)
  }

  /**
   * Send GET request.
   * @description Performs GET request with injected payload.
   * @param url - Target URL
   * @param payload - XSS payload
   * @param config - Scan configuration
   * @param param - Target parameter
   * @returns HTTP response object
   */
  static async sendGET(
    url: string,
    payload: string,
    config: Types.ScanConfig,
    param: string
  ): Promise<Response> {
    const testUrl = this.buildTestUrl(url, payload, config, param)
    const response = await fetch(testUrl, {
      method: 'GET',
      headers: config.headers || {},
      credentials: 'include'
    })
    return response
  }

  /**
   * Send POST request.
   * @description Performs POST request with encoded data.
   * @param url - Target URL
   * @param data - Form data string
   * @param config - Scan configuration
   * @returns HTTP response object
   */
  static async sendPOST(url: string, data: string, config: Types.ScanConfig): Promise<Response> {
    const response = await fetch(url, {
      method: 'POST',
      headers: config.headers || {},
      body: data,
      credentials: 'include'
    })
    return response
  }

  /**
   * Build path-based URL.
   * @description Creates URL with injected path payload.
   * @param url - Parsed URL object
   * @param payload - XSS payload
   * @param config - Scan configuration
   * @returns Modified URL string
   */
  private static buildPathBasedUrl(url: URL, payload: string, config: Types.ScanConfig): string {
    const path = url.pathname.replace(/[:{}].*?(?=\/|$)/g, payload)
    url.pathname = path
    if (config.delay && config.delay > 0) {
      url.searchParams.set('delay', config.delay.toString())
    }
    return url.toString()
  }

  /**
   * Build query param URL.
   * @description Creates URL with injected query parameter.
   * @param url - Parsed URL object
   * @param payload - XSS payload
   * @param targetParam - Target parameter name
   * @returns Modified URL string
   */
  private static buildQueryParamUrl(url: URL, payload: string, targetParam?: string): string {
    const param = targetParam || 'xss'
    url.searchParams.set(param, payload)
    return url.toString()
  }

  /**
   * Extract from malformed URL.
   * @description Parses parameters from invalid URL strings.
   * @param url - Malformed URL string
   * @returns Array of parameter names
   */
  private static extractFromMalformedUrl(url: string): string[] {
    const match = url.match(/\?([^#]+)/)
    if (match && match[1]) {
      return match[1]
        .split('&')
        .map((param) => param.split('=')[0])
        .filter((p): p is string => p !== undefined)
    }
    return []
  }

  /**
   * Check if URL is path-based.
   * @description Determines if injection uses path parameters.
   * @param url - Parsed URL object
   * @returns True if path-based injection
   */
  private static isPathBased(url: URL): boolean {
    return url.pathname.includes(':') || url.pathname.includes('{')
  }
}
