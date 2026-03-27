import type * as Types from '@app/Types.ts'
import * as Core from '@core/index.ts'

/**
 * XSS Scanner main class.
 * @description Public API for XSS vulnerability scanning.
 */
export class XssScanner {
  /**
   * Scan single URL for XSS vulnerabilities.
   * @description Main method for XSS scanning with auto-detection.
   * @param url - Target URL or full config object
   * @param options - Scan options (optional)
   * @returns Array of XSS scan results
   */
  static async scan(url: string, options?: Types.ScanOptions): Promise<Types.XssResult[]>
  static async scan(config: { url: string } & Types.ScanOptions): Promise<Types.XssResult[]>
  static async scan(
    input: string | ({ url: string } & Types.ScanOptions),
    options?: Types.ScanOptions
  ): Promise<Types.XssResult[]> {
    const url = typeof input === 'string' ? input : input.url
    const opts = typeof input === 'string' ? options || {} : input
    const config: Types.ScanConfig = {
      url,
      method: opts.method || (opts.body ? 'POST' : 'GET'),
      parameters: opts.parameters || Core.CoreRequester.extractParameters(url),
      ...(opts.delay !== undefined && { delay: opts.delay }),
      ...(opts.headers && { headers: opts.headers })
    }
    if (opts.body && config.method === 'POST') {
      config.formData = typeof opts.body === 'string'
        ? Object.fromEntries(new URLSearchParams(opts.body))
        : Object.fromEntries(Object.entries(opts.body).map(([k, v]) => [k, String(v)]))
    }
    return await Core.CoreScanner.scanUrl(config, {
      interactive: opts.interactive ?? false,
      stopOnFirst: opts.stopOnFirst ?? true
    })
  }
}

/**
 * Default export for easy usage.
 * @description Main XSS scanner instance.
 */
export default XssScanner
