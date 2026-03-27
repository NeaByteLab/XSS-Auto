import type * as Types from '@app/Types.ts'
import * as Core from '@core/index.ts'
import * as Services from '@core/services/index.ts'

/**
 * Core XSS scanning engine.
 * @description Orchestrates XSS vulnerability scanning operations.
 */
export class CoreScanner {
  /**
   * Scan single URL.
   * @description Performs XSS scan on single target.
   * @param config - Scan configuration object
   * @returns Array of XSS scan results
   */
  static async scanUrl(
    config: Types.ScanConfig,
    options?: Types.ScanOptions
  ): Promise<Types.XssResult[]> {
    const payloads = Core.CorePayload.getAllPayloads(config)
    if (config.method === 'POST' || config.formData) {
      return await this.scanPost(config, payloads, options)
    } else {
      return await this.scanGet(config, payloads, options)
    }
  }

  /**
   * Scan using GET method.
   * @description Performs XSS scan via GET requests.
   * @param config - Scan configuration
   * @param payloads - Payload array to test
   * @returns Array of XSS scan results
   */
  private static async scanGet(
    config: Types.ScanConfig,
    payloads: string[],
    options?: Types.ScanOptions
  ): Promise<Types.XssResult[]> {
    const results: Types.XssResult[] = []
    const parameters = Core.CoreRequester.extractParameters(config.url)
    const targetParams = config.parameters || parameters
    for (const param of targetParams) {
      for (const payload of payloads) {
        try {
          const response = await Core.CoreRequester.sendGET(config.url, payload, config, param)
          const httpResponse = {
            url: response.url,
            status: response.status,
            headers: Object.fromEntries(response.headers.entries()),
            text: () => response.text(),
            ok: response.ok,
            redirected: response.redirected,
            statusText: response.statusText,
            body: response.body
          }
          const analyzer = new Services.ResponseService()
          const result = await analyzer.analyze(httpResponse, payload, config, param)
          if (result) {
            const method = config.method || 'GET'
            const status = result.confirmed ? '🚨 XSS Found!' : '❌ XSS Invalid!'
            const testUrl = Core.CoreRequester.buildTestUrl(config.url, payload, config, param)
            const body = config.formData
              ? Object.entries(config.formData)
                .map(([k, v]) => `${k}=${v}`)
                .join('&')
              : ''
            console.log(
              `${status} [${method.toUpperCase()}] ${testUrl} | [Payload]: ${result.payload} | [Body]: ${
                body || 'n/a'
              }`
            )
            if (result.confirmed) {
              if (options?.interactive) {
                const shouldContinue = confirm(
                  '\nValid XSS vulnerability confirmed. Continue scanning?'
                )
                if (!shouldContinue) {
                  results.push(result)
                  return results
                }
              }
              if (options?.stopOnFirst) {
                results.push(result)
                return results
              }
            }
            results.push(result)
          }
        } catch (error) {
          console.log(`❌ Error: ${error}`)
          continue
        }
      }
    }
    return results
  }

  /**
   * Scan using POST method.
   * @description Performs XSS scan via POST requests.
   * @param config - Scan configuration
   * @param payloads - Payload array to test
   * @returns Array of XSS scan results
   */
  private static async scanPost(
    config: Types.ScanConfig,
    payloads: string[],
    options?: Types.ScanOptions
  ): Promise<Types.XssResult[]> {
    const results: Types.XssResult[] = []
    const initialResponse = await Core.CoreRequester.sendGET(config.url, '', config, '')
    const responseText = await initialResponse.text()
    const forms = Core.CoreAnalyzer.extractForms(responseText)
    if (forms.length === 0) {
      console.log('❌ No forms found for POST testing')
      return results
    }
    const testData = Core.CoreAnalyzer.generateTestData(forms)
    const fieldNames = Core.CoreAnalyzer.extractFieldNames(forms)
    for (const fieldName of fieldNames) {
      for (const payload of payloads) {
        try {
          const formData = Core.CoreAnalyzer.buildFormData(testData, payload, fieldName)
          const httpResponse = await Core.CoreRequester.sendPOST(
            new URL(forms[0]?.action || config.url, config.url).toString(),
            formData,
            config
          )
          const formattedResponse = {
            url: httpResponse.url,
            status: httpResponse.status,
            headers: Object.fromEntries(httpResponse.headers.entries()),
            text: () => httpResponse.text(),
            ok: httpResponse.ok,
            redirected: httpResponse.redirected,
            statusText: httpResponse.statusText,
            body: httpResponse.body
          }
          const analyzer = new Services.ResponseService()
          const result = await analyzer.analyze(formattedResponse, payload, config, fieldName)
          if (result) {
            const method = config.method || 'POST'
            const status = result.confirmed ? '🚨 XSS Found!' : '❌ XSS Invalid!'
            const testUrl = new URL(forms[0]?.action || config.url, config.url).toString()
            console.log(
              `${status} [${method.toUpperCase()}] ${testUrl} | [Payload]: ${result.payload} | [Body]: ${formData}`
            )
            if (result.confirmed) {
              if (options?.interactive) {
                const shouldContinue = confirm(
                  '\nValid XSS vulnerability confirmed. Continue scanning?'
                )
                if (!shouldContinue) {
                  results.push(result)
                  return results
                }
              }

              if (options?.stopOnFirst) {
                results.push(result)
                return results
              }
            }
            results.push(result)
          }
          if (config.delay && config.delay > 0) {
            await new Promise((resolve) => setTimeout(resolve, config.delay))
          }
        } catch (error) {
          console.log(`❌ Error: ${error}`)
          continue
        }
      }
    }
    return results
  }
}
