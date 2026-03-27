import type * as Types from '@app/Types.ts'

/**
 * Context analysis service.
 * @description Detects XSS injection contexts.
 */
export class ContextService {
  /**
   * Analyze injection context.
   * @description Determines XSS context type for payload.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Context analysis result
   */
  analyzeInjectionContext(responseText: string, payload: string): Types.ContextResult {
    const lowerCaseResponse = responseText.toLowerCase()
    const payloadLower = payload.toLowerCase()
    const templateContextResult = this.detectTemplateContext(lowerCaseResponse, payloadLower)
    if (templateContextResult.confidence > 0.8) {
      return templateContextResult
    }
    const cssContextResult = this.detectCssContext(lowerCaseResponse, payloadLower)
    if (cssContextResult.confidence > 0.8) {
      return cssContextResult
    }
    const cspContextResult = this.detectCspBypassContext(lowerCaseResponse, payloadLower)
    if (cspContextResult.confidence > 0.8) {
      return cspContextResult
    }
    const domClobberContextResult = this.detectDomClobberingContext(lowerCaseResponse, payloadLower)
    if (domClobberContextResult.confidence > 0.8) {
      return domClobberContextResult
    }
    const jsContextResult = this.detectJavaScriptContext(lowerCaseResponse, payloadLower)
    if (jsContextResult.confidence > 0.8) {
      return jsContextResult
    }
    const attrContextResult = this.detectAttributeContext(lowerCaseResponse, payloadLower)
    if (attrContextResult.confidence > 0.8) {
      return attrContextResult
    }
    const domContextResult = this.detectDomContext(lowerCaseResponse, payloadLower)
    if (domContextResult.confidence > 0.8) {
      return domContextResult
    }
    return {
      context: 'html',
      confidence: 0.5,
      details: ['Default HTML context']
    }
  }

  /**
   * Analyze context statically.
   * @description Static method for context analysis.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Context analysis result
   */
  static analyzeContext(responseText: string, payload: string): Types.ContextResult {
    const contextAnalyzer = new ContextService()
    const contextResult = contextAnalyzer.analyzeInjectionContext(responseText, payload)
    return contextResult
  }

  /**
   * Validate context type.
   * @description Checks if context is valid XSS context.
   * @param context - Context type string
   * @returns True if context is valid
   */
  isValidContext(context: Types.XssContext): boolean {
    const validContexts: Types.XssContext[] = [
      'html',
      'javascript',
      'attribute',
      'dom',
      'template',
      'css',
      'csp-bypass',
      'dom-clobbering'
    ]
    return validContexts.includes(context)
  }

  /**
   * Detect attribute context.
   * @description Finds HTML attribute injection contexts.
   * @param responseText - HTML response content
   * @param payloadLower - Lowercase payload string
   * @returns Attribute context result
   */
  private detectAttributeContext(responseText: string, payloadLower: string): Types.ContextResult {
    const attrIndicators = [
      'onerror=',
      'onclick=',
      'onload=',
      'onmouseover=',
      'onfocus=',
      'href=',
      'src=',
      'action=',
      'value='
    ]
    const foundIndicators = attrIndicators.filter((indicator) => responseText.includes(indicator))
    const hasPayload = foundIndicators.some(
      (indicator) => responseText.includes(payloadLower) && responseText.includes(indicator)
    )
    return {
      context: 'attribute',
      confidence: hasPayload
        ? Math.min(foundIndicators.length / attrIndicators.length + 0.2, 1.0)
        : foundIndicators.length / attrIndicators.length,
      details: foundIndicators
    }
  }

  /**
   * Detect CSP bypass context.
   * @description Finds Content Security Policy bypass contexts.
   * @param responseText - HTML response content
   * @param payloadLower - Lowercase payload string
   * @returns CSP bypass context result
   */
  private detectCspBypassContext(responseText: string, payloadLower: string): Types.ContextResult {
    const cspIndicators = ['content-security-policy', 'script-src', 'unsafe-inline', 'unsafe-eval']
    const foundIndicators = cspIndicators.filter((indicator) => responseText.includes(indicator))
    const hasPayload = foundIndicators.some(
      (indicator) => responseText.includes(payloadLower) && responseText.includes(indicator)
    )
    return {
      context: 'csp-bypass',
      confidence: hasPayload
        ? Math.min(foundIndicators.length / cspIndicators.length + 0.2, 1.0)
        : foundIndicators.length / cspIndicators.length,
      details: foundIndicators
    }
  }

  /**
   * Detect CSS context.
   * @description Finds CSS injection contexts.
   * @param responseText - HTML response content
   * @param payloadLower - Lowercase payload string
   * @returns CSS context result
   */
  private detectCssContext(responseText: string, payloadLower: string): Types.ContextResult {
    const cssIndicators = ['@keyframes', 'animation-', 'onanimation', 'style=', 'css']
    const foundIndicators = cssIndicators.filter((indicator) => responseText.includes(indicator))
    const hasPayload = foundIndicators.some(
      (indicator) => responseText.includes(payloadLower) && responseText.includes(indicator)
    )
    return {
      context: 'css',
      confidence: hasPayload
        ? Math.min(foundIndicators.length / cssIndicators.length + 0.2, 1.0)
        : foundIndicators.length / cssIndicators.length,
      details: foundIndicators
    }
  }

  /**
   * Detect DOM clobbering context.
   * @description Finds DOM clobbering injection contexts.
   * @param responseText - HTML response content
   * @param payloadLower - Lowercase payload string
   * @returns DOM clobbering context result
   */
  private detectDomClobberingContext(
    responseText: string,
    payloadLower: string
  ): Types.ContextResult {
    const clobberIndicators = [
      'id="location"',
      'id="document"',
      'id="window"',
      'id="creatorelement"'
    ]
    const foundIndicators = clobberIndicators.filter((indicator) =>
      responseText.includes(indicator)
    )
    const hasPayload = foundIndicators.some(
      (indicator) => responseText.includes(payloadLower) && responseText.includes(indicator)
    )
    return {
      context: 'dom-clobbering',
      confidence: hasPayload
        ? Math.min(foundIndicators.length / clobberIndicators.length + 0.2, 1.0)
        : foundIndicators.length / clobberIndicators.length,
      details: foundIndicators
    }
  }

  /**
   * Detect DOM context.
   * @description Finds DOM manipulation injection contexts.
   * @param responseText - HTML response content
   * @param payloadLower - Lowercase payload string
   * @returns DOM context result
   */
  private detectDomContext(responseText: string, payloadLower: string): Types.ContextResult {
    const domIndicators = [
      'document.',
      'window.',
      'location.',
      'innerhtml',
      'appendchild',
      'createelement',
      'queryselector',
      'addeventlistener'
    ]
    const foundIndicators = domIndicators.filter((indicator) => responseText.includes(indicator))
    const hasPayload = foundIndicators.some(
      (indicator) => responseText.includes(payloadLower) && responseText.includes(indicator)
    )
    return {
      context: 'dom',
      confidence: hasPayload
        ? Math.min(foundIndicators.length / domIndicators.length + 0.2, 1.0)
        : foundIndicators.length / domIndicators.length,
      details: foundIndicators
    }
  }

  /**
   * Detect JavaScript context.
   * @description Finds JavaScript injection contexts.
   * @param responseText - HTML response content
   * @param payloadLower - Lowercase payload string
   * @returns JavaScript context result
   */
  private detectJavaScriptContext(responseText: string, payloadLower: string): Types.ContextResult {
    const jsIndicators = [
      'javascript:',
      'alert(',
      'confirm(',
      'prompt(',
      'eval(',
      'constructor(',
      'function(',
      'var ',
      'let ',
      'const '
    ]
    const foundIndicators = jsIndicators.filter((indicator) => responseText.includes(indicator))
    const hasPayload = foundIndicators.some(
      (indicator) => responseText.includes(payloadLower) && responseText.includes(indicator)
    )
    return {
      context: 'javascript',
      confidence: hasPayload
        ? Math.min(foundIndicators.length / jsIndicators.length + 0.2, 1.0)
        : foundIndicators.length / jsIndicators.length,
      details: foundIndicators
    }
  }

  /**
   * Detect template context.
   * @description Finds template engine injection contexts.
   * @param responseText - HTML response content
   * @param payloadLower - Lowercase payload string
   * @returns Template context result
   */
  private detectTemplateContext(responseText: string, payloadLower: string): Types.ContextResult {
    const templateIndicators = ['{{', '${', 'ng-', 'v-', '%7b%7b']
    const foundIndicators = templateIndicators.filter((indicator) =>
      responseText.includes(indicator)
    )
    const hasPayload = foundIndicators.some(
      (indicator) => responseText.includes(payloadLower) && responseText.includes(indicator)
    )
    return {
      context: 'template',
      confidence: hasPayload
        ? Math.min(foundIndicators.length / templateIndicators.length + 0.2, 1.0)
        : foundIndicators.length / templateIndicators.length,
      details: foundIndicators
    }
  }
}
