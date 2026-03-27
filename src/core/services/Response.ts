import type * as Types from '@interfaces/index.ts'

/**
 * Response analysis service.
 * @description Analyzes HTTP responses for XSS vulnerabilities.
 */
export class ResponseService implements Types.ResponseAnalyzer {
  /**
   * Analyze HTTP response.
   * @description Processes response for XSS detection.
   * @param response - HTTP response object
   * @param payload - Test payload string
   * @param config - Scan configuration
   * @param testedParam - Tested parameter name
   * @returns XSS analysis result or null
   */
  analyze(
    response: Types.HttpResponse,
    payload: string,
    config: Types.ScanConfig,
    testedParam?: string
  ): Promise<Types.XssResult | null> {
    try {
      return response.text().then((responseText) => {
        if (!responseText) {
          return null
        }
        let isReflected = responseText.includes(payload)
        if (!isReflected && payload.includes('\\u')) {
          try {
            const decodedPayload = payload.replace(
              /\\u([0-9a-fA-F]{4})/g,
              (_, hex) => String.fromCharCode(parseInt(hex, 16))
            )
            isReflected = responseText.includes(decodedPayload)
          } catch {
            // Ignore decode errors
          }
        }
        if (!isReflected && payload.includes('`')) {
          const singleQuoteVersion = payload.replace(/`/g, "'")
          isReflected = responseText.includes(singleQuoteVersion)
        }
        const isExecutable = this.isExecutableXss(payload, responseText)
        if (!isReflected) {
          return null
        }
        return {
          id: this.generateId(),
          url: response.url,
          method: config.method || 'GET',
          parameter: testedParam || 'unknown',
          payload,
          vector: this.getVectorType(payload),
          context: this.getContext(payload, responseText),
          severity: isExecutable ? 'high' : 'medium',
          reflected: isReflected,
          confirmed: isExecutable,
          evidence: isReflected ? payload : 'No evidence collected',
          remediation: 'Apply input validation and output encoding',
          confidence: isExecutable ? 0.9 : 0.5
        }
      })
    } catch {
      return Promise.resolve(null)
    }
  }

  /**
   * Get XSS context.
   * @description Determines injection context from response.
   * @param payload - Test payload string
   * @param responseText - HTML response content
   * @returns XSS context type
   */
  private getContext(payload: string, _responseText: string): Types.XssContext {
    if (payload.includes('<script>')) {
      return 'html'
    } else if (payload.includes('javascript:')) {
      return 'attribute'
    } else if (payload.includes('onerror')) {
      return 'attribute'
    } else {
      return 'html'
    }
  }

  /**
   * Generate unique ID.
   * @description Creates unique result identifier.
   * @returns Unique ID string
   */
  private generateId(): string {
    return `xss-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  }

  /**
   * Get vector type from payload.
   * @description Determines XSS vector type from payload.
   * @param payload - Test payload string
   * @returns Vector type string
   */
  private getVectorType(payload: string): string {
    if (payload.includes('<script>')) {
      return 'script'
    } else if (payload.includes('javascript:')) {
      return 'javascript'
    } else if (payload.includes('onerror')) {
      return 'event'
    } else {
      return 'basic'
    }
  }

  /**
   * Check if payload has break-out pattern.
   * @description Determines if payload has break-out pattern.
   * @param payload - Test payload string
   * @param responseText - HTML response content
   * @returns True if payload has break-out pattern
   */
  private hasBreakOutPattern(payload: string, responseText: string): boolean {
    const payloadIndex = responseText.indexOf(payload)
    if (payloadIndex === -1) {
      return false
    }
    if (
      payload.includes('"') ||
      payload.includes("'") ||
      payload.includes('>') ||
      payload.includes('<')
    ) {
      return true
    }
    return false
  }

  /**
   * Check if XSS is executable.
   * @description Determines if reflected payload is executable XSS.
   * @param payload - Test payload string
   * @param responseText - HTML response content
   * @returns True if XSS is executable
   */
  private isExecutableXss(payload: string, responseText: string): boolean {
    if (this.isInSafeContext(payload, responseText)) {
      return false
    }
    if (
      payload.includes('onmouseover=') ||
      payload.includes('onload=') ||
      payload.includes('onerror=') ||
      payload.includes('onclick=') ||
      payload.includes('ontoggle=') ||
      payload.includes('onstart=') ||
      payload.includes('onfocus=') ||
      payload.includes('onchange=') ||
      payload.includes('oninput=') ||
      payload.includes('onblur=') ||
      payload.includes('oncancel=') ||
      payload.includes('oncontextmenu=') ||
      payload.includes('ondblclick=') ||
      payload.includes('ondrag=') ||
      payload.includes('ondrop=') ||
      payload.includes('ondragend=') ||
      payload.includes('ondragenter=') ||
      payload.includes('ondragleave=') ||
      payload.includes('ondragover=') ||
      payload.includes('ondragstart=') ||
      payload.includes('onmousedown=') ||
      payload.includes('onmouseup=') ||
      payload.includes('onmouseenter=') ||
      payload.includes('onmouseleave=') ||
      payload.includes('onmousemove=') ||
      payload.includes('onmouseout=') ||
      payload.includes('onkeydown=') ||
      payload.includes('onkeypress=') ||
      payload.includes('onkeyup=') ||
      payload.includes('onplay=') ||
      payload.includes('onpause=') ||
      payload.includes('onended=') ||
      payload.includes('onsubmit=') ||
      payload.includes('onreset=') ||
      payload.includes('oninvalid=') ||
      payload.includes('onscroll=') ||
      payload.includes('ontouchstart=') ||
      payload.includes('ontouchend=') ||
      payload.includes('ontouchmove=') ||
      payload.includes('onwheel=') ||
      payload.includes('onabort=') ||
      payload.includes('oncanplay=') ||
      payload.includes('oncanplaythrough=') ||
      payload.includes('ondurationchange=') ||
      payload.includes('onemptied=') ||
      payload.includes('onloadeddata=') ||
      payload.includes('onloadedmetadata=') ||
      payload.includes('onloadstart=') ||
      payload.includes('onmousewheel=') ||
      payload.includes('onprogress=') ||
      payload.includes('onratechange=') ||
      payload.includes('onreadystatechange=') ||
      payload.includes('onseeked=') ||
      payload.includes('onseeking=') ||
      payload.includes('onselect=') ||
      payload.includes('onshow=') ||
      payload.includes('onstalled=') ||
      payload.includes('onsuspend=') ||
      payload.includes('ontimeupdate=') ||
      payload.includes('onvolumechange=') ||
      payload.includes('onwaiting=') ||
      payload.includes('onformchange=') ||
      payload.includes('onforminput=') ||
      payload.includes('for=') ||
      payload.includes('event=')
    ) {
      return true
    }
    if (payload.includes('javascript:')) {
      return true
    }
    if (
      payload.includes('javascript%3A') ||
      payload.includes('javascript%3a') ||
      (payload.includes('%3Aalert%28') && payload.includes('%29'))
    ) {
      return true
    }
    if (
      payload.includes('eval(') ||
      payload.includes('new Function(') ||
      payload.includes('setTimeout(') ||
      payload.includes('setInterval(') ||
      payload.includes('alert(') ||
      payload.includes('confirm(') ||
      payload.includes('prompt(')
    ) {
      return true
    }
    if (
      payload.includes('expression(') ||
      payload.includes('url(javascript:') ||
      payload.includes('@import url(javascript:') ||
      payload.includes('behavior: url(javascript:') ||
      payload.includes('-moz-binding: url(javascript:')
    ) {
      return true
    }
    if (
      payload.includes('<script') ||
      payload.includes('&lt;script') ||
      payload.includes('&#x3c;script') ||
      payload.includes('&#60;script') ||
      payload.includes('\\u003cscript') ||
      payload.includes('<ScRiPt')
    ) {
      return true
    }
    if (payload.includes('\\u003cscript') && responseText.includes('<script')) {
      return true
    }
    if (payload.includes('\\u003cscript') && payload.includes('alert(')) {
      return true
    }
    if (payload.includes('\\u003c/script') && responseText.includes('</script>')) {
      return true
    }
    if (
      payload.includes('.innerHTML') ||
      payload.includes('.outerHTML') ||
      payload.includes('document.write') ||
      payload.includes('insertAdjacentHTML') ||
      payload.includes('createElement') ||
      payload.includes('appendChild')
    ) {
      return true
    }
    if (payload.includes('data-') && payload.includes('javascript:')) {
      return true
    }
    if (payload.includes('<script>') && responseText.includes(payload)) {
      return true
    }
    if (payload.includes('<script src=') && responseText.includes(payload)) {
      return true
    }
    if (payload.includes('<script src=') && payload.includes('`')) {
      return true
    }
    if (payload.includes('data:text/javascript') && responseText.includes(payload)) {
      return true
    }
    if (this.hasBreakOutPattern(payload, responseText)) {
      return true
    }
    return false
  }

  /**
   * Check if payload is in safe (non-executable) context.
   * @description Determines if reflected payload is safe.
   * @param payload - Test payload string
   * @param responseText - HTML response content
   * @returns True if payload is in safe context
   */
  private isInSafeContext(payload: string, responseText: string): boolean {
    if (payload.includes('\\u003cscript')) {
      return false
    }
    if (payload.includes('<script') && payload.includes('`')) {
      return false
    }
    if (payload.includes('on') && payload.includes('=')) {
      return false
    }
    const payloadIndex = responseText.indexOf(payload)
    if (payloadIndex === -1) {
      return true
    }
    const beforePayload = responseText.substring(Math.max(0, payloadIndex - 100), payloadIndex)
    const afterPayload = responseText.substring(
      payloadIndex + payload.length,
      Math.min(responseText.length, payloadIndex + payload.length + 100)
    )
    if (
      (beforePayload.includes('value="') && afterPayload.includes('"')) ||
      (beforePayload.includes("value='") && afterPayload.includes("'"))
    ) {
      if (beforePayload.includes('value="') && payload.includes('"')) {
        return false
      }
      if (beforePayload.includes("value='") && payload.includes("'")) {
        return false
      }
      return true
    }
    if (
      (beforePayload.includes('<textarea') && afterPayload.includes('</textarea>')) ||
      (beforePayload.includes('<textarea') && afterPayload.includes('</textarea>'))
    ) {
      if (
        payload.includes('oninput=') ||
        payload.includes('onchange=') ||
        payload.includes('onclick=') ||
        payload.includes('onscroll=')
      ) {
        return false
      }
      return true
    }
    if (
      (beforePayload.includes('<option') && afterPayload.includes('</option>')) ||
      (beforePayload.includes('<option') && afterPayload.includes('</option>'))
    ) {
      return true
    }
    if (beforePayload.includes('<meta') && beforePayload.includes('content=')) {
      if (beforePayload.includes('http-equiv="refresh"') && payload.includes('javascript:')) {
        return false
      }
      if (payload.includes('javascript:') || payload.includes('alert(')) {
        return false
      }
      return true
    }
    if (
      (beforePayload.includes('<title') && afterPayload.includes('</title>')) ||
      (beforePayload.includes('<title') && afterPayload.includes('</title>'))
    ) {
      return true
    }
    if (beforePayload.includes('style=') && !payload.includes('javascript:')) {
      if (payload.includes('expression(')) {
        return false
      }
      return true
    }
    if (
      (beforePayload.includes('createTextNode') && afterPayload.includes(')')) ||
      (beforePayload.includes('textContent') && afterPayload.includes('='))
    ) {
      return true
    }
    return false
  }
}
