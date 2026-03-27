import type * as Types from '@interfaces/index.ts'

/**
 * Reflection detection service.
 * @description Analyzes payload reflection patterns.
 */
export class ReflectionService {
  /**
   * Detect payload reflection.
   * @description Checks if payload is reflected in response.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Reflection analysis result
   */
  static detectReflection(responseText: string, payload: string): Types.ReflectionResult {
    if (responseText.includes(payload)) {
      return {
        reflected: true,
        confirmed: true,
        evidence: `Exact payload reflection: ${payload}`,
        confidence: 1.0
      }
    }
    const templateResult = this.detectTemplateInjection(responseText, payload)
    if (templateResult.reflected) {
      return templateResult
    }
    const eventResult = this.detectModernEvents(responseText, payload)
    if (eventResult.reflected) {
      return eventResult
    }
    const encodedResult = this.detectEncodedVariations(responseText, payload)
    if (encodedResult.reflected) {
      return encodedResult
    }
    const partialResult = this.detectPartialReflection(responseText, payload)
    if (partialResult.reflected) {
      return partialResult
    }
    return {
      reflected: false,
      confirmed: false,
      confidence: 0.0,
      evidence: ''
    }
  }

  /**
   * Detect encoded variations.
   * @description Finds URL/HTML encoded payload reflections.
   * @param responseText - HTML response content
   * @param payload - Original test payload
   * @returns Reflection result for encoded matches
   */
  private static detectEncodedVariations(
    responseText: string,
    payload: string
  ): Types.ReflectionResult {
    const variations = [
      encodeURIComponent(payload),
      decodeURIComponent(payload),
      payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'),
      payload.replace(/"/g, '&quot;').replace(/'/g, '&#39;'),
      btoa(payload),
      atob(payload)
    ]
    for (const variation of variations) {
      if (responseText.includes(variation)) {
        return {
          reflected: true,
          confirmed: true,
          evidence: `Encoded payload reflection: ${variation}`,
          confidence: 0.8
        }
      }
    }
    return {
      reflected: false,
      confirmed: false,
      confidence: 0.0,
      evidence: ''
    }
  }

  /**
   * Detect modern events.
   * @description Finds modern event handler reflections.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Reflection result for event handlers
   */
  private static detectModernEvents(responseText: string, payload: string): Types.ReflectionResult {
    const modernEvents = [
      'onanimationstart',
      'onanimationend',
      'onanimationiteration',
      'onbeforematch',
      'onbeforeprint',
      'onafterprint'
    ]
    for (const eventName of modernEvents) {
      const eventRegex = new RegExp(`${eventName}="[^"]*${payload}[^"]*"`, 'i')
      const eventMatches = responseText.match(eventRegex)
      if (eventMatches) {
        return {
          reflected: true,
          confirmed: true,
          evidence: `Modern event handler detected: ${eventMatches[0]}`,
          confidence: 0.8
        }
      }
    }
    return {
      reflected: false,
      confirmed: false,
      confidence: 0.0,
      evidence: ''
    }
  }

  /**
   * Detect partial matches.
   * @description Finds partial keyword reflections.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Reflection result for partial matches
   */
  private static detectPartialReflection(
    responseText: string,
    payload: string
  ): Types.ReflectionResult {
    const keywords = ReflectionService.extractXssKeywords(payload)
    const matchedKeywords = keywords.filter((keyword: string) => responseText.includes(keyword))
    if (matchedKeywords.length >= 2) {
      return {
        reflected: true,
        confirmed: false,
        evidence: `Partial match: ${matchedKeywords.join(', ')}`,
        confidence: 0.6
      }
    }
    return {
      reflected: false,
      confirmed: false,
      confidence: 0.0,
      evidence: ''
    }
  }

  /**
   * Detect template injection.
   * @description Finds template engine injection reflections.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Reflection result for template injection
   */
  private static detectTemplateInjection(
    responseText: string,
    payload: string
  ): Types.ReflectionResult {
    const templatePatterns = [/\{\{.*?\}\}/g, /\$\{.*?\}/g, /ng-[a-z]+=".*?\{\{.*?\}\}"/g]
    for (const pattern of templatePatterns) {
      const templateMatches = responseText.match(pattern)
      if (
        templateMatches &&
        templateMatches.some((matchedContent) => ReflectionService.looksLikeXss(matchedContent))
      ) {
        const hasPayload = templateMatches.some((matchedContent) =>
          matchedContent.includes(payload)
        )
        return {
          reflected: true,
          confirmed: true,
          evidence: `Template injection detected: ${templateMatches[0]}`,
          confidence: hasPayload ? 0.9 : 0.7
        }
      }
    }
    return {
      reflected: false,
      confirmed: false,
      confidence: 0.0,
      evidence: ''
    }
  }

  /**
   * Extract XSS keywords.
   * @description Gets XSS keywords from payload string.
   * @param payload - Test payload string
   * @returns Array of XSS keywords
   */
  private static extractXssKeywords(payload: string): string[] {
    const keywords = ['alert', 'script', 'javascript', 'onerror', 'onload', 'eval', 'constructor']
    return keywords.filter((keyword) => payload.toLowerCase().includes(keyword))
  }

  /**
   * Check if content looks like XSS.
   * @description Tests content against XSS patterns.
   * @param match - Matched content string
   * @returns True if content contains XSS
   */
  private static looksLikeXss(matchedContent: string): boolean {
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /eval\(/i,
      /constructor/i,
      /alert\(/i,
      /confirm\(/i,
      /prompt\(/i
    ]
    return xssPatterns.some((pattern) => pattern.test(matchedContent))
  }
}
