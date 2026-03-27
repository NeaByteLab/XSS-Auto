import type * as Types from '@app/Types.ts'

/**
 * Evidence collection service.
 * @description Extracts and analyzes XSS evidence.
 */
export class EvidenceService {
  /**
   * Analyze evidence in response text.
   * @description Finds all evidence types for given payload.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @param reflection - Reflection analysis result
   * @returns Array of evidence items found
   */
  static analyzeEvidence(
    responseText: string,
    payload: string,
    reflection: Types.ReflectionResult
  ): Types.Evidence[] {
    const evidence: Types.Evidence[] = []
    const exactMatch = EvidenceService.findExactMatch(responseText, payload)
    if (exactMatch) {
      evidence.push(exactMatch)
    }
    const encodedMatches = EvidenceService.findEncodedMatches(responseText, payload)
    evidence.push(...encodedMatches)
    const templateEvidence = EvidenceService.findTemplateEvidence(responseText, payload)
    if (templateEvidence) {
      evidence.push(templateEvidence)
    }
    const eventEvidence = EvidenceService.findEventEvidence(responseText, payload)
    if (eventEvidence) {
      evidence.push(eventEvidence)
    }
    const partialMatches = EvidenceService.findPartialMatches(responseText, payload)
    evidence.push(...partialMatches)
    evidence.forEach((evidenceItem) => {
      evidenceItem.confidence = Math.min(evidenceItem.confidence + reflection.confidence * 0.1, 1.0)
    })
    return evidence
  }

  /**
   * Collect evidence from response text.
   * @description Extracts and formats XSS evidence from response.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @param reflection - Reflection analysis result
   * @returns Formatted evidence string or empty string
   */
  static collectEvidence(
    responseText: string,
    payload: string,
    reflection: Types.ReflectionResult
  ): string {
    if (!reflection.reflected) {
      return ''
    }
    const evidence = EvidenceService.analyzeEvidence(responseText, payload, reflection)
    return EvidenceService.formatEvidence(evidence)
  }

  /**
   * Extract context around match.
   * @description Gets surrounding text near matched content.
   * @param line - Text line containing match
   * @param match - Matched string content
   * @param contextWindow - Characters before and after match
   * @returns Context string with match included
   */
  static extractContext(line: string, match: string, contextWindow: number = 50): string {
    const index = line.indexOf(match)
    if (index === -1) {
      return line
    }
    const start = Math.max(0, index - contextWindow)
    const end = Math.min(line.length, index + match.length + contextWindow)
    return line.slice(start, end)
  }

  /**
   * Extract XSS keywords from payload.
   * @description Finds common XSS patterns in payload string.
   * @param payload - Test payload string
   * @returns Array of XSS keyword matches
   */
  static extractXssKeywords(payload: string): string[] {
    const keywords = ['alert', 'script', 'javascript', 'onerror', 'onload', 'eval', 'constructor']
    return keywords.filter((keyword) => payload.toLowerCase().includes(keyword))
  }

  /**
   * Find encoded payload variations.
   * @description Searches for URL encoded and HTML encoded matches.
   * @param responseText - HTML response content
   * @param payload - Original test payload
   * @returns Array of encoded match evidence
   */
  static findEncodedMatches(responseText: string, payload: string): Types.Evidence[] {
    const evidence: Types.Evidence[] = []
    const variations = [
      encodeURIComponent(payload),
      payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'),
      payload.replace(/"/g, '&quot;').replace(/'/g, '&#39;')
    ]
    for (const variation of variations) {
      const matchIndex = responseText.indexOf(variation)
      if (matchIndex !== -1) {
        const responseLines = responseText.split('\n')
        const matchLineIndex = responseLines.findIndex((line) => line.includes(variation))
        evidence.push({
          type: 'encoded-match',
          content: variation,
          context: EvidenceService.extractContext(responseLines[matchLineIndex] || '', variation),
          line: matchLineIndex + 1,
          confidence: 0.8
        })
      }
    }
    return evidence
  }

  /**
   * Find event handler evidence.
   * @description Detects modern event handlers with payload.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Event handler evidence or null
   */
  static findEventEvidence(responseText: string, payload: string): Types.Evidence | null {
    const eventPatterns = [
      /onanimationstart="[^"]*"/g,
      /onanimationend="[^"]*"/g,
      /onbeforematch="[^"]*"/g,
      /onbeforeprint="[^"]*"/g
    ]
    for (const pattern of eventPatterns) {
      const matches = responseText.match(pattern)
      if (matches && matches.length > 0) {
        const payloadMatch = matches.find((matchItem) => matchItem.includes(payload))
        const eventMatch = payloadMatch || matches[0]
        const responseLines = responseText.split('\n')
        const matchLineIndex = responseLines.findIndex((line) => line.includes(eventMatch))
        return {
          type: 'event-handler',
          content: eventMatch,
          context: EvidenceService.extractContext(responseLines[matchLineIndex] || '', eventMatch),
          line: matchLineIndex + 1,
          confidence: payloadMatch ? 0.8 : 0.6
        }
      }
    }
    return null
  }

  /**
   * Find exact payload match.
   * @description Locates exact payload string in response.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Exact match evidence or null
   */
  static findExactMatch(responseText: string, payload: string): Types.Evidence | null {
    const matchIndex = responseText.indexOf(payload)
    if (matchIndex === -1) {
      return null
    }
    const responseLines = responseText.split('\n')
    const matchLineIndex = responseLines.findIndex((line) => line.includes(payload))
    return {
      type: 'exact-match',
      content: payload,
      context: EvidenceService.extractContext(responseLines[matchLineIndex] || '', payload),
      line: matchLineIndex + 1,
      confidence: 1.0
    }
  }

  /**
   * Find partial keyword matches.
   * @description Searches for XSS keywords from payload.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Array of partial match evidence
   */
  static findPartialMatches(responseText: string, payload: string): Types.Evidence[] {
    const evidence: Types.Evidence[] = []
    const keywords = EvidenceService.extractXssKeywords(payload)
    for (const keyword of keywords) {
      const matchIndex = responseText.indexOf(keyword)
      if (matchIndex !== -1) {
        const responseLines = responseText.split('\n')
        const matchLineIndex = responseLines.findIndex((line) => line.includes(keyword))
        evidence.push({
          type: 'partial-match',
          content: keyword,
          context: EvidenceService.extractContext(responseLines[matchLineIndex] || '', keyword),
          line: matchLineIndex + 1,
          confidence: 0.6
        })
      }
    }
    return evidence
  }

  /**
   * Find template injection evidence.
   * @description Detects template engine injection patterns.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Template injection evidence or null
   */
  static findTemplateEvidence(responseText: string, payload: string): Types.Evidence | null {
    const templatePatterns = [/\{\{.*?\}\}/g, /\$\{.*?\}/g, /ng-[a-z]+=".*?\{\{.*?\}\}"/g]
    for (const pattern of templatePatterns) {
      const matches = responseText.match(pattern)
      if (matches && matches.some((matchItem) => EvidenceService.isXssLike(matchItem))) {
        const payloadMatch = matches.find((matchItem) => matchItem.includes(payload))
        const templateMatch = payloadMatch ||
          matches.find((matchItem) => EvidenceService.isXssLike(matchItem))!
        const responseLines = responseText.split('\n')
        const matchLineIndex = responseLines.findIndex((line) => line.includes(templateMatch))
        return {
          type: 'template-injection',
          content: templateMatch,
          context: EvidenceService.extractContext(
            responseLines[matchLineIndex] || '',
            templateMatch
          ),
          line: matchLineIndex + 1,
          confidence: payloadMatch ? 0.9 : 0.7
        }
      }
    }
    return null
  }

  /**
   * Format evidence for display.
   * @description Converts evidence array to readable string.
   * @param evidence - Array of evidence items
   * @returns Formatted evidence string
   */
  static formatEvidence(evidence: Types.Evidence[]): string {
    if (evidence.length === 0) {
      return ''
    }
    const formatted = evidence.map((evidenceItem) => {
      const location = evidenceItem.line ? ` (Line ${evidenceItem.line})` : ''
      return `[${evidenceItem.type.toUpperCase()}] ${evidenceItem.content}${location}`
    })
    return formatted.join('\n')
  }

  /**
   * Get evidence summary statistics.
   * @description Calculates total evidence and confidence metrics.
   * @param evidence - Array of evidence items
   * @returns Summary object with counts and confidence
   */
  static getEvidenceSummary(evidence: Types.Evidence[]): {
    total: number
    byType: Record<string, number>
    highestConfidence: number
  } {
    const byType: Record<string, number> = {}
    let highestConfidence = 0
    for (const evidenceItem of evidence) {
      byType[evidenceItem.type] = (byType[evidenceItem.type] || 0) + 1
      highestConfidence = Math.max(highestConfidence, evidenceItem.confidence)
    }
    return {
      total: evidence.length,
      byType,
      highestConfidence
    }
  }

  /**
   * Check if content looks like XSS.
   * @description Tests content against XSS indicator patterns.
   * @param content - Text content to analyze
   * @returns True if content contains XSS patterns
   */
  static isXssLike(content: string): boolean {
    const xssIndicators = ['alert', 'constructor', 'eval', 'innerHTML', 'document', 'window']
    return xssIndicators.some((indicator) => content.toLowerCase().includes(indicator))
  }
}
