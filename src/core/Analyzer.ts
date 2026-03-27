import type * as Types from '@app/Types.ts'

/**
 * Core XSS analysis engine.
 * @description Analyzes HTTP responses for XSS reflections.
 */
export class CoreAnalyzer {
  /**
   * Analyze response for XSS.
   * @description Checks if payload reflected in response.
   * @param responseText - HTML response content
   * @param payload - Test payload string
   * @returns Reflection analysis result
   */
  static analyzeResponse(responseText: string, payload: string): Types.ReflectionResult {
    if (responseText.includes(payload)) {
      return {
        reflected: true,
        confirmed: true,
        evidence: `Direct payload reflection: ${payload}`,
        confidence: 0.9
      }
    }
    if (responseText.toLowerCase().includes(payload.toLowerCase())) {
      return {
        reflected: true,
        confirmed: false,
        evidence: `Case-insensitive reflection: ${payload}`,
        confidence: 0.7
      }
    }
    if (payload.includes('__proto__') || payload.includes('prototype')) {
      return {
        reflected: false,
        confirmed: false,
        confidence: 0.0,
        evidence: ''
      }
    }
    if (payload.includes('constructor') || payload.includes('prototype')) {
      return {
        reflected: false,
        confirmed: false,
        confidence: 0.0,
        evidence: ''
      }
    }
    return { reflected: false, confirmed: false, confidence: 0.0, evidence: '' }
  }

  /**
   * Build form data string.
   * @description Creates URL-encoded form with injected payload.
   * @param formData - Original form data object
   * @param payload - XSS payload to inject
   * @param fieldName - Target field name
   * @returns URL-encoded form string
   */
  static buildFormData(
    formData: Record<string, string>,
    payload: string,
    fieldName: string
  ): string {
    const updatedData = { ...formData }
    updatedData[fieldName] = payload
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(updatedData)) {
      params.append(key, value)
    }
    return params.toString()
  }

  /**
   * Extract field names from forms.
   * @description Gets unique field names from forms.
   * @param forms - Array of parsed form objects
   * @returns Array of unique field names
   */
  static extractFieldNames(forms: Types.ParsedForm[]): string[] {
    const fieldNames = new Set<string>()
    for (const form of forms) {
      for (const formField of form.fields) {
        fieldNames.add(formField.name)
      }
    }
    return Array.from(fieldNames)
  }

  /**
   * Extract forms from HTML.
   * @description Parses HTML to find all forms.
   * @param html - HTML content string
   * @returns Array of parsed form objects
   */
  static extractForms(html: string): Types.ParsedForm[] {
    const forms: Types.ParsedForm[] = []
    const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi
    let formMatch
    while ((formMatch = formRegex.exec(html)) !== null) {
      const formHtml = formMatch[0]
      const actionMatch = formHtml.match(/action=["']([^"']+)["']/i)
      const methodMatch = formHtml.match(/method=["']([^"']+)["']/i)
      const action = actionMatch?.[1] || ''
      const method = methodMatch?.[1]?.toUpperCase() || 'GET'
      const fields: Types.FormField[] = []
      const fieldRegex = /<(input|textarea|select)[^>]*>/gi
      let fieldMatch
      while ((fieldMatch = fieldRegex.exec(formHtml)) !== null) {
        const nameMatch = fieldMatch[0].match(/name=["']([^"']+)["']/i)
        const typeMatch = fieldMatch[0].match(/type=["']([^"']+)["']/i)
        const valueMatch = fieldMatch[0].match(/value=["']([^"']*)["']/i)
        if (nameMatch) {
          fields.push({
            name: nameMatch[1] || '',
            type: typeMatch?.[1] || 'text',
            value: valueMatch?.[1] || '',
            required: fieldMatch[0].includes('required')
          })
        }
      }
      forms.push({
        action,
        method,
        fields
      })
    }
    return forms
  }

  /**
   * Generate test data for forms.
   * @description Creates test values for all fields.
   * @param forms - Array of parsed form objects
   * @returns Test data object with field values
   */
  static generateTestData(forms: Types.ParsedForm[]): Record<string, string> {
    const testData: Record<string, string> = {}
    for (const form of forms) {
      for (const field of form.fields) {
        if (!testData[field.name]) {
          testData[field.name] = 'test'
        }
      }
    }
    return testData
  }
}
