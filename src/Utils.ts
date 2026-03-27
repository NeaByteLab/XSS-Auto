/**
 * String encoding utilities.
 * @description Provides various encoding methods for payloads.
 */
export default class Encoder {
  /**
   * Encode string to base64.
   * @description Converts string to base64 format.
   * @param inputString - String to encode
   * @returns Base64 encoded string
   */
  static base64Encode(inputString: string): string {
    return btoa(inputString)
  }

  /**
   * Double URL encode string.
   * @description Applies URL encoding twice.
   * @param inputString - String to encode
   * @returns Double URL encoded string
   */
  static doubleUrlEncode(inputString: string): string {
    return encodeURIComponent(encodeURIComponent(inputString))
  }

  /**
   * Generate all encodings.
   * @description Creates array of all encoding variations.
   * @param payload - String to encode
   * @returns Array of encoded strings
   */
  static generateEncodings(payload: string): string[] {
    return [
      this.urlEncode(payload),
      this.doubleUrlEncode(payload),
      this.htmlEncode(payload),
      this.hexEncode(payload),
      this.unicodeEncode(payload),
      this.base64Encode(payload)
    ]
  }

  /**
   * Encode string to hex.
   * @description Converts string to hexadecimal format.
   * @param inputString - String to encode
   * @returns Hexadecimal encoded string
   */
  static hexEncode(inputString: string): string {
    return inputString
      .split('')
      .map((char) => '%' + char.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('')
  }

  /**
   * Encode HTML entities.
   * @description Converts HTML characters to entities.
   * @param inputString - String to encode
   * @returns HTML entity encoded string
   */
  static htmlEncode(inputString: string): string {
    const encoding = inputString.replace(/[&<>"']/g, (match) => {
      switch (match) {
        case '&':
          return '&amp;'
        case '<':
          return '&lt;'
        case '>':
          return '&gt;'
        case '"':
          return '&quot;'
        case "'":
          return '&#39;'
        default:
          return match
      }
    })
    return encoding
  }

  /**
   * Encode string to Unicode.
   * @description Converts string to Unicode escape sequences.
   * @param inputString - String to encode
   * @returns Unicode encoded string
   */
  static unicodeEncode(inputString: string): string {
    return inputString
      .split('')
      .map((char) => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'))
      .join('')
  }

  /**
   * URL encode string.
   * @description Applies URL encoding to string.
   * @param inputString - String to encode
   * @returns URL encoded string
   */
  static urlEncode(inputString: string): string {
    return encodeURIComponent(inputString)
  }
}
