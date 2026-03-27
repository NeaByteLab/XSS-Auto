/**
 * Encoding options data.
 * @description Payload encoding configuration options.
 */
export interface EncodingOptions {
  /** URL encoding enabled */
  url?: boolean
  /** Double URL encoding */
  double?: boolean
  /** HTML encoding enabled */
  html?: boolean
  /** Hex encoding enabled */
  hex?: boolean
  /** Unicode encoding enabled */
  unicode?: boolean
  /** Base64 encoding enabled */
  base64?: boolean
  /** Uppercase conversion */
  uppercase?: boolean
  /** Lowercase conversion */
  lowercase?: boolean
  /** Mixed case conversion */
  mixed?: boolean
}
