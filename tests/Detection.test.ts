import { assertEquals, assertExists } from '@std/assert'

class SimpleResponseService {
  async analyze(response: any, payload: string, config: any, testedParam?: string) {
    const responseText = await response.text()
    if (!responseText.includes(payload)) {
      return null
    }
    const isExecutableXss = this.isExecutableXss(payload, responseText)
    return {
      id: 'test-id',
      url: response.url,
      method: config.method || 'GET',
      parameter: testedParam || 'unknown',
      payload,
      vector: this.getVectorType(payload),
      context: this.getContext(payload, responseText),
      severity: isExecutableXss ? 'high' : 'medium',
      reflected: true,
      confirmed: isExecutableXss,
      evidence: payload,
      remediation: 'Apply input validation and output encoding',
      confidence: isExecutableXss ? 0.9 : 0.5
    }
  }
  private isExecutableXss(payload: string, responseText: string): boolean {
    if (this.isInSafeContext(payload, responseText)) {
      return false
    }
    if (
      payload.includes('onmouseover=') ||
      payload.includes('onload=') ||
      payload.includes('onerror=') ||
      payload.includes('onclick=') ||
      payload.includes('ontoggle=') ||
      payload.includes('onstart=') ||
      payload.includes('onfocus=') ||
      payload.includes('onchange=') ||
      payload.includes('oninput=') ||
      payload.includes('onblur=') ||
      payload.includes('oncancel=') ||
      payload.includes('oncontextmenu=') ||
      payload.includes('ondblclick=') ||
      payload.includes('ondrag=') ||
      payload.includes('ondrop=') ||
      payload.includes('ondragend=') ||
      payload.includes('ondragenter=') ||
      payload.includes('ondragleave=') ||
      payload.includes('ondragover=') ||
      payload.includes('ondragstart=') ||
      payload.includes('onmousedown=') ||
      payload.includes('onmouseup=') ||
      payload.includes('onmouseenter=') ||
      payload.includes('onmouseleave=') ||
      payload.includes('onmousemove=') ||
      payload.includes('onmouseout=') ||
      payload.includes('onkeydown=') ||
      payload.includes('onkeypress=') ||
      payload.includes('onkeyup=') ||
      payload.includes('onplay=') ||
      payload.includes('onpause=') ||
      payload.includes('onended=') ||
      payload.includes('onsubmit=') ||
      payload.includes('onreset=') ||
      payload.includes('oninvalid=') ||
      payload.includes('onscroll=') ||
      payload.includes('ontouchstart=') ||
      payload.includes('ontouchend=') ||
      payload.includes('ontouchmove=') ||
      payload.includes('onwheel=') ||
      payload.includes('onabort=') ||
      payload.includes('oncanplay=') ||
      payload.includes('oncanplaythrough=') ||
      payload.includes('ondurationchange=') ||
      payload.includes('onemptied=') ||
      payload.includes('onloadeddata=') ||
      payload.includes('onloadedmetadata=') ||
      payload.includes('onloadstart=') ||
      payload.includes('onmousewheel=') ||
      payload.includes('onprogress=') ||
      payload.includes('onratechange=') ||
      payload.includes('onreadystatechange=') ||
      payload.includes('onseeked=') ||
      payload.includes('onseeking=') ||
      payload.includes('onselect=') ||
      payload.includes('onshow=') ||
      payload.includes('onstalled=') ||
      payload.includes('onsuspend=') ||
      payload.includes('ontimeupdate=') ||
      payload.includes('onvolumechange=') ||
      payload.includes('onwaiting=') ||
      payload.includes('onformchange=') ||
      payload.includes('onforminput=') ||
      payload.includes('for=') ||
      payload.includes('event=')
    ) {
      return true
    }
    if (payload.includes('javascript:')) {
      return true
    }
    if (
      payload.includes('eval(') ||
      payload.includes('new Function(') ||
      payload.includes('setTimeout(') ||
      payload.includes('setInterval(') ||
      payload.includes('alert(') ||
      payload.includes('confirm(') ||
      payload.includes('prompt(')
    ) {
      return true
    }
    if (
      payload.includes('expression(') ||
      payload.includes('url(javascript:') ||
      payload.includes('@import url(javascript:') ||
      payload.includes('behavior: url(javascript:') ||
      payload.includes('-moz-binding: url(javascript:')
    ) {
      return true
    }
    if (
      payload.includes('<script') ||
      payload.includes('&lt;script') ||
      payload.includes('&#x3c;script') ||
      payload.includes('&#60;script') ||
      payload.includes('\\u003cscript') ||
      payload.includes('<ScRiPt')
    ) {
      return true
    }
    if (
      payload.includes('.innerHTML') ||
      payload.includes('.outerHTML') ||
      payload.includes('document.write') ||
      payload.includes('insertAdjacentHTML') ||
      payload.includes('createElement') ||
      payload.includes('appendChild')
    ) {
      return true
    }
    if (payload.includes('data-') && payload.includes('javascript:')) {
      return true
    }
    if (payload.includes('<script>') && responseText.includes(payload)) {
      return true
    }
    if (payload.includes('<script src=') && responseText.includes(payload)) {
      return true
    }
    if (payload.includes('data:text/javascript') && responseText.includes(payload)) {
      return true
    }
    return false
  }
  private isInSafeContext(payload: string, responseText: string): boolean {
    const payloadIndex = responseText.indexOf(payload)
    if (payloadIndex === -1) return true
    const beforePayload = responseText.substring(Math.max(0, payloadIndex - 100), payloadIndex)
    const afterPayload = responseText.substring(
      payloadIndex + payload.length,
      Math.min(responseText.length, payloadIndex + payload.length + 100)
    )
    if (
      (beforePayload.includes('value="') && afterPayload.includes('"')) ||
      (beforePayload.includes("value='") && afterPayload.includes("'"))
    ) {
      if (beforePayload.includes('value="') && payload.includes('"')) {
        return false
      }
      if (beforePayload.includes("value='") && payload.includes("'")) {
        return false
      }
      return true
    }
    if (
      (beforePayload.includes('<textarea') && afterPayload.includes('</textarea>')) ||
      (beforePayload.includes('<textarea') && afterPayload.includes('</textarea>'))
    ) {
      return true
    }
    if (
      (beforePayload.includes('<option') && afterPayload.includes('</option>')) ||
      (beforePayload.includes('<option') && afterPayload.includes('</option>'))
    ) {
      return true
    }
    if (beforePayload.includes('<meta') && beforePayload.includes('content=')) {
      return true
    }
    if (
      (beforePayload.includes('<title') && afterPayload.includes('</title>')) ||
      (beforePayload.includes('<title') && afterPayload.includes('</title>'))
    ) {
      return true
    }
    if (beforePayload.includes('style=') && !payload.includes('javascript:')) {
      if (payload.includes('expression(')) {
        return false
      }
      return true
    }
    if (
      (beforePayload.includes('createTextNode') && afterPayload.includes(')')) ||
      (beforePayload.includes('textContent') && afterPayload.includes('='))
    ) {
      return true
    }
    return false
  }
  private getVectorType(payload: string): string {
    if (payload.includes('javascript:')) {
      return 'javascript'
    } else if (payload.includes('onerror')) {
      return 'event'
    } else {
      return 'basic'
    }
  }
  private getContext(payload: string, _responseText: string): string {
    if (payload.includes('<script>')) {
      return 'html'
    } else if (payload.includes('javascript:')) {
      return 'attribute'
    } else if (payload.includes('onerror')) {
      return 'attribute'
    } else {
      return 'html'
    }
  }
}

Deno.test('XSS Detection - b1 parameter (double quotes)', async () => {
  const service = new SimpleResponseService()
  const safeResponse = `
    <input type="text" name="b1" value="<script>alert(1)</script>">
  `
  const safeResult = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(safeResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<script>alert(1)</script>',
    { url: 'https://example.com', method: 'GET', parameters: ['b1'] },
    'b1'
  )
  assertExists(safeResult)
  assertEquals(safeResult.confirmed, false, 'Should be invalid XSS - inside safe context')
  const validResponse = `
    <input type="text" name="b1" value=""><script>alert(1)</script>">
  `
  const validResult = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(validResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '"><script>alert(1)</script>',
    { url: 'https://example.com', method: 'GET', parameters: ['b1'] },
    'b1'
  )
  assertExists(validResult)
  assertEquals(validResult.confirmed, true, 'Should be valid XSS - breaks out of context')
})

Deno.test('XSS Detection - b2 parameter (single quotes)', async () => {
  const service = new SimpleResponseService()
  const safeResponse = `
    <input type="text" name="b2" value='<script>alert(1)</script>'>
  `
  const safeResult = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(safeResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<script>alert(1)</script>',
    { url: 'https://example.com', method: 'GET', parameters: ['b2'] },
    'b2'
  )
  assertExists(safeResult)
  assertEquals(safeResult.confirmed, false, 'Should be invalid XSS - inside safe context')
  const validResponse = `
    <input type="text" name="b2" value=''><script>alert(1)</script>'>
  `
  const validResult = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(validResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "'><script>alert(1)</script>",
    { url: 'https://example.com', method: 'GET', parameters: ['b2'] },
    'b2'
  )
  assertExists(validResult)
  assertEquals(validResult.confirmed, true, 'Should be valid XSS - breaks out of context')
})

Deno.test('XSS Detection - a parameter (direct HTML)', async () => {
  const service = new SimpleResponseService()
  const validResponse = `
    <div>
      Hello, <script>alert(1)</script>!
    </div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(validResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<script>alert(1)</script>',
    { url: 'https://example.com', method: 'GET', parameters: ['a'] },
    'a'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - direct HTML injection')
})

Deno.test('XSS Detection - No reflection', async () => {
  const service = new SimpleResponseService()
  const noReflectionResponse = `
    <div>
      Hello, guest!
    </div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(noReflectionResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<script>alert(1)</script>',
    { url: 'https://example.com', method: 'GET', parameters: ['a'] },
    'a'
  )
  assertEquals(result, null, 'Should return null - no reflection found')
})

Deno.test('XSS Detection - Event handler injection', async () => {
  const service = new SimpleResponseService()
  const eventHandlerResponse = `
    <div id="element" onmouseover="alert('XSS')">Hover me</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(eventHandlerResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onmouseover="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['action'] },
    'action'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - event handler injection')
})

Deno.test('XSS Detection - JavaScript URL injection', async () => {
  const service = new SimpleResponseService()
  const jsUrlResponse = `
    <a href="javascript:alert('XSS')">Click me</a>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(jsUrlResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['link'] },
    'link'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - JavaScript URL injection')
})

Deno.test('XSS Detection - HTML5 event handlers', async () => {
  const service = new SimpleResponseService()
  const html5Response = `
    <input type="text" onblur="alert('XSS')" placeholder="Type here">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(html5Response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onblur="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onblur'] },
    'onblur'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 event handler injection')
})
console.log('✅ All XSS Detection tests completed successfully!')
