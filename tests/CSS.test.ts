import { assertEquals, assertExists } from '@std/assert'
import { ResponseService } from '@app/core/services/index.ts'

Deno.test('XSS Detection - MDN CSS expression injection', async () => {
  const service = new ResponseService()
  const cssExpressionResponse = `
    <div style="width: expression(alert('XSS'));">CSS Expression</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(cssExpressionResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "expression(alert('XSS'))",
    { url: 'https://example.com', method: 'GET', parameters: ['style'] },
    'style'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN CSS expression injection')
})

Deno.test('XSS Detection - MDN CSS url() injection', async () => {
  const service = new ResponseService()
  const cssUrlResponse = `
    <div style="background: url(javascript:alert('XSS'));">CSS URL</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(cssUrlResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "url(javascript:alert('XSS'))",
    { url: 'https://example.com', method: 'GET', parameters: ['style'] },
    'style'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN CSS url() injection')
})

Deno.test('XSS Detection - MDN CSS @import injection', async () => {
  const service = new ResponseService()
  const cssImportResponse = `
    <style>
      @import url(javascript:alert('XSS'));
    </style>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(cssImportResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "@import url(javascript:alert('XSS'))",
    { url: 'https://example.com', method: 'GET', parameters: ['import'] },
    'import'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN CSS @import injection')
})

Deno.test('XSS Detection - MDN CSS behavior injection', async () => {
  const service = new ResponseService()
  const cssBehaviorResponse = `
    <div style="behavior: url(javascript:alert('XSS'));">CSS Behavior</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(cssBehaviorResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "behavior: url(javascript:alert('XSS'))",
    { url: 'https://example.com', method: 'GET', parameters: ['behavior'] },
    'behavior'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN CSS behavior injection')
})

Deno.test('XSS Detection - MDN CSS -moz-binding injection', async () => {
  const service = new ResponseService()
  const cssBindingResponse = `
    <div style="-moz-binding: url(javascript:alert('XSS'));">CSS Binding</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(cssBindingResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "-moz-binding: url(javascript:alert('XSS'))",
    { url: 'https://example.com', method: 'GET', parameters: ['binding'] },
    'binding'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN CSS -moz-binding injection')
})

Deno.test('XSS Detection - MDN applet archive injection', async () => {
  const service = new ResponseService()
  const appletResponse = `
    <applet archive="javascript:alert('XSS')" code="malicious.class">
    </applet>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(appletResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['archive'] },
    'archive'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN applet archive injection')
})

Deno.test('XSS Detection - MDN base href injection', async () => {
  const service = new ResponseService()
  const baseResponse = `
    <base href="javascript:alert('XSS')">
    <script src="relative.js"></script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(baseResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['href'] },
    'href'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN base href injection')
})

Deno.test('XSS Detection - MDN embed allowscriptaccess injection', async () => {
  const service = new ResponseService()
  const embedResponse = `
    <embed src="javascript:alert('XSS')" allowscriptaccess="always" type="application/x-shockwave-flash">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(embedResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['src'] },
    'src'
  )
  assertExists(result)
  assertEquals(
    result.confirmed,
    true,
    'Should be valid XSS - MDN embed allowscriptaccess injection'
  )
})

Deno.test('XSS Detection - MDN meta x-ua-compatible injection', async () => {
  const service = new ResponseService()
  const metaResponse = `
    <meta http-equiv="x-ua-compatible" content="javascript:alert('XSS')">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(metaResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN meta x-ua-compatible injection')
})

Deno.test('XSS Detection - MDN object param injection', async () => {
  const service = new ResponseService()
  const objectParamResponse = `
    <object type="text/html" data="javascript:alert('XSS')">
      <param name="allowScriptAccess" value="always">
    </object>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(objectParamResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['data'] },
    'data'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN object param injection')
})

Deno.test('XSS Detection - MDN sandbox iframe injection', async () => {
  const service = new ResponseService()
  const sandboxResponse = `
    <iframe sandbox="allow-scripts" src="javascript:alert('XSS')"></iframe>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(sandboxResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['src'] },
    'src'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN sandbox iframe injection')
})

Deno.test('XSS Detection - MDN script for injection', async () => {
  const service = new ResponseService()
  const scriptForResponse = `
    <script for="window" event="onload">
      alert('XSS');
    </script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(scriptForResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['event'] },
    'event'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN script for injection')
})

Deno.test('XSS Detection - MDN script src injection', async () => {
  const service = new ResponseService()
  const scriptResponse = `
    <script src="javascript:alert('XSS')"></script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(scriptResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['src'] },
    'src'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN script src injection')
})

Deno.test('XSS Detection - MDN xml data island injection', async () => {
  const service = new ResponseService()
  const xmlResponse = `
    <xml id="data">
      <script>alert('XSS')</script>
    </xml>
    <script dataSrc="#data"></script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(xmlResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "<script>alert('XSS')</script>",
    { url: 'https://example.com', method: 'GET', parameters: ['xml'] },
    'xml'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN xml data island injection')
})
