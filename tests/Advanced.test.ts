import { assertEquals, assertExists } from '@std/assert'
import { ResponseService } from '@app/core/services/index.ts'

Deno.test('XSS Detection - MDN accesskey injection', async () => {
  const service = new ResponseService()
  const accesskeyResponse = `
    <link rel="canonical" href="https://example.com" accesskey="x" onclick="alert('XSS')">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(accesskeyResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'accesskey="x" onclick="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['accesskey'] },
    'accesskey'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - accesskey injection')
})

Deno.test('XSS Detection - MDN autofocus onfocus injection', async () => {
  const service = new ResponseService()
  const autofocusResponse = `
    <input type="text" autofocus onfocus="alert('XSS')" x="repair">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(autofocusResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'autofocus onfocus="alert(\'XSS\')" x="repair"',
    { url: 'https://example.com', method: 'GET', parameters: ['autofocus'] },
    'autofocus'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - autofocus onfocus injection')
})

Deno.test('XSS Detection - MDN backtick injection', async () => {
  const service = new ResponseService()
  const backtickResponse = `
    <div onmouseover=alert('XSS')>Content</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(backtickResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "onmouseover=alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['onmouseover'] },
    'onmouseover'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - backtick injection')
})

Deno.test('XSS Detection - MDN body onload injection', async () => {
  const service = new ResponseService()
  const bodyResponse = `
    <body onload="alert('XSS')">
      <h1>Welcome</h1>
    </body>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(bodyResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onload="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onload'] },
    'onload'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - body onload injection')
})

Deno.test('XSS Detection - MDN button onclick injection', async () => {
  const service = new ResponseService()
  const buttonResponse = `
    <button type="button" onclick="alert('XSS')">Click me</button>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(buttonResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onclick="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onclick'] },
    'onclick'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - button onclick injection')
})

Deno.test('XSS Detection - MDN hidden input injection', async () => {
  const service = new ResponseService()
  const hiddenResponse = `
    <input type="hidden" value="test" onchange="alert('XSS')">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(hiddenResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onchange="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onchange'] },
    'onchange'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - hidden input injection')
})

Deno.test('XSS Detection - MDN img srcset injection', async () => {
  const service = new ResponseService()
  const imgResponse = `
    <img srcset="invalid.jpg" onerror="alert('XSS')" alt="Image">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(imgResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onerror="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onerror'] },
    'onerror'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - img srcset injection')
})

Deno.test('XSS Detection - MDN picture source injection', async () => {
  const service = new ResponseService()
  const pictureResponse = `
    <picture>
      <source srcset="invalid.jpg" onerror="alert('XSS')">
      <img src="fallback.jpg" alt="Fallback">
    </picture>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(pictureResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onerror="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onerror'] },
    'onerror'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - picture source injection')
})

Deno.test('XSS Detection - MDN select onchange injection', async () => {
  const service = new ResponseService()
  const selectResponse = `
    <select onchange="alert('XSS')">
      <option value="1">Option 1</option>
      <option value="2">Option 2</option>
    </select>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(selectResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onchange="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onchange'] },
    'onchange'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - select onchange injection')
})

Deno.test('XSS Detection - MDN textarea oninput injection', async () => {
  const service = new ResponseService()
  const textareaResponse = `
    <textarea oninput="alert('XSS')" placeholder="Type here"></textarea>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(textareaResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'oninput="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['oninput'] },
    'oninput'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - textarea oninput injection')
})

Deno.test('XSS Detection - MDN unquoted attribute injection', async () => {
  const service = new ResponseService()
  const unquotedResponse = `
    <div class=test onmouseover=alert('XSS')>Content</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(unquotedResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "onmouseover=alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['class'] },
    'class'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - unquoted attribute injection')
})
