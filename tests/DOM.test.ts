import { assertEquals, assertExists } from '@std/assert'
import { ResponseService } from '@app/core/services/index.ts'

Deno.test('XSS Detection - MDN innerHTML DOM injection', async () => {
  const service = new ResponseService()
  const innerHtmlResponse = `
    <div id="container">
      <script>
        const element = document.getElementById('container');
        element.innerHTML = '<img src=x onerror=alert("XSS")>';
      </script>
    </div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(innerHtmlResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<img src=x onerror=alert("XSS")>',
    { url: 'https://example.com', method: 'GET', parameters: ['innerHTML'] },
    'innerHTML'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN innerHTML DOM injection')
})

Deno.test('XSS Detection - MDN outerHTML DOM injection', async () => {
  const service = new ResponseService()

  const outerHtmlResponse = `
    <div id="target">
      <script>
        const element = document.getElementById('target');
        element.outerHTML = '<div onmouseover=alert("XSS")>New content</div>';
      </script>
    </div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(outerHtmlResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<div onmouseover=alert("XSS")>New content</div>',
    { url: 'https://example.com', method: 'GET', parameters: ['outerHTML'] },
    'outerHTML'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN outerHTML DOM injection')
})

Deno.test('XSS Detection - MDN document.write injection', async () => {
  const service = new ResponseService()
  const documentWriteResponse = `
    <script>
      document.write('<iframe src=javascript:alert("XSS")></iframe>');
    </script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(documentWriteResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<iframe src=javascript:alert("XSS")></iframe>',
    { url: 'https://example.com', method: 'GET', parameters: ['documentWrite'] },
    'documentWrite'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN document.write injection')
})

Deno.test('XSS Detection - MDN createElement injection', async () => {
  const service = new ResponseService()
  const createElementResponse = `
    <script>
      const element = document.createElement('img');
      element.setAttribute('src', 'x');
      element.setAttribute('onerror', 'alert("XSS")');
      document.body.appendChild(element);
    </script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(createElementResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'alert("XSS")',
    { url: 'https://example.com', method: 'GET', parameters: ['onerror'] },
    'onerror'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN createElement injection')
})

Deno.test('XSS Detection - MDN appendChild injection', async () => {
  const service = new ResponseService()
  const appendChildResponse = `
    <script>
      const maliciousDiv = document.createElement('div');
      maliciousDiv.innerHTML = '<script>alert("XSS")<\/script>';
      document.body.appendChild(maliciousDiv);
    </script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(appendChildResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<script>alert("XSS")<\/script>',
    { url: 'https://example.com', method: 'GET', parameters: ['innerHTML'] },
    'innerHTML'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN appendChild injection')
})

Deno.test('XSS Detection - MDN data-* attribute injection', async () => {
  const service = new ResponseService()
  const dataAttributeResponse = `
    <div data-xss="javascript:alert('XSS')" onclick="this.dataset.xss">Click me</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(dataAttributeResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['data-xss'] },
    'data-xss'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN data-* attribute injection')
})

Deno.test('XSS Detection - MDN dataset property injection', async () => {
  const service = new ResponseService()
  const datasetResponse = `
    <script>
      const element = document.getElementById('target');
      element.dataset.payload = '<script>alert("XSS")<\/script>';
      element.innerHTML = element.dataset.payload;
    </script>
    <div id="target"></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(datasetResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<script>alert("XSS")<\/script>',
    { url: 'https://example.com', method: 'GET', parameters: ['dataset'] },
    'dataset'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN dataset property injection')
})

Deno.test('XSS Detection - MDN insertAdjacentHTML injection', async () => {
  const service = new ResponseService()
  const insertAdjacentResponse = `
    <script>
      const element = document.getElementById('container');
      element.insertAdjacentHTML('beforeend', '<img src=x onerror=alert("XSS")>');
    </script>
    <div id="container"></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(insertAdjacentResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<img src=x onerror=alert("XSS")>',
    { url: 'https://example.com', method: 'GET', parameters: ['insertAdjacentHTML'] },
    'insertAdjacentHTML'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN insertAdjacentHTML injection')
})

Deno.test('XSS Detection - MDN createTextNode injection', async () => {
  const service = new ResponseService()
  const createTextNodeResponse = `
    <script>
      const element = document.getElementById('safe');
      const textNode = document.createTextNode('<script>alert("XSS")<\/script>');
      element.appendChild(textNode);
    </script>
    <div id="safe"></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(createTextNodeResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<script>alert("XSS")<\/script>',
    { url: 'https://example.com', method: 'GET', parameters: ['createTextNode'] },
    'createTextNode'
  )
  assertExists(result)
  assertEquals(result.confirmed, false, 'Should be invalid XSS - createTextNode is safe')
})

Deno.test('XSS Detection - MDN textContent injection', async () => {
  const service = new ResponseService()
  const textContentResponse = `
    <script>
      const element = document.getElementById('safe');
      element.textContent = '<script>alert("XSS")<\/script>';
    </script>
    <div id="safe"></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(textContentResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<script>alert("XSS")<\/script>',
    { url: 'https://example.com', method: 'GET', parameters: ['textContent'] },
    'textContent'
  )
  assertExists(result)
  assertEquals(result.confirmed, false, 'Should be invalid XSS - textContent is safe')
})

Deno.test('XSS Detection - MDN eval injection', async () => {
  const service = new ResponseService()
  const evalResponse = `
    <script>
      eval('alert("XSS")');
    </script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(evalResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'alert("XSS")',
    { url: 'https://example.com', method: 'GET', parameters: ['eval'] },
    'eval'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN eval injection')
})

Deno.test('XSS Detection - MDN Function constructor injection', async () => {
  const service = new ResponseService()
  const functionResponse = `
    <script>
      const malicious = new Function('alert("XSS")');
      malicious();
    </script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(functionResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'alert("XSS")',
    { url: 'https://example.com', method: 'GET', parameters: ['Function'] },
    'Function'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Function constructor injection')
})

Deno.test('XSS Detection - MDN setTimeout injection', async () => {
  const service = new ResponseService()
  const setTimeoutResponse = `
    <script>
      setTimeout('alert("XSS")', 1000);
    </script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(setTimeoutResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'alert("XSS")',
    { url: 'https://example.com', method: 'GET', parameters: ['setTimeout'] },
    'setTimeout'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN setTimeout injection')
})

Deno.test('XSS Detection - MDN setInterval injection', async () => {
  const service = new ResponseService()
  const setIntervalResponse = `
    <script>
      setInterval('alert("XSS")', 2000);
    </script>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(setIntervalResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'alert("XSS")',
    { url: 'https://example.com', method: 'GET', parameters: ['setInterval'] },
    'setInterval'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN setInterval injection')
})
