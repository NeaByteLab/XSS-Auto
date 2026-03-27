import { assertEquals, assertExists } from '@std/assert'
import { ResponseService } from '@app/core/services/index.ts'

Deno.test('XSS Detection - MDN HTML entity encoding bypass', async () => {
  const service = new ResponseService()
  const entityResponse = `
    <div>&lt;script&gt;alert('XSS')&lt;/script&gt;</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(entityResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN HTML entity encoding bypass')
})

Deno.test('XSS Detection - MDN URL encoding bypass', async () => {
  const service = new ResponseService()
  const urlEncodedResponse = `
    <a href="javascript%3Aalert%28%27XSS%27%29">Click me</a>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(urlEncodedResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'javascript%3Aalert%28%27XSS%27%29',
    { url: 'https://example.com', method: 'GET', parameters: ['href'] },
    'href'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN URL encoding bypass')
})

Deno.test('XSS Detection - MDN Unicode encoding bypass', async () => {
  const service = new ResponseService()
  const unicodeResponse = `
    <div>\u003cscript\u003ealert('XSS')\u003c/script\u003e</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(unicodeResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Unicode encoding bypass')
})

Deno.test('XSS Detection - MDN Hex encoding bypass', async () => {
  const service = new ResponseService()
  const hexResponse = `
    <div>&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(hexResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Hex encoding bypass')
})

Deno.test('XSS Detection - MDN Decimal encoding bypass', async () => {
  const service = new ResponseService()
  const decimalResponse = `
    <div>&#60;script&#62;alert('XSS')&#60;/script&#62;</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(decimalResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Decimal encoding bypass')
})

Deno.test('XSS Detection - MDN Mixed case bypass', async () => {
  const service = new ResponseService()
  const mixedCaseResponse = `
    <div><ScRiPt>alert('XSS')</ScRiPt></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(mixedCaseResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "<ScRiPt>alert('XSS')</ScRiPt>",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Mixed case bypass')
})

Deno.test('XSS Detection - MDN Self-closing tag bypass', async () => {
  const service = new ResponseService()
  const selfClosingResponse = `
    <div><script>alert('XSS')//</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(selfClosingResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "<script>alert('XSS')//",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Self-closing tag bypass')
})

Deno.test('XSS Detection - MDN Comment bypass', async () => {
  const service = new ResponseService()
  const commentResponse = `
    <div><script><!--alert('XSS');//--></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(commentResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "<script><!--alert('XSS');//-->",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Comment bypass')
})

Deno.test('XSS Detection - MDN Grave accent bypass', async () => {
  const service = new ResponseService()
  const graveResponse = `
    <div><script src='javascript:alert('XSS')'></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(graveResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "<script src=`javascript:alert('XSS')`",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Grave accent bypass')
})

Deno.test('XSS Detection - MDN Line break bypass', async () => {
  const service = new ResponseService()
  const lineBreakResponse = `
    <div><script>alert(\n'XSS'\n)</script></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(lineBreakResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "alert(\n'XSS'\n)",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Line break bypass')
})

Deno.test('XSS Detection - MDN Tab bypass', async () => {
  const service = new ResponseService()
  const tabResponse = `
    <div><script>alert(\t'XSS'\t)</script></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(tabResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "alert(\t'XSS'\t)",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Tab bypass')
})

Deno.test('XSS Detection - MDN Null byte bypass', async () => {
  const service = new ResponseService()
  const nullByteResponse = `
    <div><script>alert\0('XSS')</script></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(nullByteResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "alert\0('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Null byte bypass')
})

Deno.test('XSS Detection - MDN Slash bypass', async () => {
  const service = new ResponseService()
  const slashResponse = `
    <div><script>alert('XSS')/</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(slashResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "<script>alert('XSS')/",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN Slash bypass')
})

Deno.test('XSS Detection - MDN No quotes bypass', async () => {
  const service = new ResponseService()
  const noQuotesResponse = `
    <div><script>alert(/XSS/)</script></div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(noQuotesResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'alert(/XSS/)',
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN No quotes bypass')
})
