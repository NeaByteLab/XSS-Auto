import { assertEquals, assertExists } from '@std/assert'
import { ResponseService } from '@app/core/services/index.ts'

Deno.test('XSS Detection - MDN innerHTML injection', async () => {
  const service = new ResponseService()
  const innerHtmlResponse = `
    <h1 id="welcome">Welcome back, <img src=x onerror=alert('hello!')>!</h1>
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
    "<img src=x onerror=alert('hello!')>",
    { url: 'https://example.com', method: 'GET', parameters: ['user'] },
    'user'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - MDN innerHTML injection')
})

Deno.test('XSS Detection - Event handler injection', async () => {
  const service = new ResponseService()
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
  const service = new ResponseService()
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

Deno.test('XSS Detection - SVG onload injection', async () => {
  const service = new ResponseService()
  const svgResponse = `
    <svg onload="alert('XSS')">
      <circle cx="50" cy="50" r="40"/>
    </svg>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(svgResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<svg onload="alert(\'XSS\')">',
    { url: 'https://example.com', method: 'GET', parameters: ['svg'] },
    'svg'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - SVG onload injection')
})

Deno.test('XSS Detection - Iframe src injection', async () => {
  const service = new ResponseService()
  const iframeResponse = `
    <iframe src="javascript:alert('XSS')"></iframe>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(iframeResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    { url: 'https://example.com', method: 'GET', parameters: ['iframe'] },
    'iframe'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - iframe src injection')
})

Deno.test('XSS Detection - MDN style attribute injection', async () => {
  const service = new ResponseService()
  const styleResponse = `
    <div style="background:url(javascript:alert('XSS'))">Click me</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(styleResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "background:url(javascript:alert('XSS'))",
    { url: 'https://example.com', method: 'GET', parameters: ['style'] },
    'style'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - style attribute injection')
})

Deno.test('XSS Detection - MDN form action injection', async () => {
  const service = new ResponseService()
  const formResponse = `
    <form action="javascript:alert('XSS')" method="post">
      <input type="submit" value="Submit">
    </form>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(formResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['action'] },
    'action'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - form action injection')
})

Deno.test('XSS Detection - MDN meta refresh injection', async () => {
  const service = new ResponseService()
  const metaResponse = `
    <meta http-equiv="refresh" content="0;url=javascript:alert('XSS')">
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
    "0;url=javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['content'] },
    'content'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - meta refresh injection')
})

Deno.test('XSS Detection - MDN object data injection', async () => {
  const service = new ResponseService()
  const objectResponse = `
    <object data="javascript:alert('XSS')" type="text/html"></object>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(objectResponse),
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
  assertEquals(result.confirmed, true, 'Should be valid XSS - object data injection')
})

Deno.test('XSS Detection - MDN embed src injection', async () => {
  const service = new ResponseService()
  const embedResponse = `
    <embed src="javascript:alert('XSS')" type="image/gif">
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
  assertEquals(result.confirmed, true, 'Should be valid XSS - embed src injection')
})

Deno.test('XSS Detection - MDN link href injection', async () => {
  const service = new ResponseService()
  const linkResponse = `
    <link rel="stylesheet" href="javascript:alert('XSS')">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(linkResponse),
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
  assertEquals(result.confirmed, true, 'Should be valid XSS - link href injection')
})

Deno.test('XSS Detection - MDN video poster injection', async () => {
  const service = new ResponseService()
  const videoResponse = `
    <video poster="javascript:alert('XSS')" controls>
      <source src="movie.mp4" type="video/mp4">
    </video>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(videoResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    "javascript:alert('XSS')",
    { url: 'https://example.com', method: 'GET', parameters: ['poster'] },
    'poster'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - video poster injection')
})

Deno.test('XSS Detection - MDN audio src injection', async () => {
  const service = new ResponseService()
  const audioResponse = `
    <audio src="javascript:alert('XSS')" controls>
      Your browser does not support the audio element.
    </audio>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(audioResponse),
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
  assertEquals(result.confirmed, true, 'Should be valid XSS - audio src injection')
})

Deno.test('XSS Detection - MDN details ontoggle injection', async () => {
  const service = new ResponseService()
  const detailsResponse = `
    <details ontoggle="alert('XSS')">
      <summary>Click me</summary>
      <p>Hidden content</p>
    </details>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(detailsResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'ontoggle="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['ontoggle'] },
    'ontoggle'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - details ontoggle injection')
})

Deno.test('XSS Detection - MDN marquee behavior injection', async () => {
  const service = new ResponseService()
  const marqueeResponse = `
    <marquee behavior="alternate" onstart="alert('XSS')">Scrolling text</marquee>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(marqueeResponse),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onstart="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onstart'] },
    'onstart'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - marquee onstart injection')
})
