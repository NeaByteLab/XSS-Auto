import { assertEquals, assertExists } from '@std/assert'
import { ResponseService } from '@app/core/services/index.ts'

Deno.test('XSS Detection - HTML5 onblur injection', async () => {
  const service = new ResponseService()
  const response = `
    <input type="text" onblur="alert('XSS')" placeholder="Type here">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
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
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 onblur injection')
})

Deno.test('XSS Detection - HTML5 oncancel injection', async () => {
  const service = new ResponseService()
  const response = `
    <dialog oncancel="alert('XSS')">Dialog content</dialog>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'oncancel="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['oncancel'] },
    'oncancel'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 oncancel injection')
})

Deno.test('XSS Detection - HTML5 oncontextmenu injection', async () => {
  const service = new ResponseService()
  const response = `
    <div oncontextmenu="alert('XSS')">Right-click me</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'oncontextmenu="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['oncontextmenu'] },
    'oncontextmenu'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 oncontextmenu injection')
})

Deno.test('XSS Detection - HTML5 ondblclick injection', async () => {
  const service = new ResponseService()
  const response = `
    <button ondblclick="alert('XSS')">Double-click me</button>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'ondblclick="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['ondblclick'] },
    'ondblclick'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 ondblclick injection')
})

Deno.test('XSS Detection - HTML5 drag events injection', async () => {
  const service = new ResponseService()
  const response = `
    <div ondrag="alert('XSS')" ondrop="alert('XSS')" draggable="true">Drag me</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'ondrag="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['ondrag'] },
    'ondrag'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 drag events injection')
})

Deno.test('XSS Detection - HTML5 mouse events injection', async () => {
  const service = new ResponseService()
  const response = `
    <div onmousedown="alert('XSS')" onmouseup="alert('XSS')" onmouseenter="alert('XSS')" onmouseleave="alert('XSS')">Mouse events</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onmousedown="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onmousedown'] },
    'onmousedown'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 mouse events injection')
})

Deno.test('XSS Detection - HTML5 keyboard events injection', async () => {
  const service = new ResponseService()
  const response = `
    <input type="text" onkeydown="alert('XSS')" onkeypress="alert('XSS')" onkeyup="alert('XSS')" placeholder="Type here">
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onkeydown="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onkeydown'] },
    'onkeydown'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 keyboard events injection')
})

Deno.test('XSS Detection - HTML5 media events injection', async () => {
  const service = new ResponseService()
  const response = `
    <video onplay="alert('XSS')" onpause="alert('XSS')" onended="alert('XSS')" controls>
      <source src="video.mp4" type="video/mp4">
    </video>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onplay="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onplay'] },
    'onplay'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 media events injection')
})

Deno.test('XSS Detection - HTML5 form events injection', async () => {
  const service = new ResponseService()
  const response = `
    <form onsubmit="alert('XSS')" onreset="alert('XSS')" oninput="alert('XSS')" oninvalid="alert('XSS')">
      <input type="text" name="test" required>
      <button type="submit">Submit</button>
    </form>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onsubmit="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onsubmit'] },
    'onsubmit'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 form events injection')
})

Deno.test('XSS Detection - HTML5 scroll events injection', async () => {
  const service = new ResponseService()
  const response = `
    <div style="height: 1000px;" onscroll="alert('XSS')">Scroll me</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onscroll="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onscroll'] },
    'onscroll'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 scroll events injection')
})

Deno.test('XSS Detection - HTML5 touch events injection', async () => {
  const service = new ResponseService()
  const response = `
    <div ontouchstart="alert('XSS')" ontouchend="alert('XSS')" ontouchmove="alert('XSS')">Touch me</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'ontouchstart="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['ontouchstart'] },
    'ontouchstart'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 touch events injection')
})

Deno.test('XSS Detection - HTML5 wheel events injection', async () => {
  const service = new ResponseService()
  const response = `
    <div onwheel="alert('XSS')" style="width: 100px; height: 100px; background: red;">Scroll wheel here</div>
  `
  const result = await service.analyze(
    {
      url: 'https://example.com',
      status: 200,
      headers: {},
      text: () => Promise.resolve(response),
      ok: true,
      redirected: false,
      statusText: 'OK',
      body: null
    },
    'onwheel="alert(\'XSS\')"',
    { url: 'https://example.com', method: 'GET', parameters: ['onwheel'] },
    'onwheel'
  )
  assertExists(result)
  assertEquals(result.confirmed, true, 'Should be valid XSS - HTML5 wheel events injection')
})
