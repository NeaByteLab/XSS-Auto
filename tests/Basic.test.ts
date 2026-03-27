import { assertEquals, assertExists } from '@std/assert'
import { ResponseService } from '@app/core/services/index.ts'

Deno.test('XSS Detection - a parameter (direct HTML)', async () => {
  const service = new ResponseService()
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

Deno.test('XSS Detection - b1 parameter (double quotes)', async () => {
  const service = new ResponseService()
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
  const service = new ResponseService()
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

Deno.test('XSS Detection - No reflection', async () => {
  const service = new ResponseService()
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
