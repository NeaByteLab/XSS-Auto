import XssScanner from '@neabyte/xss-auto'

for (const testCase of JSON.parse(await Deno.readTextFile(`${Deno.cwd()}/examples/data.json`))) {
  console.log(`\n[${testCase.method}] ${testCase.description} @ ${testCase.url}`)
  await XssScanner.scan(testCase.url, {
    method: testCase.method,
    headers: {
      'User-Agent': 'XSS-Auto-Test/1.0.0',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    },
    delay: 0,
    useFirst: true,
    useInteractive: false
  })
}
