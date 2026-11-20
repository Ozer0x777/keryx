import { BASE, check, launch, login, startStack, waitUp } from './harness.mjs'
import { readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const stack = startStack()
try {
  await waitUp()
  const browser = await launch()
  const dir = join(dirname(fileURLToPath(import.meta.url)), 'scenarios')
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.mjs') && (!process.env.E2E_ONLY || new RegExp(process.env.E2E_ONLY).test(x))).sort()) {
    console.log(`— ${f}`)
    await (await import(join(dir, f))).default({ browser, stack, BASE, check, login: (n) => login(browser, stack, n) })
  }
  await browser.close()
} finally { stack.stop() }
