import { BASE, check, launch, login, startStack, waitUp } from './harness.mjs'
import { copyFileSync, existsSync, readFileSync, readdirSync } from 'node:fs'
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
} finally {
  stack.stop()
  // Pare-feu applicatif (E2E_WAF) : règles déclenchées pendant la suite, par règle et par chemin. En mode détection,
  // c'est la liste des faux positifs à traiter avant le mode blocage ; E2E_WAF_LOG garde le journal complet.
  const log = join(stack.dir, 'waf.log')
  if (stack.waf && existsSync(log)) {
    if (process.env.E2E_WAF_LOG) copyFileSync(log, process.env.E2E_WAF_LOG)
    const hits = new Map()
    for (const line of readFileSync(log, 'utf8').split('\n')) {
      const id = /\[id \\?"(\d+)\\?"\]/.exec(line)?.[1]
      if (!id) continue
      const uri = (/\[uri \\?"([^"\\]*)\\?"\]/.exec(line)?.[1] || '?').replace(/\/[A-Z]+-\d+/g, '/{ref}').replace(/[0-9a-f-]{36}/g, '{id}').split('?')[0]
      const k = `${id} ${uri}`; hits.set(k, (hits.get(k) || 0) + 1)
    }
    console.log(`pare-feu applicatif (${stack.waf}) : ${hits.size ? hits.size + ' règle(s) et chemin(s) déclenchés' : 'aucune règle déclenchée'}`)
    for (const [k, n] of [...hits].sort()) console.log(`  ${k} ×${n}`)
  }
}
