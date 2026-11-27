import { useEffect, useRef } from 'react'

// Journal brut (blocs <pre><code>) : adresses IP et compte visé mis en évidence. Seul le texte est découpé, en nœuds
// texte et <mark> créés ici : le contenu n'est jamais réinterprété comme du HTML.
const MOTIF = /(\b\d{1,3}(?:\.\d{1,3}){3}\b)|((?:invalid user|user|account|for(?!\s+invalid\b))\s+)([^\s:;,'"()]+)/gi
export function surligner(racine) {
  for (const code of racine.querySelectorAll('pre code, pre.wz-log')) {
    if (code.dataset.surligne) continue
    code.dataset.surligne = '1'
    const marcheur = document.createTreeWalker(code, NodeFilter.SHOW_TEXT)
    const noeuds = []
    while (marcheur.nextNode()) noeuds.push(marcheur.currentNode)
    for (const n of noeuds) {
      const texte = n.nodeValue
      MOTIF.lastIndex = 0
      if (!MOTIF.test(texte)) continue
      MOTIF.lastIndex = 0
      const frag = document.createDocumentFragment()
      let i = 0
      for (const m of texte.matchAll(MOTIF)) {
        frag.append(document.createTextNode(texte.slice(i, m.index)))
        if (m[1]) {
          const mk = document.createElement('mark'); mk.className = 'hl-ip'; mk.textContent = m[1]; frag.append(mk)
        } else {
          frag.append(document.createTextNode(m[2]))
          const mk = document.createElement('mark'); mk.className = 'hl-user'; mk.textContent = m[3]; frag.append(mk)
        }
        i = m.index + m[0].length
      }
      frag.append(document.createTextNode(texte.slice(i)))
      n.replaceWith(frag)
    }
  }
}

// Le HTML affiché ici (description, commentaires, synthèse) est assaini côté serveur (nh3, liste blanche).
export default function Html({ html, highlight = false }) {
  const ref = useRef(null)
  useEffect(() => { if (highlight && ref.current) surligner(ref.current) }, [html, highlight])
  return <div ref={ref} className="rich-content" dangerouslySetInnerHTML={{ __html: html || '' }} />
}
