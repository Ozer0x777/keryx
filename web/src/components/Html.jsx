// Le HTML affiché ici (description, commentaires, synthèse) est assaini côté serveur (nh3, liste blanche).
export default function Html({ html }) {
  return <div className="rich-content" dangerouslySetInnerHTML={{ __html: html || '' }} />
}
