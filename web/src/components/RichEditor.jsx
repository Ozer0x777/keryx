import { t as tr } from '../i18n.js'
import { EditorContent, useEditor } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import Image from '@tiptap/extension-image'
import { useEffect, useRef } from 'react'
import { useConfirm } from './Confirm.jsx'

// Éditeur riche (TipTap). Le HTML produit est assaini côté serveur (nh3, liste blanche) avant stockage.
export default function RichEditor({ value, onChange, label, onImage, templates, minHeight = 120 }) {
  const fileRef = useRef(null)
  const [ask, dialog] = useConfirm()
  const editor = useEditor({
    injectCSS: false,  // CSP sans style-src 'unsafe-inline' : les styles de l'éditeur sont dans styles.css
    extensions: [
      StarterKit.configure({ heading: { levels: [2, 3] }, link: { openOnClick: false, protocols: ['https', 'mailto'] } }),
      Image.configure({ inline: false }),
    ],
    content: value || '',
    onUpdate: ({ editor: e }) => onChange(e.isEmpty ? '' : e.getHTML()),
    editorProps: { attributes: { 'aria-label': label, class: 'rich-content', style: `min-height:${minHeight}px` } },
  })

  useEffect(() => {
    if (editor && value === '' && !editor.isEmpty) editor.commands.clearContent()
  }, [value, editor])

  if (!editor) return null
  const btn = (name, title, action, active) => (
    <button type="button" className={`tool${active ? ' active' : ''}`} aria-label={title} title={title}
      onClick={action}>{name}</button>
  )
  const setLink = async () => {
    const current = editor.getAttributes('link').href || ''
    const r = await ask({
      title: current ? tr('Modifier le lien du texte sélectionné') : tr('Ajouter un lien au texte sélectionné'),
      fields: [{ name: 'url', label: tr('Adresse du lien (https://…)'), initial: current, required: false, maxLength: 2000, placeholder: 'https://',
        hint: current ? tr('Laisser vide pour retirer le lien.') : tr('Seules les adresses https:// sont acceptées.'),
        validate: (v) => (/^https:\/\/\S+$/.test(v) ? '' : tr("L'adresse doit commencer par https:// et ne pas contenir d'espace.")) }],
      confirm: current ? tr('Mettre à jour le lien') : tr('Ajouter le lien'),
    })
    if (!r) { editor.commands.focus(); return }
    if (!r.values.url) editor.chain().focus().unsetLink().run()
    else editor.chain().focus().extendMarkRange('link').setLink({ href: r.values.url }).run()
  }
  return (
    <div className="editor">
      <div className="toolbar" role="toolbar" aria-label={tr("Mise en forme")}>
        {btn('H2', tr('Titre de section'), () => editor.chain().focus().toggleHeading({ level: 2 }).run(), editor.isActive('heading', { level: 2 }))}
        {btn('B', tr('Gras'), () => editor.chain().focus().toggleBold().run(), editor.isActive('bold'))}
        {btn('I', tr('Italique'), () => editor.chain().focus().toggleItalic().run(), editor.isActive('italic'))}
        {btn('•', tr('Liste à puces'), () => editor.chain().focus().toggleBulletList().run(), editor.isActive('bulletList'))}
        {btn('1.', tr('Liste numérotée'), () => editor.chain().focus().toggleOrderedList().run(), editor.isActive('orderedList'))}
        {btn('{ }', tr('Bloc de code'), () => editor.chain().focus().toggleCodeBlock().run(), editor.isActive('codeBlock'))}
        {btn('↗', tr('Lien'), setLink, editor.isActive('link'))}
        {templates?.length > 0 && (
          <select className="tpl" aria-label={tr("Insérer un modèle")} value="" onChange={(e) => {
            const m = templates.find((x) => x.id === e.target.value)
            if (m) editor.chain().focus().insertContent(m.body_html).run()
          }}>
            <option value="">{tr("Modèle…")}</option>
            {templates.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
          </select>
        )}
        {onImage && btn('▣', tr('Image (PNG, JPEG, WebP)'), () => fileRef.current?.click(), false)}
        {onImage && (
          <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" hidden
            onChange={async (e) => {
              const f = e.target.files?.[0]
              e.target.value = ''
              if (!f) return
              const src = await onImage(f)
              if (src) editor.chain().focus().setImage({ src, alt: f.name }).run()
            }} />
        )}
      </div>
      <EditorContent editor={editor} />
      {dialog}
    </div>
  )
}
