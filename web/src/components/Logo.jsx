// Logo Keryx : « Concept H — Bouclier plein ». Liseré clair discret pour rester visible sur la barre latérale sombre.
export default function Logo({ size = 26 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 120 120" fill="none" aria-hidden="true" focusable="false">
      <path d="M60 10 L100 27 L100 66 C100 98 60 115 60 115 C60 115 20 98 20 66 L20 27 Z"
        fill="#141A26" stroke="#F7F4EC" strokeOpacity=".45" strokeWidth="3" strokeLinejoin="round" />
      <path d="M45 62 L80 93" stroke="#E2592F" strokeWidth="10" strokeLinecap="round" />
      <path d="M45 31 L45 93" stroke="#F7F4EC" strokeWidth="10" strokeLinecap="round" />
      <path d="M45 62 L80 31" stroke="#F7F4EC" strokeWidth="10" strokeLinecap="round" />
    </svg>
  )
}
