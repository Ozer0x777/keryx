// Client de l'API Keryx : cookies de session (HttpOnly) + en-tête CSRF en double soumission.
function csrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)keryx_csrf=([^;]+)/)
  return m ? decodeURIComponent(m[1]) : ''
}

export class ApiError extends Error {
  constructor(status, detail) {
    super(detail || `Erreur ${status}`)
    this.status = status
  }
}

export async function api(path, { method = 'GET', json, form, params } = {}) {
  let url = `/api/v1${path}`
  if (params) {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''))
    if ([...q].length) url += `?${q}`
  }
  const headers = {}
  let body
  if (json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(json)
  } else if (form) {
    body = form
  }
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken()
  const res = await fetch(url, { method, headers, body, credentials: 'same-origin' })
  const type = res.headers.get('content-type') || ''
  if (!res.ok) {
    let detail
    if (type.includes('json')) {
      const data = await res.json().catch(() => ({}))
      detail = data.detail || data.title
    }
    if (res.status === 401 && !path.startsWith('/auth/') && path !== '/me') {
      window.dispatchEvent(new Event('keryx:unauthorized'))
    }
    throw new ApiError(res.status, detail)
  }
  if (type.includes('json')) return res.json()
  return res.blob()
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
