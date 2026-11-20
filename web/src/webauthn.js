// Pont entre l'API WebAuthn du navigateur et le JSON du serveur (champs binaires en base64url).
const b64uToBuf = (s) => {
  const pad = '='.repeat((4 - (s.length % 4)) % 4)
  const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer
}
const bufToB64u = (buf) => {
  let s = ''
  new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b) })
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const webauthnSupported = () => typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials

export async function createCredential(options) {
  const cred = await navigator.credentials.create({ publicKey: {
    ...options,
    challenge: b64uToBuf(options.challenge),
    user: { ...options.user, id: b64uToBuf(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  } })
  return {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    response: { clientDataJSON: bufToB64u(cred.response.clientDataJSON), attestationObject: bufToB64u(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [] },
    clientExtensionResults: cred.getClientExtensionResults(),
  }
}

export async function getAssertion(options) {
  const cred = await navigator.credentials.get({ publicKey: {
    ...options,
    challenge: b64uToBuf(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  } })
  return {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    response: { clientDataJSON: bufToB64u(cred.response.clientDataJSON), authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature), userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null },
    clientExtensionResults: cred.getClientExtensionResults(),
  }
}
