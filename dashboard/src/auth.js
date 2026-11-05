// Cognito hosted UI, authorization-code flow with PKCE. No SDK: three fetches and sessionStorage.
// The ID token is sent to the API (it carries `email`, which the gate matches against policy approvers).

const KEY = 'ag.tokens'
const VERIFIER = 'ag.pkce'

export async function loadConfig() {
  const r = await fetch('/config.json', { cache: 'no-store' })
  if (!r.ok) throw new Error('config.json missing: deploy the stack, or copy config.example.json for local dev')
  return r.json()
}

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function decodeJwt(token) {
  const part = token.split('.')[1]
  const json = atob(part.replace(/-/g, '+').replace(/_/g, '/'))
  return JSON.parse(decodeURIComponent(escape(json)))
}

export function currentTokens(now = Date.now()) {
  try {
    const t = JSON.parse(sessionStorage.getItem(KEY) || 'null')
    if (!t || !t.id_token) return null
    if (decodeJwt(t.id_token).exp * 1000 < now + 30_000) return null
    return t
  } catch {
    return null
  }
}

const redirectUri = () => window.location.origin + '/'

export async function signIn(cfg) {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)))
  sessionStorage.setItem(VERIFIER, JSON.stringify({ verifier, state, hash: window.location.hash }))
  const q = new URLSearchParams({
    response_type: 'code', client_id: cfg.userPoolClientId, redirect_uri: redirectUri(),
    scope: 'openid email', code_challenge_method: 'S256', code_challenge: challenge, state,
  })
  window.location.assign(`${cfg.cognitoDomain}/oauth2/authorize?${q}`)
}

export async function completeSignIn(cfg) {
  const params = new URLSearchParams(window.location.search)
  const code = params.get('code')
  if (!code) return false
  const saved = JSON.parse(sessionStorage.getItem(VERIFIER) || '{}')
  sessionStorage.removeItem(VERIFIER)
  if (!saved.verifier || params.get('state') !== saved.state) throw new Error('sign-in state mismatch; try again')
  const r = await fetch(`${cfg.cognitoDomain}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: cfg.userPoolClientId, code,
      redirect_uri: redirectUri(), code_verifier: saved.verifier,
    }),
  })
  if (!r.ok) throw new Error(`token exchange failed (${r.status})`)
  sessionStorage.setItem(KEY, JSON.stringify(await r.json()))
  window.history.replaceState(null, '', '/' + (saved.hash || ''))
  return true
}

export function signOut(cfg) {
  sessionStorage.removeItem(KEY)
  const q = new URLSearchParams({ client_id: cfg.userPoolClientId, logout_uri: redirectUri() })
  window.location.assign(`${cfg.cognitoDomain}/logout?${q}`)
}
