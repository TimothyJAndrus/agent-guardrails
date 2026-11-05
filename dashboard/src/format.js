// Pure helpers (no DOM) so they can be unit-tested with `node --test`.

export const STEP_LABELS = {
  'run.started': 'Run started',
  'run.ended': 'Run ended',
  'call.allowed': 'Allowed by policy',
  'call.denied': 'Denied by policy',
  'call.executing': 'Executing',
  'call.result': 'Result',
  'call.args_mismatch': 'BLOCKED: arguments changed after approval',
  'call.replay_blocked': 'BLOCKED: second execution',
  'approval.requested': 'Waiting for a human',
  'approval.notified': 'Approver notified',
  'approval.notify_failed': 'Notification failed',
  'approval.decided': 'Human decision',
  'approval.expired': 'Approval expired',
  'approval.unauthorized': 'BLOCKED: not an approver',
  'workflow.resumed': 'Workflow resumed',
  'workflow.resume_failed': 'Workflow resume failed',
}

export function tone(step, data = {}) {
  if (step.includes('denied') || step.includes('mismatch') || step.includes('blocked') ||
      step.includes('unauthorized') || step.includes('failed') || step === 'approval.expired') return 'bad'
  if (step === 'approval.decided') return data.decision === 'approved' ? 'good' : 'bad'
  if (step === 'call.result') return data.ok ? 'good' : 'bad'
  if (step.startsWith('approval.')) return 'wait'
  if (step === 'call.allowed') return 'good'
  return 'neutral'
}

export function detail(ev) {
  const d = ev.data || {}
  switch (ev.step) {
    case 'run.started': return d.task || ''
    case 'run.ended': return [d.status, d.answer].filter(Boolean).join(': ')
    case 'call.allowed':
    case 'call.denied':
    case 'approval.requested': return `${d.rule}: ${d.reason}`
    case 'approval.decided':
      return `${d.decision} by ${d.approver?.name || d.approver?.id} via ${d.approver?.channel}${d.note ? ` ("${d.note}")` : ''}`
    case 'approval.notified': return `via ${d.channel}`
    case 'approval.notify_failed': return `${d.channel}: ${d.error}`
    case 'call.result': return summarizeResult(d.result)
    case 'call.executing': return `by ${d.principal}`
    default: return ''
  }
}

export function fmtTime(ts) {
  if (!ts) return ''
  const d = new Date(ts * 1000)
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function timeLeft(expiresAt, now = Date.now() / 1000) {
  const s = Math.max(0, Math.round(expiresAt - now))
  if (s === 0) return 'expired'
  if (s < 60) return `${s}s left`
  if (s < 3600) return `${Math.floor(s / 60)}m left`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m left`
}

export function parseRoute(hash) {
  const h = (hash || '').replace(/^#\/?/, '')
  const [page, id] = h.split('/')
  if (page === 'runs' && id) return { page: 'run', id: decodeURIComponent(id) }
  if (['pending', 'denials', 'runs', 'policy'].includes(page)) return { page }
  return { page: 'pending' }
}

// Results are stored as JSON text; show them readably and short (the full event is one click away).
export function summarizeResult(text, limit = 220) {
  if (!text) return ''
  let v = text
  try { v = JSON.parse(text) } catch { return String(text).slice(0, limit) }
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const parts = Object.entries(v).map(([k, x]) => `${k}: ${typeof x === 'string' ? x.replace(/\s+/g, ' ') : JSON.stringify(x)}`)
    const s = parts.join(' · ')
    return s.length > limit ? s.slice(0, limit) + '…' : s
  }
  const s = typeof v === 'string' ? v : JSON.stringify(v)
  return s.length > limit ? s.slice(0, limit) + '…' : s
}
