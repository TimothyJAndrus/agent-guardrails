import { StrictMode, useCallback, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { completeSignIn, currentTokens, decodeJwt, loadConfig, signIn, signOut } from './auth.js'
import { STEP_LABELS, detail, fmtTime, parseRoute, timeLeft, tone } from './format.js'
import './styles.css'

function useApi(cfg) {
  return useCallback(async (path, opts = {}) => {
    const t = currentTokens()
    if (!t) { signIn(cfg); return new Promise(() => {}) }
    const r = await fetch(cfg.apiUrl.replace(/\/$/, '') + path, {
      ...opts,
      headers: { Authorization: `Bearer ${t.id_token}`, 'Content-Type': 'application/json', ...(opts.headers || {}) },
    })
    const body = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`)
    return body
  }, [cfg])
}

function useHash() {
  const [hash, setHash] = useState(window.location.hash)
  useEffect(() => {
    const f = () => setHash(window.location.hash)
    window.addEventListener('hashchange', f)
    return () => window.removeEventListener('hashchange', f)
  }, [])
  return parseRoute(hash)
}

function Args({ args }) {
  return <pre className="args">{JSON.stringify(args, null, 2)}</pre>
}

function Pending({ api }) {
  const [items, setItems] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const [notes, setNotes] = useState({})
  const load = useCallback(() => api('/v1/dashboard/pending').then(r => setItems(r.items)).catch(e => setErr(e.message)), [api])
  useEffect(() => { load(); const i = setInterval(load, 5000); return () => clearInterval(i) }, [load])
  const decide = async (id, decision) => {
    setBusy(id); setErr('')
    try { await api(`/v1/dashboard/calls/${id}/decide`, { method: 'POST', body: JSON.stringify({ decision, note: notes[id] || '' }) }) }
    catch (e) { setErr(e.message) }
    setBusy(''); load()
  }
  if (!items) return <p className="muted">Loading…</p>
  return (
    <section>
      {err && <p className="error">{err}</p>}
      {items.length === 0 && <p className="muted">Nothing is waiting for a decision.</p>}
      {items.map(c => (
        <article key={c.id} className="card wait">
          <header>
            <div><b>{c.agent}</b> wants to call <code>{c.tool}</code></div>
            <span className="pill">{timeLeft(c.expires_at)}</span>
          </header>
          <p className="muted">Rule <code>{c.rule}</code>: {c.reason}</p>
          <Args args={c.args} />
          {c.context && <p className="muted">Agent's stated reason (recorded, not used by the policy): {c.context}</p>}
          <input placeholder="Note (optional)" value={notes[c.id] || ''} onChange={e => setNotes({ ...notes, [c.id]: e.target.value })} />
          <div className="actions">
            <button className="approve" disabled={busy === c.id} onClick={() => decide(c.id, 'approve')}>Approve</button>
            <button className="reject" disabled={busy === c.id} onClick={() => decide(c.id, 'reject')}>Reject</button>
            <a href={`#/runs/${encodeURIComponent(c.run)}`}>Open run</a>
          </div>
        </article>
      ))}
    </section>
  )
}

function CallTable({ items, empty }) {
  if (!items) return <p className="muted">Loading…</p>
  if (items.length === 0) return <p className="muted">{empty}</p>
  return (
    <table>
      <thead><tr><th>When</th><th>Agent</th><th>Tool</th><th>Rule</th><th>Reason</th><th></th></tr></thead>
      <tbody>{items.map(c => (
        <tr key={c.id}>
          <td>{fmtTime(c.created)}</td><td>{c.agent}</td><td><code>{c.tool}</code></td><td><code>{c.rule}</code></td>
          <td>{c.reason}</td><td><a href={`#/runs/${encodeURIComponent(c.run)}`}>Replay</a></td>
        </tr>))}
      </tbody>
    </table>
  )
}

function Denials({ api }) {
  const [items, setItems] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => { api('/v1/dashboard/denials').then(r => setItems(r.items)).catch(e => setErr(e.message)) }, [api])
  return <section>{err && <p className="error">{err}</p>}<CallTable items={items} empty="No denials yet." /></section>
}

function Runs({ api }) {
  const [items, setItems] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => { api('/v1/dashboard/runs').then(r => setItems(r.items)).catch(e => setErr(e.message)) }, [api])
  if (err) return <p className="error">{err}</p>
  if (!items) return <p className="muted">Loading…</p>
  return (
    <table>
      <thead><tr><th>Started</th><th>Agent</th><th>Task</th><th>Status</th></tr></thead>
      <tbody>{items.map(r => (
        <tr key={r.id}>
          <td><a href={`#/runs/${encodeURIComponent(r.id)}`}>{fmtTime(r.started)}</a></td>
          <td>{r.agent}</td><td className="task">{r.task}</td><td>{r.status}</td>
        </tr>))}
      </tbody>
    </table>
  )
}

function Run({ api, id }) {
  const [rep, setRep] = useState(null)
  const [err, setErr] = useState('')
  const [open, setOpen] = useState({})
  useEffect(() => { api(`/v1/dashboard/runs/${encodeURIComponent(id)}`).then(setRep).catch(e => setErr(e.message)) }, [api, id])
  if (err) return <p className="error">{err}</p>
  if (!rep) return <p className="muted">Loading…</p>
  const t0 = rep.events[0]?.ts || 0
  return (
    <section>
      <h2>{rep.run.agent}: <span className="task">{rep.run.task}</span></h2>
      <p className={rep.chain.ok ? 'chain ok' : 'chain broken'}>
        {rep.chain.ok
          ? `Audit chain verified: ${rep.chain.count} events, head ${rep.chain.head.slice(0, 12)}…`
          : `Audit chain BROKEN at event ${rep.chain.broken_at} (${rep.chain.why}). This record has been altered.`}
      </p>
      <ol className="timeline">
        {rep.events.map(ev => (
          <li key={ev.seq} className={tone(ev.step, ev.data)} onClick={() => setOpen({ ...open, [ev.seq]: !open[ev.seq] })}>
            <span className="t">+{(ev.ts - t0).toFixed(1)}s</span>
            <span className="step">{STEP_LABELS[ev.step] || ev.step}</span>
            {ev.tool && <code>{ev.tool}</code>}
            <span className="detail">{detail(ev)}</span>
            {open[ev.seq] && <pre className="args">{JSON.stringify(ev, null, 2)}</pre>}
          </li>
        ))}
      </ol>
    </section>
  )
}

function Policy({ api }) {
  const [doc, setDoc] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => { api('/v1/dashboard/policy').then(setDoc).catch(e => setErr(e.message)) }, [api])
  if (err) return <p className="error">{err}</p>
  if (!doc) return <p className="muted">Loading…</p>
  return (
    <section>
      <p>Default: <b>{doc.default || 'deny'}</b>. Approvals expire after {doc.approval?.expires_in || 900}s.</p>
      <table>
        <thead><tr><th>Rule</th><th>Tool</th><th>Effect</th><th>When</th><th>Per run</th></tr></thead>
        <tbody>{(doc.rules || []).map(r => (
          <tr key={r.id}><td><code>{r.id}</code><div className="muted">{r.description}</div></td><td><code>{r.tool}</code></td>
            <td><span className={`pill ${r.effect}`}>{r.effect}</span></td>
            <td><code>{r.when ? JSON.stringify(r.when) : 'always'}</code></td><td>{r.max_per_run ?? ''}</td></tr>))}
        </tbody>
      </table>
    </section>
  )
}

function App({ cfg }) {
  const api = useApi(cfg)
  const route = useHash()
  const t = currentTokens()
  const email = t ? decodeJwt(t.id_token).email : ''
  const tabs = [['pending', 'Waiting for you'], ['denials', 'Denials'], ['runs', 'Runs'], ['policy', 'Policy']]
  const page = { pending: <Pending api={api} />, denials: <Denials api={api} />, runs: <Runs api={api} />,
    policy: <Policy api={api} />, run: <Run api={api} id={route.id} /> }[route.page]
  return (
    <main>
      <nav>
        <b>agent-guardrails</b>
        {tabs.map(([k, label]) => <a key={k} href={`#/${k}`} className={route.page === k ? 'on' : ''}>{label}</a>)}
        <span className="spacer" />
        {email && <span className="muted">{email}</span>}
        <button className="link" onClick={() => signOut(cfg)}>Sign out</button>
      </nav>
      {page}
    </main>
  )
}

async function boot() {
  const root = createRoot(document.getElementById('root'))
  try {
    const cfg = await loadConfig()
    await completeSignIn(cfg)
    if (!currentTokens()) { await signIn(cfg); return }
    root.render(<StrictMode><App cfg={cfg} /></StrictMode>)
  } catch (e) {
    root.render(<main><p className="error">{e.message}</p></main>)
  }
}

boot()
