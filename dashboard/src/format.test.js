import { test } from 'node:test'
import assert from 'node:assert/strict'
import { detail, parseRoute, summarizeResult, timeLeft, tone } from './format.js'

test('routes', () => {
  assert.deepEqual(parseRoute(''), { page: 'pending' })
  assert.deepEqual(parseRoute('#/denials'), { page: 'denials' })
  assert.deepEqual(parseRoute('#/runs/run_abc'), { page: 'run', id: 'run_abc' })
  assert.deepEqual(parseRoute('#/nope'), { page: 'pending' })
})

test('tones flag every blocked step as bad', () => {
  for (const s of ['call.denied', 'call.args_mismatch', 'call.replay_blocked', 'approval.unauthorized',
    'approval.expired', 'approval.notify_failed']) assert.equal(tone(s), 'bad', s)
  assert.equal(tone('approval.decided', { decision: 'approved' }), 'good')
  assert.equal(tone('approval.decided', { decision: 'rejected' }), 'bad')
  assert.equal(tone('approval.requested'), 'wait')
})

test('decision detail names the human and channel', () => {
  const d = detail({ step: 'approval.decided', data: { decision: 'approved', approver: { channel: 'slack', id: 'U1', name: 'tim' }, note: 'ok' } })
  assert.equal(d, 'approved by tim via slack ("ok")')
})

test('time left', () => {
  assert.equal(timeLeft(100, 100), 'expired')
  assert.equal(timeLeft(130, 100), '30s left')
  assert.equal(timeLeft(100 + 3600 + 120, 100), '1h 2m left')
})

test('results render as readable text, not escaped JSON', () => {
  const r = summarizeResult(JSON.stringify({ key: 'public/t.md', content: '# Ticket\nFrom: Jordan' }))
  assert.equal(r, 'key: public/t.md · content: # Ticket From: Jordan')
  assert.ok(summarizeResult(JSON.stringify({ c: 'x'.repeat(500) })).endsWith('…'))
  assert.equal(summarizeResult('plain'), 'plain')
})
