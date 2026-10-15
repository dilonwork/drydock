import { useEffect, useState } from 'react'
import { api, type AuditEntry } from '../api'

function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleString('en-US', { hour12: false })
}

const PAGE = 100

export default function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [total, setTotal] = useState(0)
  const [filter, setFilter] = useState('')
  const [msg, setMsg] = useState('')

  const refresh = (action?: string) => {
    setMsg('')
    api.listAudit({ limit: PAGE, action: action?.trim() || undefined })
      .then(r => { setEntries(r.entries); setTotal(r.total) })
      .catch((e: Error) => setMsg('✕ ' + e.message))
  }
  useEffect(() => { refresh() }, [])

  const loadMore = async () => {
    try {
      const r = await api.listAudit({ limit: PAGE, offset: entries.length, action: filter.trim() || undefined })
      setEntries(prev => [...prev, ...r.entries])
      setTotal(r.total)
    } catch (e: unknown) { setMsg('✕ ' + (e as Error).message) }
  }

  return (
    <>
      <div className="page-head"><h1>Audit log</h1><span className="tag t-gray">{total}</span></div>
      <div className="page-sub">Who did what, newest first. Every state-changing action is recorded; reads are not.</div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            placeholder="Filter by action prefix, e.g. auth. or job."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') refresh(filter) }}
            style={{ flex: 1 }}
          />
          <button className="btn" onClick={() => refresh(filter)}>Filter</button>
          <button className="btn" onClick={() => { setFilter(''); refresh() }}>Clear</button>
        </div>
      </div>

      {msg && <div className="warn" style={{ marginBottom: 12 }}>{msg}</div>}

      <div className="card">
        <table>
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr></thead>
          <tbody>
            {entries.map(e => (
              <tr key={e.id}>
                <td className="mono" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{fmtTs(e.ts)}</td>
                <td><b>{e.username}</b></td>
                <td><span className="tag t-blue mono" style={{ fontSize: 11 }}>{e.action}</span></td>
                <td className="mut" style={{ fontSize: 12 }}>{e.detail || <span className="dim">—</span>}</td>
              </tr>
            ))}
            {entries.length === 0 && (
              <tr><td colSpan={4} className="dim" style={{ textAlign: 'center', padding: 24 }}>
                No audit entries yet.
              </td></tr>
            )}
          </tbody>
        </table>
        {entries.length < total && (
          <div style={{ padding: 12, textAlign: 'center' }}>
            <button className="btn" onClick={loadMore}>
              Load more ({total - entries.length} remaining)
            </button>
          </div>
        )}
      </div>
    </>
  )
}
