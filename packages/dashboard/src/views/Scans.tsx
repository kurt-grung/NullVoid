import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getScans, triggerScan, isApiUnavailableError, type ScanSummary } from '../api'

export default function Scans() {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [apiUnavailable, setApiUnavailable] = useState(false)
  const [target, setTarget] = useState('.')
  const [submitting, setSubmitting] = useState(false)

  const refresh = () => {
    setError(null)
    getScans()
      .then((r) => setScans(r.scans))
      .catch((e) => {
        if (isApiUnavailableError(e)) setApiUnavailable(true)
        else setError(e.message)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    refresh()
  }, [])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    triggerScan(target)
      .then(() => {
        setTarget('.')
        refresh()
      })
      .catch((e) => setError(e.message))
      .finally(() => setSubmitting(false))
  }

  if (loading) return <div className="loading">Loading...</div>

  return (
    <>
      <h1>Scans</h1>
      {apiUnavailable && (
        <div className="api-unavailable" role="status">
          <p>No API connected. Deploy the NullVoid API to view and run scans.</p>
          <p style={{ marginTop: '0.5rem', fontSize: '0.9rem' }}>
            If the API is deployed on Vercel, add <code>TURSO_DATABASE_URL</code> and{' '}
            <code>TURSO_AUTH_TOKEN</code> in Vercel → Settings → Environment Variables.
          </p>
        </div>
      )}
      {error && !apiUnavailable && <div className="error">{error}</div>}

      <div className="card">
        <h3>New Scan</h3>
        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Target path (e.g. . or ./packages/api)"
            style={{
              flex: 1,
              padding: '0.5rem',
              background: 'var(--bg)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              color: 'var(--text)',
            }}
          />
          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Starting...' : 'Start Scan'}
          </button>
        </form>
      </div>

      <div className="card">
        <h3>Recent Scans</h3>
        <ul className="threat-list">
          {scans.map((s) => (
            <li key={s.id} className="threat-item">
              <Link to={`/scans/${s.id}`} style={{ color: 'inherit' }}>
                <span className={`status-badge status-${s.status}`}>{s.status}</span>
                {' '}
                <code>{s.target}</code>
                {' '}
                <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                  {new Date(s.createdAt).toLocaleString()}
                </span>
              </Link>
            </li>
          ))}
        </ul>
        {scans.length === 0 && <p style={{ color: 'var(--text-muted)' }}>No scans yet.</p>}
      </div>
    </>
  )
}
