import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getScan, type ScanDetail, type Threat } from '../api'

export default function ScanDetailView() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<ScanDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    getScan(id)
      .then(setScan)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <div className="loading">Loading...</div>
  if (error) return <div className="error">{error}</div>
  if (!scan) return <div className="error">Scan not found</div>

  const r = scan.result
  const threats = r?.threats ?? []
  const risk = r?.riskAssessment

  return (
    <>
      <p><Link to="/scans">← Back to Scans</Link></p>
      <h1>Scan: {scan.target}</h1>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '1rem' }}>
        <span className={`status-badge status-${scan.status}`}>{scan.status}</span>
        <span style={{ color: 'var(--text-muted)' }}>
          {new Date(scan.createdAt).toLocaleString()}
          {scan.completedAt && ` — ${new Date(scan.completedAt).toLocaleString()}`}
        </span>
      </div>

      {scan.error && <div className="error">{scan.error}</div>}

      {r && (
        <>
          <div className="metric-grid">
            <div className="metric">
              <div className="metric-value">{r.summary?.totalPackages ?? 0}</div>
              <div className="metric-label">Packages</div>
            </div>
            <div className="metric">
              <div className="metric-value">{r.summary?.threatsFound ?? threats.length}</div>
              <div className="metric-label">Threats</div>
            </div>
            <div className="metric">
              <div className="metric-value">{r.summary?.scanDuration ?? 0}ms</div>
              <div className="metric-label">Duration</div>
            </div>
            {risk && (
              <div className="metric">
                <div className="metric-value">{(risk.overall * 100).toFixed(0)}%</div>
                <div className="metric-label">Risk Score</div>
              </div>
            )}
          </div>

          {risk && (
            <div className="card">
              <h3>Risk Breakdown</h3>
              <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
                <div>
                  <strong>Overall:</strong> {(risk.overall * 100).toFixed(1)}%
                </div>
                {Object.entries(risk.byCategory ?? {}).length > 0 && (
                  <div>
                    <strong>By Category:</strong>{' '}
                    {Object.entries(risk.byCategory).map(([k, v]) => `${k}: ${(v * 100).toFixed(0)}%`).join(', ')}
                  </div>
                )}
                {Object.entries(risk.bySeverity ?? {}).length > 0 && (
                  <div>
                    <strong>By Severity:</strong>{' '}
                    {Object.entries(risk.bySeverity).map(([k, v]) => (
                      <span key={k} className={`severity-${k.toLowerCase()}`} style={{ marginRight: '0.5rem' }}>
                        {k}: {typeof v === 'number' ? v.toFixed(2) : v}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="card">
            <h3>Threats ({threats.length})</h3>
            {threats.length === 0 ? (
              <p style={{ color: 'var(--text-muted)' }}>No threats found.</p>
            ) : (
              <ul className="threat-list">
                {threats.map((t: Threat, i: number) => (
                  <li key={i} className="threat-item">
                    <span className={`severity-${(t.severity ?? '').toLowerCase()}`} style={{ fontWeight: 600 }}>
                      {t.severity}
                    </span>
                    {' '}
                    {t.package && <code>{t.package}</code>}
                    {' — '}
                    {t.message}
                    {t.details && (
                      <div style={{ marginTop: '0.5rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                        {t.details.slice(0, 200)}...
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </>
  )
}
