import { useEffect, useState } from 'react'
import { getScans, getScan, type ScanSummary, type ScanDetail } from '../api'

export default function Executive() {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [totalThreats, setTotalThreats] = useState(0)
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 })
  const [packageThreats, setPackageThreats] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getScans()
      .then((r) => setScans(r.scans))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const completed = scans.filter((s) => s.status === 'completed')

  useEffect(() => {
    if (completed.length === 0) return
    let cancelled = false
    const load = async () => {
      let threats = 0
      const sev: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
      const pkg: Record<string, number> = {}
      for (const s of completed.slice(0, 20)) {
        if (cancelled) return
        try {
          const d = (await getScan(s.id)) as ScanDetail
          if (d.result?.threats) {
            threats += d.result.threats.length
            for (const t of d.result.threats) {
              sev[t.severity] = (sev[t.severity] ?? 0) + 1
              if (t.package) pkg[t.package] = (pkg[t.package] ?? 0) + 1
            }
          }
        } catch {
          /* skip */
        }
      }
      if (!cancelled) {
        setTotalThreats(threats)
        setSeverityCounts(sev)
        setPackageThreats(pkg)
      }
    }
    load()
    return () => { cancelled = true }
  }, [completed.length])

  if (loading) return <div className="loading">Loading...</div>
  if (error) return <div className="error">{error}</div>

  const topPackages = Object.entries(packageThreats)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)

  return (
    <>
      <h1>Executive Overview</h1>
      <div className="metric-grid">
        <div className="metric">
          <div className="metric-value">{scans.length}</div>
          <div className="metric-label">Total Scans</div>
        </div>
        <div className="metric">
          <div className="metric-value">{completed.length}</div>
          <div className="metric-label">Completed</div>
        </div>
        <div className="metric">
          <div className="metric-value">{totalThreats}</div>
          <div className="metric-label">Threats Found</div>
        </div>
      </div>

      <div className="card">
        <h3>Severity Distribution</h3>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <span className="severity-critical">CRITICAL: {severityCounts.CRITICAL ?? 0}</span>
          <span className="severity-high">HIGH: {severityCounts.HIGH ?? 0}</span>
          <span className="severity-medium">MEDIUM: {severityCounts.MEDIUM ?? 0}</span>
          <span className="severity-low">LOW: {severityCounts.LOW ?? 0}</span>
        </div>
      </div>

      <div className="card">
        <h3>Top Packages by Threat Count</h3>
        {topPackages.length === 0 ? (
          <p style={{ color: 'var(--text-muted)' }}>No threat data yet. Run scans to see results.</p>
        ) : (
          <ul className="threat-list">
            {topPackages.map(([pkg, count]) => (
              <li key={pkg} className="threat-item">
                <code>{pkg}</code> — {count} threat{count !== 1 ? 's' : ''}
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  )
}
