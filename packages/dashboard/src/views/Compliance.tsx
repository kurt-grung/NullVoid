import { useEffect, useState } from 'react'
import { getScans, getScan, type ScanDetail } from '../api'

export default function Compliance() {
  const [scans, setScans] = useState<{ id: string; status: string }[]>([])
  const [riskData, setRiskData] = useState<Array<{ target: string; overall: number; byCategory: Record<string, number> }>>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getScans()
      .then((r) => {
        setScans(r.scans.filter((s) => s.status === 'completed'))
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (scans.length === 0) return
    Promise.all(scans.slice(0, 10).map((s) => getScan(s.id)))
      .then((details) => {
        setRiskData(
          details
            .filter((d): d is ScanDetail => !!d.result?.riskAssessment)
            .map((d) => ({
              target: d.target,
              overall: d.result!.riskAssessment!.overall,
              byCategory: d.result!.riskAssessment!.byCategory ?? {},
            }))
        )
      })
      .catch(() => {})
  }, [scans.length])

  if (loading) return <div className="loading">Loading...</div>
  if (error) return <div className="error">{error}</div>

  const avgRisk = riskData.length > 0
    ? riskData.reduce((a, r) => a + r.overall, 0) / riskData.length
    : 0

  // Coverage = 100% - risk. For scans missing a category, treat as 100% coverage.
  const allCategories = new Set<string>()
  for (const r of riskData) {
    for (const k of Object.keys(r.byCategory)) allCategories.add(k)
  }
  const categoryCoverage: Record<string, number> = {}
  const numScans = riskData.length
  for (const k of allCategories) {
    let sum = 0
    for (const r of riskData) {
      const v = r.byCategory[k]
      sum += v !== undefined ? 1 - v : 1
    }
    categoryCoverage[k] = numScans > 0 ? (sum / numScans) * 100 : 0
  }

  return (
    <>
      <h1>Compliance</h1>
      <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>
        Control coverage and gap analysis based on scan risk assessments (C/I/A model).
      </p>

      <div className="metric-grid">
        <div className="metric">
          <div className="metric-value">{(avgRisk * 100).toFixed(1)}%</div>
          <div className="metric-label">Average Risk (lower is better)</div>
        </div>
        <div className="metric">
          <div className="metric-value">{riskData.length}</div>
          <div className="metric-label">Scans with Risk Data</div>
        </div>
      </div>

      <div className="card">
        <h3>Control Coverage by Category</h3>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Coverage = 100% − risk. Higher coverage indicates better control.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {Object.entries(categoryCoverage).map(([cat, cov]) => (
            <div key={cat}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                <span style={{ textTransform: 'capitalize' }}>{cat}</span>
                <span>{cov.toFixed(1)}%</span>
              </div>
              <div
                style={{
                  height: 8,
                  background: 'var(--bg)',
                  borderRadius: 4,
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${Math.min(100, cov)}%`,
                    height: '100%',
                    background: cov >= 80 ? 'var(--low)' : cov >= 50 ? 'var(--medium)' : 'var(--high)',
                  }}
                />
              </div>
            </div>
          ))}
        </div>
        {Object.keys(categoryCoverage).length === 0 && (
          <p style={{ color: 'var(--text-muted)' }}>Run scans to see compliance data.</p>
        )}
      </div>

      <div className="card">
        <h3>Gap Analysis</h3>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Categories with &lt;80% coverage may need attention for SOC 2 / ISO 27001 alignment.
        </p>
        <ul className="threat-list">
          {Object.entries(categoryCoverage)
            .filter(([, cov]) => cov < 80)
            .map(([cat, cov]) => (
              <li key={cat} className="threat-item">
                <span style={{ textTransform: 'capitalize' }}>{cat}</span>: {cov.toFixed(1)}% coverage — consider remediation
              </li>
            ))}
        </ul>
        {Object.entries(categoryCoverage).filter(([, cov]) => cov < 80).length === 0 &&
          Object.keys(categoryCoverage).length > 0 && (
            <p style={{ color: 'var(--low)' }}>All categories meet 80%+ coverage.</p>
          )}
        {Object.keys(categoryCoverage).length === 0 && (
          <p style={{ color: 'var(--text-muted)' }}>No data yet.</p>
        )}
      </div>
    </>
  )
}
