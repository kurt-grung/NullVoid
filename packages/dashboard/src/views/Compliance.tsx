import { useEffect, useState } from 'react'
import { getScans, getScan, isApiUnavailableError, type ScanDetail } from '../api'

export default function Compliance() {
  const [scans, setScans] = useState<{ id: string; status: string }[]>([])
  const [riskData, setRiskData] = useState<Array<{ target: string; overall: number; byCategory: Record<string, number> }>>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [apiUnavailable, setApiUnavailable] = useState(false)

  useEffect(() => {
    getScans()
      .then((r) => {
        setScans(r.scans.filter((s) => s.status === 'completed'))
      })
      .catch((e) => {
        if (isApiUnavailableError(e)) setApiUnavailable(true)
        else setError(e.message)
      })
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

  if (loading) return (
    <div className="text-center py-12 text-neutral-500 dark:text-neutral-400">Loading...</div>
  )
  if (error && !apiUnavailable) return (
    <div className="alert-error mb-6">
      {error}
    </div>
  )

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
      {apiUnavailable && (
        <div className="alert-info mb-6" role="status">
          <p className="text-neutral-600 dark:text-neutral-400 text-sm font-medium">No API connected. On Vercel: set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN, then check deployment logs if issues persist.</p>
        </div>
      )}
      <p className="text-neutral-500 dark:text-neutral-400 text-sm mb-6">
        Control coverage and gap analysis based on scan risk assessments (C/I/A model).
      </p>

      <div className="grid grid-cols-[repeat(auto-fill,minmax(160px,1fr))] gap-3 mb-6">
        <div className="metric-minimal">
          <div className="value">{(avgRisk * 100).toFixed(1)}%</div>
          <div className="label">Average Risk (lower is better)</div>
        </div>
        <div className="metric-minimal">
          <div className="value">{riskData.length}</div>
          <div className="label">Scans with Risk Data</div>
        </div>
      </div>

      <div className="card-minimal">
        <h3>Control Coverage by Category</h3>
        <p className="text-neutral-500 dark:text-neutral-400 text-xs mt-2">
          Coverage = 100% − risk. Higher coverage indicates better control.
        </p>
        <div className="flex flex-col gap-3 mt-4">
          {Object.entries(categoryCoverage).map(([cat, cov]) => (
            <div key={cat}>
              <div className="flex justify-between mb-1 text-sm">
                <span className="capitalize text-neutral-700 dark:text-neutral-300">{cat}</span>
                <span className="text-neutral-600 dark:text-neutral-400">{cov.toFixed(1)}%</span>
              </div>
              <div className="h-1.5 bg-surface-muted dark:bg-dark-muted rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{
                    width: `${Math.min(100, cov)}%`,
                    backgroundColor:
                      cov >= 80 ? 'rgb(34, 197, 94)' : cov >= 50 ? 'rgb(234, 179, 8)' : 'rgb(249, 115, 22)',
                  }}
                />
              </div>
            </div>
          ))}
        </div>
        {Object.keys(categoryCoverage).length === 0 && (
          <p className="text-neutral-500 dark:text-neutral-400 text-sm mt-4">Run scans to see compliance data.</p>
        )}
      </div>

      <div className="card-minimal">
        <h3>Gap Analysis</h3>
        <p className="text-neutral-500 dark:text-neutral-400 text-xs mt-2">
          Categories with &lt;80% coverage may need attention for SOC 2 / ISO 27001 alignment.
        </p>
        <ul className="list-none p-0 m-0 mt-4">
          {Object.entries(categoryCoverage)
            .filter(([, cov]) => cov < 80)
            .map(([cat, cov]) => (
              <li key={cat} className="list-item-minimal">
                <span className="capitalize">{cat}</span>: {cov.toFixed(1)}% coverage — consider remediation
              </li>
            ))}
        </ul>
        {Object.entries(categoryCoverage).filter(([, cov]) => cov < 80).length === 0 &&
          Object.keys(categoryCoverage).length > 0 && (
            <p className="text-green-600 dark:text-green-400 text-sm mt-4">All categories meet 80%+ coverage.</p>
          )}
        {Object.keys(categoryCoverage).length === 0 && (
          <p className="text-neutral-500 dark:text-neutral-400 text-sm mt-4">No data yet.</p>
        )}
      </div>
    </>
  )
}
