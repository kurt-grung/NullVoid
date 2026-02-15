import { useEffect, useState } from 'react'
import { getScans, getScan, isApiUnavailableError, type ScanSummary, type ScanDetail } from '../api'

export default function Executive() {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [totalThreats, setTotalThreats] = useState(0)
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 })
  const [packageThreats, setPackageThreats] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(true)
  const [apiUnavailable, setApiUnavailable] = useState(false)

  useEffect(() => {
    getScans()
      .then((r) => setScans(r.scans))
      .catch((e) => {
        if (isApiUnavailableError(e)) setApiUnavailable(true)
        else setScans([])
      })
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

  if (loading) return (
    <div className="text-center py-12 text-neutral-500 dark:text-neutral-400">Loading...</div>
  )

  const topPackages = Object.entries(packageThreats)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)

  return (
    <>
      <h1>Executive Overview</h1>
      {apiUnavailable && (
        <div className="card-minimal border-l-4 border-l-neutral-400 dark:border-l-neutral-500" role="status">
          <p className="text-neutral-600 dark:text-neutral-400 text-sm font-medium">No API connected. On Vercel: set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN, then check deployment logs if issues persist.</p>
        </div>
      )}
      <div className="grid grid-cols-[repeat(auto-fill,minmax(160px,1fr))] gap-3 mb-6">
        <div className="metric-minimal">
          <div className="value">{scans.length}</div>
          <div className="label">Total Scans</div>
        </div>
        <div className="metric-minimal">
          <div className="value">{completed.length}</div>
          <div className="label">Completed</div>
        </div>
        <div className="metric-minimal">
          <div className="value">{totalThreats}</div>
          <div className="label">Threats Found</div>
        </div>
      </div>

      <div className="card-minimal">
        <h3>Severity Distribution</h3>
        <div className="flex gap-4 flex-wrap mt-3 text-sm">
          <span className="text-red-600 dark:text-red-400">CRITICAL: {severityCounts.CRITICAL ?? 0}</span>
          <span className="text-orange-600 dark:text-orange-400">HIGH: {severityCounts.HIGH ?? 0}</span>
          <span className="text-amber-600 dark:text-amber-400">MEDIUM: {severityCounts.MEDIUM ?? 0}</span>
          <span className="text-green-600 dark:text-green-400">LOW: {severityCounts.LOW ?? 0}</span>
        </div>
      </div>

      <div className="card-minimal">
        <h3>Top Packages by Threat Count</h3>
        {topPackages.length === 0 ? (
          <p className="text-neutral-500 dark:text-neutral-400 text-sm mt-3">No threat data yet. Run scans to see results.</p>
        ) : (
          <ul className="list-none p-0 m-0 mt-3">
            {topPackages.map(([pkg, count]) => (
              <li key={pkg} className="list-item-minimal">
                <code>{pkg}</code> — {count} threat{count !== 1 ? 's' : ''}
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  )
}
