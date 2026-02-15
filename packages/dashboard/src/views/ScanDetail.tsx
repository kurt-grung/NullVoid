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

  if (loading) return (
    <div className="text-center py-12 text-neutral-500 dark:text-neutral-400">Loading...</div>
  )
  if (error) return (
    <div className="card-minimal border-l-4 border-l-red-500 text-red-600 dark:text-red-400 text-sm">
      {error}
    </div>
  )
  if (!scan) return (
    <div className="card-minimal border-l-4 border-l-red-500 text-red-600 dark:text-red-400 text-sm">
      Scan not found
    </div>
  )

  const r = scan.result
  const threats = r?.threats ?? []
  const risk = r?.riskAssessment

  const statusClass =
    scan.status === 'pending'
      ? 'bg-amber-200 dark:bg-amber-900/50 text-amber-800 dark:text-amber-200'
      : scan.status === 'running'
        ? 'bg-blue-500 text-white'
        : scan.status === 'completed'
          ? 'bg-green-500 text-white'
          : 'bg-red-500 text-white'

  return (
    <>
      <p><Link to="/scans">← Back to Scans</Link></p>
      <h1>Scan: {scan.target}</h1>
      <div className="flex gap-2 items-center mb-4">
        <span className={`badge-minimal ${statusClass}`}>
          {scan.status}
        </span>
        <span className="text-neutral-500 dark:text-neutral-400 text-sm">
          {new Date(scan.createdAt).toLocaleString()}
          {scan.completedAt && ` — ${new Date(scan.completedAt).toLocaleString()}`}
        </span>
      </div>

      {scan.error && (
        <div className="card-minimal border-l-4 border-l-red-500 text-red-600 dark:text-red-400 text-sm mb-4">
          {scan.error}
        </div>
      )}

      {r && (
        <>
          <div className="grid grid-cols-[repeat(auto-fill,minmax(160px,1fr))] gap-3 mb-6">
            <div className="metric-minimal">
              <div className="value">{r.summary?.totalPackages ?? 0}</div>
              <div className="label">Packages</div>
            </div>
            <div className="metric-minimal">
              <div className="value">{r.summary?.threatsFound ?? threats.length}</div>
              <div className="label">Threats</div>
            </div>
            <div className="metric-minimal">
              <div className="value">{r.summary?.scanDuration ?? 0}ms</div>
              <div className="label">Duration</div>
            </div>
            {risk && (
              <div className="metric-minimal">
                <div className="value">{(risk.overall * 100).toFixed(0)}%</div>
                <div className="label">Risk Score</div>
              </div>
            )}
          </div>

          {risk && (
            <div className="card-minimal">
              <h3>Risk Breakdown</h3>
              <div className="flex gap-6 flex-wrap mt-3 text-sm">
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
                    {Object.entries(risk.bySeverity ?? {}).map(([k, v]) => (
                      <span
                        key={k}
                        className={`mr-2 ${
                          k === 'CRITICAL'
                            ? 'text-red-600 dark:text-red-400'
                            : k === 'HIGH'
                              ? 'text-orange-600 dark:text-orange-400'
                              : k === 'MEDIUM'
                                ? 'text-amber-600 dark:text-amber-400'
                                : 'text-green-600 dark:text-green-400'
                        }`}
                      >
                        {k}: {typeof v === 'number' ? v.toFixed(2) : v}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="card-minimal">
            <h3>Threats ({threats.length})</h3>
            {threats.length === 0 ? (
              <p className="text-neutral-500 dark:text-neutral-400 text-sm mt-3">No threats found.</p>
            ) : (
              <ul className="list-none p-0 m-0 mt-3">
                {threats.map((t: Threat, i: number) => (
                  <li key={i} className="list-item-minimal">
                    <span
                      className={`font-medium ${
                        (t.severity ?? '').toUpperCase() === 'CRITICAL'
                          ? 'text-red-600 dark:text-red-400'
                          : (t.severity ?? '').toUpperCase() === 'HIGH'
                            ? 'text-orange-600 dark:text-orange-400'
                            : (t.severity ?? '').toUpperCase() === 'MEDIUM'
                              ? 'text-amber-600 dark:text-amber-400'
                              : 'text-green-600 dark:text-green-400'
                      }`}
                    >
                      {t.severity}
                    </span>
                    {' '}
                    {t.package && <code>{t.package}</code>}
                    {' — '}
                    {t.message}
                    {t.details && (
                      <div className="mt-2 text-xs text-neutral-500 dark:text-neutral-400">
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
