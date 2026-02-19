import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getScan, getReportUrl, type ScanDetail, type Threat } from '../api'
import { useOrgTeam } from '../context/OrgTeamContext'

function ThreatRow({ t }: { t: Threat }) {
  const [expanded, setExpanded] = useState(false)
  const hasDetails = !!(t.filePath || t.lineNumber != null || t.confidence != null || t.details || t.sampleCode)
  const severityClass =
    (t.severity ?? '').toUpperCase() === 'CRITICAL'
      ? 'text-red-600 dark:text-red-400'
      : (t.severity ?? '').toUpperCase() === 'HIGH'
        ? 'text-orange-600 dark:text-orange-400'
        : (t.severity ?? '').toUpperCase() === 'MEDIUM'
          ? 'text-amber-600 dark:text-amber-400'
          : 'text-green-600 dark:text-green-400'

  return (
    <li className="list-item-minimal">
      <div className="flex items-start gap-2">
        {hasDetails && (
          <button
            type="button"
            onClick={() => setExpanded((e) => !e)}
            className="shrink-0 mt-0.5 p-0.5 rounded hover:bg-surface-muted dark:hover:bg-dark-muted transition-colors text-neutral-500 dark:text-neutral-400"
            aria-expanded={expanded}
          >
            <span className={`inline-block w-4 h-4 transition-transform ${expanded ? 'rotate-90' : ''}`}>▶</span>
          </button>
        )}
        <div className="flex-1 min-w-0">
          <span className={`font-medium ${severityClass}`}>{t.severity}</span>
          {' '}
          {t.package && <code>{t.package}</code>}
          {' — '}
          {t.message}
          {expanded && hasDetails && (
            <div className="mt-3 pl-6 space-y-2 text-xs text-neutral-500 dark:text-neutral-400 border-l-2 border-surface-border dark:border-dark-border">
              {t.filePath && <div><strong>File:</strong> <code>{t.filePath}</code></div>}
              {t.lineNumber != null && <div><strong>Line:</strong> {t.lineNumber}</div>}
              {t.confidence != null && <div><strong>Confidence:</strong> {(t.confidence * 100).toFixed(0)}%</div>}
              {t.details && <div><strong>Details:</strong> {t.details}</div>}
              {t.sampleCode && <div><strong>Sample:</strong> <pre className="mt-1 p-2 bg-surface dark:bg-dark-surface rounded overflow-x-auto text-[11px]">{t.sampleCode}</pre></div>}
            </div>
          )}
        </div>
      </div>
    </li>
  )
}

export default function ScanDetailView() {
  const { id } = useParams<{ id: string }>()
  const { organizationId, teamId } = useOrgTeam()
  const [scan, setScan] = useState<ScanDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    getScan(id, organizationId ?? undefined, teamId ?? undefined)
      .then(setScan)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [id, organizationId, teamId])

  if (loading) return (
    <div className="text-center py-12 text-neutral-500 dark:text-neutral-400">Loading...</div>
  )
  if (error) return (
    <div className="alert-error mb-6">
      {error}
    </div>
  )
  if (!scan) return (
    <div className="alert-error mb-6">
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
      <div className="flex gap-2 items-center mb-4 flex-wrap">
        <span className={`badge-minimal ${statusClass}`}>
          {scan.status}
        </span>
        <span className="text-neutral-500 dark:text-neutral-400 text-sm">
          {new Date(scan.createdAt).toLocaleString()}
          {scan.completedAt && ` — ${new Date(scan.completedAt).toLocaleString()}`}
        </span>
        {scan.status === 'completed' && id && (
          <span className="flex gap-2 ml-4">
            <a
              href={getReportUrl(id, 'html')}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm font-medium text-black dark:text-white hover:underline"
            >
              View HTML
            </a>
            <span className="text-neutral-400 dark:text-neutral-500">|</span>
            <a
              href={getReportUrl(id, 'markdown')}
              download
              className="text-sm font-medium text-black dark:text-white hover:underline"
            >
              Download MD
            </a>
            <span className="text-neutral-400 dark:text-neutral-500">|</span>
            <select
              className="text-sm bg-surface-muted dark:bg-dark-muted border border-surface-border dark:border-dark-border rounded px-2 py-1 text-black dark:text-white"
              onChange={(e) => {
                const v = e.target.value as '' | 'soc2' | 'iso27001'
                if (v) window.open(getReportUrl(id, 'html', v), '_blank')
              }}
              defaultValue=""
            >
              <option value="">Compliance report...</option>
              <option value="soc2">SOC 2</option>
              <option value="iso27001">ISO 27001</option>
            </select>
          </span>
        )}
      </div>

      {scan.error && (
        <div className="alert-error mb-4">
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
                {threats.map((t, i) => (
                  <ThreatRow key={i} t={t} />
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </>
  )
}
