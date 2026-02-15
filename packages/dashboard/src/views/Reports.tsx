import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getScans, getReportUrl, isApiUnavailableError, type ScanSummary } from '../api'

export default function Reports() {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [apiUnavailable, setApiUnavailable] = useState(false)
  const [compliance, setCompliance] = useState<'soc2' | 'iso27001' | undefined>(undefined)

  useEffect(() => {
    getScans()
      .then((r) => setScans(r.scans.filter((s) => s.status === 'completed')))
      .catch((e) => {
        if (isApiUnavailableError(e)) setApiUnavailable(true)
        else setError(e.message)
      })
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="text-center py-12 text-neutral-500 dark:text-neutral-400">Loading...</div>
  )
  if (error && !apiUnavailable) return (
    <div className="alert-error mb-6">
      {error}
    </div>
  )

  return (
    <>
      <h1>Reports</h1>
      {apiUnavailable && (
        <div className="alert-info mb-6" role="status">
          <p className="text-neutral-600 dark:text-neutral-400 text-sm font-medium">
            No API connected. Run <code>make api</code> and ensure the dashboard proxies to it.
          </p>
        </div>
      )}
      <p className="text-neutral-500 dark:text-neutral-400 text-sm mb-6">
        View or download security scan reports (HTML or Markdown). Optionally include SOC 2 or ISO 27001 compliance mapping.
      </p>

      <div className="card-minimal mb-6">
        <h3>Compliance filter</h3>
        <div className="flex gap-4 mt-3">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="compliance"
              checked={compliance === undefined}
              onChange={() => setCompliance(undefined)}
              className="rounded-full"
            />
            <span className="text-sm">None</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="compliance"
              checked={compliance === 'soc2'}
              onChange={() => setCompliance('soc2')}
              className="rounded-full"
            />
            <span className="text-sm">SOC 2</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="compliance"
              checked={compliance === 'iso27001'}
              onChange={() => setCompliance('iso27001')}
              className="rounded-full"
            />
            <span className="text-sm">ISO 27001</span>
          </label>
        </div>
      </div>

      <div className="card-minimal">
        <h3>Completed scans</h3>
        {scans.length === 0 ? (
          <p className="text-neutral-500 dark:text-neutral-400 text-sm mt-4">
            No completed scans yet. <Link to="/scans" className="underline">Run a scan</Link> to generate reports.
          </p>
        ) : (
          <ul className="list-none p-0 m-0 mt-4 space-y-3">
            {scans.map((s) => (
              <li
                key={s.id}
                className="flex flex-wrap items-center gap-3 py-3 border-b border-surface-border dark:border-dark-border last:border-0"
              >
                <div className="flex-1 min-w-0">
                  <Link to={`/scans/${s.id}`} className="font-medium text-black dark:text-white hover:underline truncate block">
                    {s.target || s.id}
                  </Link>
                  <span className="text-neutral-500 dark:text-neutral-400 text-xs">
                    {s.completedAt ? new Date(s.completedAt).toLocaleString() : s.id}
                  </span>
                </div>
                <div className="flex gap-2">
                  <a
                    href={getReportUrl(s.id, 'html', compliance)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1.5 text-sm font-medium rounded-md bg-black dark:bg-white text-white dark:text-black hover:opacity-80 transition-opacity no-underline"
                  >
                    View HTML
                  </a>
                  <a
                    href={getReportUrl(s.id, 'markdown', compliance)}
                    download
                    className="px-3 py-1.5 text-sm font-medium rounded-md border border-surface-border dark:border-dark-border text-neutral-700 dark:text-neutral-300 hover:bg-surface-muted dark:hover:bg-dark-muted transition-colors no-underline"
                  >
                    Download MD
                  </a>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  )
}
