import { useEffect, useState, useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { getScans, triggerScan, isApiUnavailableError, type ScanSummary } from '../api'
import { useOrgTeam } from '../context/OrgTeamContext'

type StatusFilter = 'all' | 'completed' | 'failed' | 'running' | 'pending'
type DateFilter = 'all' | '7' | '30' | '90'

export default function Scans() {
  const { organizationId, teamId } = useOrgTeam()
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [apiUnavailable, setApiUnavailable] = useState(false)
  const [target, setTarget] = useState(() => localStorage.getItem('nullvoid-default-scan-target') || '.')
  const [submitting, setSubmitting] = useState(false)
  const [searchParams, setSearchParams] = useSearchParams()
  const [statusFilter, setStatusFilter] = useState<StatusFilter>(() => (searchParams.get('status') as StatusFilter) || 'all')
  const [dateFilter, setDateFilter] = useState<DateFilter>(() => (searchParams.get('days') as DateFilter) || 'all')
  const [targetSearch, setTargetSearch] = useState(() => searchParams.get('target') || '')

  const refresh = () => {
    setError(null)
    setApiUnavailable(false)
    getScans(organizationId ?? undefined, teamId ?? undefined)
      .then((r) => setScans(r.scans))
      .catch((e) => {
        const msg = e instanceof Error ? e.message : String(e)
        if (isApiUnavailableError(e)) {
          setApiUnavailable(true)
          if (!/Failed to fetch|NetworkError|API error \d+/.test(msg)) setError(msg)
        } else {
          setError(msg)
        }
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    refresh()
  }, [organizationId, teamId])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    const optimisticScan: ScanSummary = {
      id: `scan-${Date.now()}-pending`,
      status: 'running',
      target,
      createdAt: new Date().toISOString(),
    }
    setScans((prev) => [optimisticScan, ...prev])
    triggerScan(target, organizationId ?? undefined, teamId ?? undefined)
      .then(() => {
        setTarget(localStorage.getItem('nullvoid-default-scan-target') || '.')
        refresh()
      })
      .catch((e) => {
        setError(e.message)
        setScans((prev) => prev.filter((s) => s.id !== optimisticScan.id))
      })
      .finally(() => setSubmitting(false))
  }

  const filteredScans = useMemo(() => {
    let list = scans
    if (statusFilter !== 'all') {
      list = list.filter((s) => s.status === statusFilter)
    }
    if (dateFilter !== 'all') {
      const days = parseInt(dateFilter, 10)
      const cutoff = new Date()
      cutoff.setDate(cutoff.getDate() - days)
      list = list.filter((s) => new Date(s.createdAt) >= cutoff)
    }
    if (targetSearch.trim()) {
      const q = targetSearch.trim().toLowerCase()
      list = list.filter((s) => (s.target ?? '').toLowerCase().includes(q))
    }
    return list
  }, [scans, statusFilter, dateFilter, targetSearch])

  const updateFilters = (updates: { status?: StatusFilter; days?: DateFilter; target?: string }) => {
    const next = new URLSearchParams(searchParams)
    if (updates.status !== undefined) {
      if (updates.status === 'all') next.delete('status')
      else next.set('status', updates.status)
      setStatusFilter(updates.status)
    }
    if (updates.days !== undefined) {
      if (updates.days === 'all') next.delete('days')
      else next.set('days', updates.days)
      setDateFilter(updates.days)
    }
    if (updates.target !== undefined) {
      if (!updates.target) next.delete('target')
      else next.set('target', updates.target)
      setTargetSearch(updates.target)
    }
    setSearchParams(next, { replace: true })
  }

  if (loading) return (
    <div className="text-center py-12 text-neutral-500 dark:text-neutral-400">Loading...</div>
  )

  const statusClass = (s: string) =>
    s === 'pending'
      ? 'bg-amber-200 dark:bg-amber-900/50 text-amber-800 dark:text-amber-200'
      : s === 'running'
        ? 'bg-blue-500 text-white'
        : s === 'completed'
          ? 'bg-green-500 text-white'
          : 'bg-red-500 text-white'

  return (
    <>
      <h1>Scans</h1>
      {apiUnavailable && (
        <div className="alert-info mb-6" role="status">
          <p className="text-neutral-600 dark:text-neutral-400 text-sm font-medium">No API connected. The API could not be reached.</p>
          {error && <p className="mt-2 text-xs text-neutral-600 dark:text-neutral-400 font-mono">{error}</p>}
          <p className="mt-2 text-xs text-neutral-500 dark:text-neutral-500">
            On Vercel: ensure <code>TURSO_DATABASE_URL</code> and <code>TURSO_AUTH_TOKEN</code> are set in Environment Variables. If they are, check Vercel → Deployments → logs for API errors.
          </p>
        </div>
      )}
      {error && !apiUnavailable && (
        <div className="alert-error mb-6">
          {error}
        </div>
      )}

      <div className="card-minimal">
        <h3>New Scan</h3>
        <form onSubmit={handleSubmit} className="flex gap-2 items-center mt-3">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Target path (e.g. . or ./packages/api)"
            className="flex-1 px-4 py-2.5 bg-surface dark:bg-dark-surface border border-surface-border dark:border-dark-border rounded-md text-black dark:text-white text-sm font-medium focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white focus:ring-offset-0"
          />
          <button
            type="submit"
            className="px-5 py-2.5 text-sm font-semibold rounded-md bg-black dark:bg-white text-white dark:text-black cursor-pointer transition-opacity hover:opacity-80 disabled:opacity-50"
            disabled={submitting}
          >
            {submitting ? 'Starting...' : 'Start Scan'}
          </button>
        </form>
      </div>

      <div className="card-minimal">
        <h3>Recent Scans</h3>
        <div className="flex flex-wrap gap-3 mt-3 mb-4">
          <select
            value={statusFilter}
            onChange={(e) => updateFilters({ status: e.target.value as StatusFilter })}
            className="text-sm bg-surface-muted dark:bg-dark-muted border border-surface-border dark:border-dark-border rounded px-3 py-2 text-black dark:text-white"
          >
            <option value="all">All statuses</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="running">Running</option>
            <option value="pending">Pending</option>
          </select>
          <select
            value={dateFilter}
            onChange={(e) => updateFilters({ days: e.target.value as DateFilter })}
            className="text-sm bg-surface-muted dark:bg-dark-muted border border-surface-border dark:border-dark-border rounded px-3 py-2 text-black dark:text-white"
          >
            <option value="all">All time</option>
            <option value="7">Last 7 days</option>
            <option value="30">Last 30 days</option>
            <option value="90">Last 90 days</option>
          </select>
          <input
            type="search"
            placeholder="Search target..."
            value={targetSearch}
            onChange={(e) => setTargetSearch(e.target.value)}
            onBlur={() => updateFilters({ target: targetSearch })}
            onKeyDown={(e) => e.key === 'Enter' && updateFilters({ target: targetSearch })}
            className="text-sm bg-surface-muted dark:bg-dark-muted border border-surface-border dark:border-dark-border rounded px-3 py-2 text-black dark:text-white min-w-[180px]"
          />
        </div>
        <ul className="list-none p-0 m-0 mt-3">
          {filteredScans.map((s) => (
            <li key={s.id} className="list-item-minimal">
              {s.id.endsWith('-pending') ? (
                <>
                  <span className={`badge-minimal ${statusClass(s.status)}`}>{s.status}</span>
                  {' '}
                  <code>{s.target}</code>
                  {' '}
                  <span className="text-neutral-500 dark:text-neutral-400 text-xs">
                    {new Date(s.createdAt).toLocaleString()}
                  </span>
                </>
              ) : (
                <Link to={`/scans/${s.id}`} className="text-inherit no-underline hover:no-underline">
                  <span className={`badge-minimal ${statusClass(s.status)}`}>{s.status}</span>
                  {' '}
                  <code>{s.target}</code>
                  {' '}
                  <span className="text-neutral-500 dark:text-neutral-400 text-xs">
                    {new Date(s.createdAt).toLocaleString()}
                  </span>
                </Link>
              )}
            </li>
          ))}
        </ul>
        {filteredScans.length === 0 && (
          <p className="text-neutral-500 dark:text-neutral-400 text-sm mt-6 font-medium">
            {scans.length === 0 ? 'No scans yet.' : 'No scans match the current filters.'}
          </p>
        )}
      </div>
    </>
  )
}
