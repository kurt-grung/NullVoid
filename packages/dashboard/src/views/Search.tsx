import { useEffect, useState, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import { getScans, getScan, isApiUnavailableError, type ScanSummary, type ScanDetail, type Threat } from '../api'
import { useOrgTeam } from '../context/OrgTeamContext'

interface SearchResult {
  kind: 'scan'
  scan: ScanSummary
  match: string
}

interface ThreatResult {
  kind: 'threat'
  scan: ScanSummary
  threat: Threat
  match: string
}

export default function Search() {
  const { organizationId, teamId } = useOrgTeam()
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [results, setResults] = useState<Array<SearchResult | ThreatResult>>([])
  const [loading, setLoading] = useState(true)
  const [searching, setSearching] = useState(false)
  const [apiUnavailable, setApiUnavailable] = useState(false)
  const searchIdRef = useRef(0)

  useEffect(() => {
    getScans(organizationId ?? undefined, teamId ?? undefined, 100)
      .then((r) => setScans(r.scans))
      .catch((e) => {
        if (isApiUnavailableError(e)) setApiUnavailable(true)
        else setScans([])
      })
      .finally(() => setLoading(false))
  }, [organizationId, teamId])

  useEffect(() => {
    const id = setTimeout(() => setDebouncedQuery(query.trim()), 300)
    return () => clearTimeout(id)
  }, [query])

  const runSearch = useCallback(async (q: string) => {
    if (!q) {
      setResults([])
      setSearching(false)
      return
    }
    searchIdRef.current += 1
    const ourId = searchIdRef.current
    setSearching(true)
    try {
      const lower = q.toLowerCase()
      const res: Array<SearchResult | ThreatResult> = []

      for (const s of scans) {
        if ((s.target ?? '').toLowerCase().includes(lower)) {
          res.push({ kind: 'scan', scan: s, match: 'target' })
        }
      }

      const completed = scans.filter((s) => s.status === 'completed' && !s.id.endsWith('-pending')).slice(0, 30)
      for (const s of completed) {
        if (ourId !== searchIdRef.current) break
        try {
          const d = (await getScan(s.id, organizationId ?? undefined, teamId ?? undefined)) as ScanDetail
          for (const t of d.result?.threats ?? []) {
            const msg = (t.message ?? '').toLowerCase()
            const type = (t.type ?? '').toLowerCase()
            const pkg = (t.package ?? '').toLowerCase()
            if (msg.includes(lower) || type.includes(lower) || pkg.includes(lower)) {
              let match = 'message'
              if (type.includes(lower)) match = 'type'
              else if (pkg.includes(lower)) match = 'package'
              res.push({ kind: 'threat', scan: s, threat: t, match })
            }
          }
        } catch {
          /* skip */
        }
      }

      if (ourId === searchIdRef.current) setResults(res)
    } finally {
      if (ourId === searchIdRef.current) setSearching(false)
    }
  }, [scans, organizationId, teamId])

  useEffect(() => {
    runSearch(debouncedQuery)
  }, [debouncedQuery, runSearch])

  if (loading) return (
    <div className="text-center py-12 text-neutral-500 dark:text-neutral-400">Loading...</div>
  )

  return (
    <>
      <h1>Search</h1>
      {apiUnavailable && (
        <div className="alert-info mb-6" role="status">
          <p className="text-neutral-600 dark:text-neutral-400 text-sm font-medium">No API connected.</p>
        </div>
      )}
      <p className="text-neutral-500 dark:text-neutral-400 text-sm mb-6">
        Search across scan targets, threat messages, threat types, and package names.
      </p>

      <div className="card-minimal mb-6">
        <input
          type="search"
          placeholder="Search scans and threats..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full px-4 py-3 bg-surface dark:bg-dark-surface border border-surface-border dark:border-dark-border rounded-md text-black dark:text-white text-base font-medium focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white focus:ring-offset-0"
          autoFocus
        />
      </div>

      {searching && (
        <p className="text-neutral-500 dark:text-neutral-400 text-sm mb-4">Searching...</p>
      )}

      <div className="card-minimal">
        <h3>Results</h3>
        {!debouncedQuery ? (
          <p className="text-neutral-500 dark:text-neutral-400 text-sm mt-4">Enter a search query above.</p>
        ) : results.length === 0 ? (
          <p className="text-neutral-500 dark:text-neutral-400 text-sm mt-4">No matches found.</p>
        ) : (
          <ul className="list-none p-0 m-0 mt-4 space-y-3">
            {results.map((r, i) =>
              r.kind === 'scan' ? (
                <li key={`scan-${r.scan.id}`} className="list-item-minimal">
                  <Link to={`/scans/${r.scan.id}`} className="font-medium text-black dark:text-white hover:underline">
                    Scan: {r.scan.target || r.scan.id}
                  </Link>
                  <span className="text-neutral-500 dark:text-neutral-400 text-xs ml-2">(matched {r.match})</span>
                  <span className="text-neutral-500 dark:text-neutral-400 text-xs block mt-1">
                    {new Date(r.scan.createdAt).toLocaleString()} · {r.scan.status}
                  </span>
                </li>
              ) : (
                <li key={`threat-${r.scan.id}-${i}`} className="list-item-minimal">
                  <Link to={`/scans/${r.scan.id}`} className="font-medium text-black dark:text-white hover:underline">
                    {r.threat.type}: {r.threat.message}
                  </Link>
                  {r.threat.package && <code className="ml-2">{r.threat.package}</code>}
                  <span className="text-neutral-500 dark:text-neutral-400 text-xs ml-2">(matched {r.match})</span>
                  <span className="text-neutral-500 dark:text-neutral-400 text-xs block mt-1">
                    Scan: {r.scan.target || r.scan.id} · {r.threat.severity}
                  </span>
                </li>
              )
            )}
          </ul>
        )}
      </div>
    </>
  )
}
