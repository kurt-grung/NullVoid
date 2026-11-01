import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { getScans, getScan, isApiUnavailableError, type ScanSummary, type ScanDetail } from '../api'
import { useOrgTeam } from '../context/OrgTeamContext'

interface DayData {
  date: string
  scans: number
  threats: number
}

export default function Trends() {
  const { organizationId, teamId } = useOrgTeam()
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [apiUnavailable, setApiUnavailable] = useState(false)

  useEffect(() => {
    getScans(organizationId ?? undefined, teamId ?? undefined, 200)
      .then((r) => setScans(r.scans))
      .catch((e) => {
        if (isApiUnavailableError(e)) setApiUnavailable(true)
        else setScans([])
      })
      .finally(() => setLoading(false))
  }, [organizationId, teamId])

  const [chartData, setChartData] = useState<DayData[]>([])
  const [loadingDetails, setLoadingDetails] = useState(false)
  const isDark = typeof document !== 'undefined' && document.documentElement.classList.contains('dark')
  const barScans = isDark ? '#ffffff' : '#000000'
  const barThreats = isDark ? '#e5e5e5' : '#666666'

  useEffect(() => {
    if (scans.length === 0) {
      setChartData([])
      setLoadingDetails(false)
      return
    }
    let cancelled = false
    setLoadingDetails(true)
    const load = async () => {
      try {
        const byDay = new Map<string, { scans: number; threats: number }>()
        const completed = scans.filter((s) => s.status === 'completed').slice(0, 50)
        for (const s of completed) {
          if (cancelled) return
          try {
            const d = (await getScan(s.id, organizationId ?? undefined, teamId ?? undefined)) as ScanDetail
            const dateStr = d.createdAt ? new Date(d.createdAt).toISOString().slice(0, 10) : ''
            if (!dateStr) continue
            const prev = byDay.get(dateStr) ?? { scans: 0, threats: 0 }
            prev.scans += 1
            prev.threats += d.result?.threats?.length ?? 0
            byDay.set(dateStr, prev)
          } catch {
            /* skip */
          }
        }
        for (const s of scans.filter((s) => s.status !== 'completed')) {
          if (cancelled) return
          const dateStr = s.createdAt ? new Date(s.createdAt).toISOString().slice(0, 10) : ''
          if (!dateStr) continue
          const prev = byDay.get(dateStr) ?? { scans: 0, threats: 0 }
          prev.scans += 1
          byDay.set(dateStr, prev)
        }
        if (!cancelled) {
          const sorted = Array.from(byDay.entries())
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([date, v]) => ({ date, scans: v.scans, threats: v.threats }))
          setChartData(sorted)
        }
      } finally {
        if (!cancelled) setLoadingDetails(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [scans, organizationId, teamId])

  if (loading) return (
    <div className="text-center py-12 text-neutral-500 dark:text-neutral-400">Loading...</div>
  )

  return (
    <>
      <h1>Scan Trends</h1>
      {apiUnavailable && (
        <div className="alert-info mb-6" role="status">
          <p className="text-neutral-600 dark:text-neutral-400 text-sm font-medium">No API connected.</p>
        </div>
      )}
      <p className="text-neutral-500 dark:text-neutral-400 text-sm mb-6">
        Scans and threats over time (grouped by day). Based on last {scans.length} scans.
      </p>

      <div className="card-minimal">
        <h3>Scans & Threats by Day</h3>
        {loadingDetails ? (
          <div className="h-64 flex items-center justify-center text-neutral-500 dark:text-neutral-400 text-sm">
            Loading chart data...
          </div>
        ) : chartData.length === 0 ? (
          <p className="text-neutral-500 dark:text-neutral-400 text-sm py-12 text-center">
            No scan data yet. <Link to="/scans" className="underline">Run scans</Link> to see trends.
          </p>
        ) : (
          <div className="h-80 mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-neutral-200 dark:stroke-neutral-700" />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 11, fill: 'currentColor' }}
                  className="text-neutral-500 dark:text-neutral-400"
                />
                <YAxis
                  yAxisId="left"
                  tick={{ fontSize: 11, fill: 'currentColor' }}
                  className="text-neutral-500 dark:text-neutral-400"
                />
                <YAxis
                  yAxisId="right"
                  orientation="right"
                  tick={{ fontSize: 11, fill: 'currentColor' }}
                  className="text-neutral-500 dark:text-neutral-400"
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: isDark ? '#000' : '#fff',
                    border: `1px solid ${isDark ? '#222' : '#eaeaea'}`,
                    borderRadius: '0.5rem',
                    color: isDark ? '#fff' : '#000',
                  }}
                  labelStyle={{ color: 'inherit' }}
                />
                <Legend />
                <Bar yAxisId="left" dataKey="scans" fill={barScans} name="Scans" radius={[2, 2, 0, 0]} />
                <Bar yAxisId="right" dataKey="threats" fill={barThreats} name="Threats" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </>
  )
}
