import { useEffect, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { getScan, type ScanDetail } from '../api'
import { useOrgTeam } from '../context/OrgTeamContext'
import Breadcrumbs from '../components/Breadcrumbs'

function severityCounts(result?: ScanDetail['result']) {
  const counts: Record<string, number> = {}
  for (const t of result?.threats ?? []) {
    const s = (t.severity ?? 'UNKNOWN').toUpperCase()
    counts[s] = (counts[s] ?? 0) + 1
  }
  return counts
}

export default function ScanCompare() {
  const [params] = useSearchParams()
  const id1 = params.get('id1') ?? ''
  const id2 = params.get('id2') ?? ''
  const { organizationId, teamId } = useOrgTeam()
  const [scanA, setScanA] = useState<ScanDetail | null>(null)
  const [scanB, setScanB] = useState<ScanDetail | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!id1 || !id2) return
    setLoading(true)
    Promise.all([
      getScan(id1, organizationId ?? undefined, teamId ?? undefined),
      getScan(id2, organizationId ?? undefined, teamId ?? undefined),
    ])
      .then(([a, b]) => {
        setScanA(a)
        setScanB(b)
      })
      .finally(() => setLoading(false))
  }, [id1, id2, organizationId, teamId])

  if (!id1 || !id2) {
    return (
      <div className="page">
        <Breadcrumbs items={[{ label: 'Scans', to: '/scans' }, { label: 'Compare' }]} />
        <p className="text-neutral-500">Add query params: /scans/compare?id1=...&id2=...</p>
      </div>
    )
  }

  if (loading) return <div className="page">Loading comparison…</div>

  const threatsA = new Set((scanA?.result?.threats ?? []).map((t) => `${t.type}:${t.message}`))
  const threatsB = new Set((scanB?.result?.threats ?? []).map((t) => `${t.type}:${t.message}`))
  const onlyA = [...threatsA].filter((k) => !threatsB.has(k))
  const onlyB = [...threatsB].filter((k) => !threatsA.has(k))
  const both = [...threatsA].filter((k) => threatsB.has(k))

  return (
    <div className="page space-y-6">
      <Breadcrumbs items={[{ label: 'Scans', to: '/scans' }, { label: 'Compare' }]} />
      <div className="grid md:grid-cols-2 gap-4">
        <div className="card-minimal">
          <h2 className="font-semibold mb-2">
            <Link to={`/scans/${id1}`}>{scanA?.target ?? id1}</Link>
          </h2>
          <p>Threats: {scanA?.result?.summary.threatsFound ?? '—'}</p>
          <p>Risk: {scanA?.result?.riskAssessment ? `${(scanA.result.riskAssessment.overall * 100).toFixed(0)}%` : '—'}</p>
          <pre className="text-xs mt-2">{JSON.stringify(severityCounts(scanA?.result), null, 2)}</pre>
        </div>
        <div className="card-minimal">
          <h2 className="font-semibold mb-2">
            <Link to={`/scans/${id2}`}>{scanB?.target ?? id2}</Link>
          </h2>
          <p>Threats: {scanB?.result?.summary.threatsFound ?? '—'}</p>
          <p>Risk: {scanB?.result?.riskAssessment ? `${(scanB.result.riskAssessment.overall * 100).toFixed(0)}%` : '—'}</p>
          <pre className="text-xs mt-2">{JSON.stringify(severityCounts(scanB?.result), null, 2)}</pre>
        </div>
      </div>
      <div className="grid md:grid-cols-3 gap-4 text-sm">
        <div className="card-minimal"><h3 className="font-medium mb-2">Only in A ({onlyA.length})</h3><ul className="list-disc pl-4">{onlyA.slice(0, 20).map((t) => <li key={t}>{t}</li>)}</ul></div>
        <div className="card-minimal"><h3 className="font-medium mb-2">In both ({both.length})</h3><ul className="list-disc pl-4">{both.slice(0, 20).map((t) => <li key={t}>{t}</li>)}</ul></div>
        <div className="card-minimal"><h3 className="font-medium mb-2">Only in B ({onlyB.length})</h3><ul className="list-disc pl-4">{onlyB.slice(0, 20).map((t) => <li key={t}>{t}</li>)}</ul></div>
      </div>
    </div>
  )
}
