import { useEffect, useState } from 'react'
import { getSchedules, createSchedule, deleteSchedule, isApiUnavailableError, type ScheduleEntry } from '../api'
import Breadcrumbs from '../components/Breadcrumbs'

export default function Schedules() {
  const [schedules, setSchedules] = useState<ScheduleEntry[]>([])
  const [target, setTarget] = useState('.')
  const [cron, setCron] = useState('0 9 * * *')
  const [error, setError] = useState<string | null>(null)
  const [apiUnavailable, setApiUnavailable] = useState(false)

  const handleSchedulesError = (e: unknown) => {
    const msg = e instanceof Error ? e.message : String(e)
    if (isApiUnavailableError(e)) {
      setApiUnavailable(true)
      if (!/Failed to fetch|NetworkError|API error \d+/.test(msg)) setError(msg)
    } else {
      setError(msg)
    }
  }

  const load = () => {
    getSchedules()
      .then((r) => {
        setSchedules(r.schedules)
        setError(null)
        setApiUnavailable(false)
      })
      .catch(handleSchedulesError)
  }

  useEffect(() => {
    load()
  }, [])

  const onCreate = async () => {
    setError(null)
    try {
      await createSchedule(target, cron)
      setTarget('.')
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="page space-y-4">
      <Breadcrumbs items={[{ label: 'Schedules' }]} />
      <h1 className="text-xl font-semibold">Scheduled scans</h1>
      {apiUnavailable && (
        <p className="text-amber-700 text-sm">
          API unavailable. Set <code>VITE_API_URL</code> in Vercel to your Railway API URL, or redeploy after the latest vercel.json fix.
        </p>
      )}
      {error && <p className="text-red-600 text-sm">{error}</p>}
      <div className="card-minimal flex flex-wrap gap-2 items-end">
        <label className="text-sm">
          Target
          <input className="input-minimal block mt-1" value={target} onChange={(e) => setTarget(e.target.value)} />
        </label>
        <label className="text-sm">
          Cron
          <input className="input-minimal block mt-1" value={cron} onChange={(e) => setCron(e.target.value)} />
        </label>
        <button type="button" className="btn-minimal" onClick={() => void onCreate()}>
          Add schedule
        </button>
      </div>
      <ul className="space-y-2">
        {schedules.map((s) => (
          <li key={s.id} className="card-minimal flex justify-between items-center text-sm">
            <span>
              <code>{s.target}</code> — <code>{s.cronExpression}</code>
            </span>
            <button type="button" className="text-red-600" onClick={() => void deleteSchedule(s.id).then(load)}>
              Delete
            </button>
          </li>
        ))}
        {schedules.length === 0 && <li className="text-neutral-500 text-sm">No schedules yet.</li>}
      </ul>
    </div>
  )
}
