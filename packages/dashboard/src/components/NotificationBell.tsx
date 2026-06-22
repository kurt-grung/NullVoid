import { useEffect, useState } from 'react'
import { getScans, type ScanSummary } from '../api'

export default function NotificationBell() {
  const [recent, setRecent] = useState<ScanSummary[]>([])
  const [seenAt, setSeenAt] = useState(() => Number(localStorage.getItem('nullvoid-notifications-seen') ?? '0'))

  useEffect(() => {
    const poll = () => {
      getScans(undefined, undefined, 10)
        .then((r) => setRecent(r.scans))
        .catch(() => setRecent([]))
    }
    poll()
    const id = setInterval(poll, 30000)
    return () => clearInterval(id)
  }, [])

  const unread = recent.filter((s) => {
    const t = new Date(s.completedAt ?? s.createdAt).getTime()
    return (s.status === 'completed' || s.status === 'failed') && t > seenAt
  }).length

  const markSeen = () => {
    const now = Date.now()
    setSeenAt(now)
    localStorage.setItem('nullvoid-notifications-seen', String(now))
  }

  return (
    <div className="relative">
      <button
        type="button"
        onClick={markSeen}
        className="px-2 py-1 rounded hover:bg-surface-muted dark:hover:bg-dark-muted"
        aria-label={`Notifications${unread ? `, ${unread} unread` : ''}`}
      >
        🔔
        {unread > 0 && (
          <span className="absolute -top-1 -right-1 text-[10px] bg-red-600 text-white rounded-full px-1 min-w-[16px]">
            {unread}
          </span>
        )}
      </button>
    </div>
  )
}
