import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

const SHORTCUTS: Array<{ keys: string; path: string }> = [
  { keys: 'g e', path: '/' },
  { keys: 'g s', path: '/scans' },
  { keys: 'g t', path: '/trends' },
  { keys: 'g m', path: '/ml' },
  { keys: 'g c', path: '/config' },
]

export function useKeyboardShortcuts() {
  const navigate = useNavigate()

  useEffect(() => {
    let pending = ''
    let timer: ReturnType<typeof setTimeout> | null = null

    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
      if (e.key === '?') {
        window.alert(SHORTCUTS.map((s) => `${s.keys} → ${s.path}`).join('\n'))
        return
      }
      pending = pending ? `${pending} ${e.key.toLowerCase()}` : e.key.toLowerCase()
      if (timer) clearTimeout(timer)
      timer = setTimeout(() => {
        pending = ''
      }, 800)
      const match = SHORTCUTS.find((s) => s.keys === pending)
      if (match) {
        pending = ''
        navigate(match.path)
      }
    }

    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [navigate])
}
