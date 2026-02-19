import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Link } from 'react-router-dom'
import { SpeedInsights } from '@vercel/speed-insights/react'
import { OrgTeamProvider } from './context/OrgTeamContext'
import Executive from './views/Executive'
import ScanDetail from './views/ScanDetail'
import Scans from './views/Scans'
import Compliance from './views/Compliance'
import Reports from './views/Reports'
import ML from './views/ML'
import Settings from './views/Settings'
import Trends from './views/Trends'
import Search from './views/Search'
import { getHealth, getOrganizations, getTeams } from './api'
import { useOrgTeam } from './context/OrgTeamContext'
import './index.css'

const basename = import.meta.env.BASE_URL.replace(/\/$/, '') || undefined

function NavWithHealth() {
  const { organizationId, teamId, setOrganizationId, setTeamId } = useOrgTeam()
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('nullvoid-theme') as 'dark' | 'light' | null
      if (stored) return stored
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
    }
    return 'dark'
  })
  const [apiHealthy, setApiHealthy] = useState<boolean | null>(null)
  const [orgs, setOrgs] = useState<{ id: string; name: string }[]>([])
  const [teams, setTeams] = useState<{ id: string; name: string }[]>([])

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('nullvoid-theme', theme)
  }, [theme])

  useEffect(() => {
    getHealth()
      .then((r) => setApiHealthy(r.ok))
      .catch(() => setApiHealthy(false))
    const id = setInterval(() => {
      getHealth()
        .then((r) => setApiHealthy(r.ok))
        .catch(() => setApiHealthy(false))
    }, 45000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    getOrganizations()
      .then((r) => setOrgs(r.organizations))
      .catch(() => setOrgs([]))
  }, [])

  useEffect(() => {
    if (organizationId) {
      getTeams(organizationId).then((r) => setTeams(r.teams)).catch(() => setTeams([]))
    } else {
      setTeams([])
      setTeamId(null)
    }
  }, [organizationId, setTeamId])

  return (
    <nav className="flex items-center gap-8 px-8 py-5 bg-surface-card dark:bg-dark-card border-b border-surface-border dark:border-dark-border flex-wrap">
      <Link to="/" className="font-sans font-bold text-lg tracking-tight text-black dark:text-white no-underline hover:opacity-80 transition-opacity">NullVoid</Link>
      <div className="flex gap-6">
        <NavLink
          to="/"
          end
          className={({ isActive }) =>
            `text-sm font-medium transition-colors ${isActive ? 'text-black dark:text-white no-underline' : 'text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white no-underline'}`
          }
        >
          Executive
        </NavLink>
        <NavLink
          to="/scans"
          className={({ isActive }) =>
            `text-sm font-medium transition-colors ${isActive ? 'text-black dark:text-white no-underline' : 'text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white no-underline'}`
          }
        >
          Scans
        </NavLink>
        <NavLink
          to="/compliance"
          className={({ isActive }) =>
            `text-sm font-medium transition-colors ${isActive ? 'text-black dark:text-white no-underline' : 'text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white no-underline'}`
          }
        >
          Compliance
        </NavLink>
        <NavLink
          to="/reports"
          className={({ isActive }) =>
            `text-sm font-medium transition-colors ${isActive ? 'text-black dark:text-white no-underline' : 'text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white no-underline'}`
          }
        >
          Reports
        </NavLink>
        <NavLink
          to="/trends"
          className={({ isActive }) =>
            `text-sm font-medium transition-colors ${isActive ? 'text-black dark:text-white no-underline' : 'text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white no-underline'}`
          }
        >
          Trends
        </NavLink>
        <NavLink
          to="/search"
          className={({ isActive }) =>
            `text-sm font-medium transition-colors ${isActive ? 'text-black dark:text-white no-underline' : 'text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white no-underline'}`
          }
        >
          Search
        </NavLink>
        <NavLink
          to="/ml"
          className={({ isActive }) =>
            `text-sm font-medium transition-colors ${isActive ? 'text-black dark:text-white no-underline' : 'text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white no-underline'}`
          }
        >
          ML
        </NavLink>
        <NavLink
          to="/settings"
          className={({ isActive }) =>
            `text-sm font-medium transition-colors ${isActive ? 'text-black dark:text-white no-underline' : 'text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white no-underline'}`
          }
        >
          Settings
        </NavLink>
      </div>
      {(orgs.length > 0 || teams.length > 0) && (
        <div className="flex gap-2 items-center">
          {orgs.length > 0 && (
            <select
              value={organizationId ?? ''}
              onChange={(e) => setOrganizationId(e.target.value || null)}
              className="text-sm bg-surface-muted dark:bg-dark-muted border border-surface-border dark:border-dark-border rounded px-2 py-1.5 text-black dark:text-white"
            >
              <option value="">All orgs</option>
              {orgs.map((o) => (
                <option key={o.id} value={o.id}>{o.name}</option>
              ))}
            </select>
          )}
          {teams.length > 0 && (
            <select
              value={teamId ?? ''}
              onChange={(e) => setTeamId(e.target.value || null)}
              className="text-sm bg-surface-muted dark:bg-dark-muted border border-surface-border dark:border-dark-border rounded px-2 py-1.5 text-black dark:text-white"
            >
              <option value="">All teams</option>
              {teams.map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
          )}
        </div>
      )}
      <div className="ml-auto flex items-center gap-3">
        {apiHealthy !== null && (
          <span
            className="flex items-center gap-1.5 text-xs font-medium"
            title={apiHealthy ? 'API connected' : 'API unavailable'}
          >
            <span
              className={`inline-block w-2 h-2 rounded-full ${apiHealthy ? 'bg-green-500' : 'bg-red-500'}`}
              aria-hidden
            />
            {apiHealthy ? 'Connected' : 'API unavailable'}
          </span>
        )}
        <button
          type="button"
          className="p-2 rounded-md hover:bg-surface-muted dark:hover:bg-dark-muted transition-colors text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white"
          onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
          title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
        >
          {theme === 'dark' ? <span className="inline-block w-5 h-5 rounded-full bg-white" /> : <span className="inline-block w-5 h-5 rounded-full bg-black" />}
        </button>
      </div>
    </nav>
  )
}

function App() {
  return (
    <BrowserRouter basename={basename}>
      <OrgTeamProvider>
        <div className="flex flex-col min-h-screen">
          <NavWithHealth />
          <main className="flex-1 px-8 py-10 max-w-[1200px] mx-auto w-full">
            <Routes>
              <Route path="/" element={<Executive />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/scans/:id" element={<ScanDetail />} />
              <Route path="/compliance" element={<Compliance />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/trends" element={<Trends />} />
              <Route path="/search" element={<Search />} />
              <Route path="/ml" element={<ML />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </main>
          <SpeedInsights />
        </div>
      </OrgTeamProvider>
    </BrowserRouter>
  )
}

export default App
