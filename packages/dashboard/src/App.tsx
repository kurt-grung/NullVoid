import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { SpeedInsights } from '@vercel/speed-insights/react'
import Executive from './views/Executive'
import ScanDetail from './views/ScanDetail'
import Scans from './views/Scans'
import Compliance from './views/Compliance'
import './index.css'

const basename = import.meta.env.BASE_URL.replace(/\/$/, '') || undefined

function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('nullvoid-theme') as 'dark' | 'light' | null
      if (stored) return stored
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
    }
    return 'dark'
  })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('nullvoid-theme', theme)
  }, [theme])

  return (
    <BrowserRouter basename={basename}>
      <div className="flex flex-col min-h-screen">
        <nav className="flex items-center gap-8 px-8 py-5 bg-surface-card dark:bg-dark-card border-b border-surface-border dark:border-dark-border">
          <span className="font-sans font-bold text-lg tracking-tight text-black dark:text-white">NullVoid</span>
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
          </div>
          <button
            type="button"
            className="ml-auto p-2 rounded-md hover:bg-surface-muted dark:hover:bg-dark-muted transition-colors text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white"
            onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
            title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            {theme === 'dark' ? <span className="inline-block w-5 h-5 rounded-full bg-white" /> : <span className="inline-block w-5 h-5 rounded-full bg-black" />}
          </button>
        </nav>
        <main className="flex-1 px-8 py-10 max-w-[1200px] mx-auto w-full">
          <Routes>
            <Route path="/" element={<Executive />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/compliance" element={<Compliance />} />
          </Routes>
        </main>
        <SpeedInsights />
      </div>
    </BrowserRouter>
  )
}

export default App
