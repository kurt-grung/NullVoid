import { useState, useEffect } from 'react'
import { getApiKey, setApiKey } from '../api'

const DEFAULT_SCAN_TARGET = 'nullvoid-default-scan-target'

export default function Settings() {
  const [apiKey, setApiKeyInput] = useState('')
  const [defaultTarget, setDefaultTarget] = useState('.')
  const [theme, setTheme] = useState<'dark' | 'light'>('dark')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    setApiKeyInput(getApiKey() ?? '')
    const stored = localStorage.getItem(DEFAULT_SCAN_TARGET)
    if (stored) setDefaultTarget(stored)
    const t = localStorage.getItem('nullvoid-theme') as 'dark' | 'light' | null
    if (t) setTheme(t)
  }, [])

  const handleSaveApiKey = () => {
    setApiKey(apiKey.trim() || null)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const handleSaveTarget = () => {
    const value = defaultTarget.trim() || '.'
    localStorage.setItem(DEFAULT_SCAN_TARGET, value)
    setDefaultTarget(value)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const handleThemeChange = (t: 'dark' | 'light') => {
    setTheme(t)
    document.documentElement.classList.toggle('dark', t === 'dark')
    localStorage.setItem('nullvoid-theme', t)
  }

  return (
    <>
      <h1>Settings</h1>
      <div className="card-minimal">
        <h3>API Key</h3>
        <p className="text-sm text-neutral-500 dark:text-neutral-400 mt-1 mb-3">
          Optional. When the API requires authentication, set your key here. Stored in localStorage.
        </p>
        <div className="flex gap-2">
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKeyInput(e.target.value)}
            placeholder="X-API-Key value"
            className="flex-1 px-4 py-2.5 bg-surface dark:bg-dark-surface border border-surface-border dark:border-dark-border rounded-md text-black dark:text-white text-sm font-medium focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white focus:ring-offset-0"
          />
          <button
            type="button"
            onClick={handleSaveApiKey}
            className="px-5 py-2.5 text-sm font-semibold rounded-md bg-black dark:bg-white text-white dark:text-black cursor-pointer transition-opacity hover:opacity-80"
          >
            Save
          </button>
        </div>
      </div>

      <div className="card-minimal">
        <h3>Default Scan Target</h3>
        <p className="text-sm text-neutral-500 dark:text-neutral-400 mt-1 mb-3">
          Default path used when starting a new scan (e.g. <code>.</code> or <code>./packages/api</code>).
        </p>
        <div className="flex gap-2">
          <input
            type="text"
            value={defaultTarget}
            onChange={(e) => setDefaultTarget(e.target.value)}
            placeholder="."
            className="flex-1 px-4 py-2.5 bg-surface dark:bg-dark-surface border border-surface-border dark:border-dark-border rounded-md text-black dark:text-white text-sm font-medium focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white focus:ring-offset-0"
          />
          <button
            type="button"
            onClick={handleSaveTarget}
            className="px-5 py-2.5 text-sm font-semibold rounded-md bg-black dark:bg-white text-white dark:text-black cursor-pointer transition-opacity hover:opacity-80"
          >
            Save
          </button>
        </div>
      </div>

      <div className="card-minimal">
        <h3>Theme</h3>
        <div className="flex gap-2 mt-3">
          <button
            type="button"
            onClick={() => handleThemeChange('light')}
            className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
              theme === 'light'
                ? 'bg-black dark:bg-white text-white dark:text-black'
                : 'bg-surface-muted dark:bg-dark-muted text-neutral-600 dark:text-neutral-400 hover:bg-surface dark:hover:bg-dark-surface'
            }`}
          >
            Light
          </button>
          <button
            type="button"
            onClick={() => handleThemeChange('dark')}
            className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
              theme === 'dark'
                ? 'bg-black dark:bg-white text-white dark:text-black'
                : 'bg-surface-muted dark:bg-dark-muted text-neutral-600 dark:text-neutral-400 hover:bg-surface dark:hover:bg-dark-surface'
            }`}
          >
            Dark
          </button>
        </div>
      </div>

      {saved && (
        <p className="text-sm text-green-600 dark:text-green-400 font-medium mt-4">Saved.</p>
      )}
    </>
  )
}
