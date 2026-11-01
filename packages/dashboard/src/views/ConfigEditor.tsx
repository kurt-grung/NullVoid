import { useState } from 'react'
import Breadcrumbs from '../components/Breadcrumbs'

const STORAGE_KEY = 'nullvoid-rc-draft'

export default function ConfigEditor() {
  const [json, setJson] = useState(() => localStorage.getItem(STORAGE_KEY) ?? '{\n  "depth": 5\n}')
  const [validation, setValidation] = useState<string | null>(null)

  const validate = () => {
    try {
      JSON.parse(json)
      setValidation('Valid JSON')
    } catch (e) {
      setValidation(e instanceof Error ? e.message : 'Invalid JSON')
    }
  }

  const save = () => {
    localStorage.setItem(STORAGE_KEY, json)
    setValidation('Saved to browser local draft (copy to .nullvoidrc.json)')
  }

  return (
    <div className="page space-y-4">
      <Breadcrumbs items={[{ label: 'Configuration' }]} />
      <h1 className="text-xl font-semibold">Web configuration</h1>
      <p className="text-sm text-neutral-500">
        Edit a JSON draft for <code>.nullvoidrc.json</code>. Use CLI <code>nullvoid validate-config</code> before deploy.
      </p>
      <textarea
        className="w-full min-h-[280px] font-mono text-sm p-3 rounded border border-surface-border dark:border-dark-border bg-surface dark:bg-dark-surface"
        value={json}
        onChange={(e) => setJson(e.target.value)}
      />
      <div className="flex gap-2">
        <button type="button" className="btn-minimal" onClick={validate}>Validate</button>
        <button type="button" className="btn-minimal" onClick={save}>Save draft</button>
      </div>
      {validation && <p className="text-sm">{validation}</p>}
    </div>
  )
}
