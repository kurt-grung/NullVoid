import { useEffect, useState } from 'react'
import {
  getMlStatus,
  runMlExport,
  runMlTrain,
  runMlExportBehavioral,
  runMlTrainBehavioral,
  isApiUnavailableError,
} from '../api'

type Cmd = 'export' | 'train' | 'export-behavioral' | 'train-behavioral' | null

export default function ML() {
  const [available, setAvailable] = useState<boolean | null>(null)
  const [running, setRunning] = useState<Cmd>(null)
  const [output, setOutput] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [apiUnavailable, setApiUnavailable] = useState(false)

  useEffect(() => {
    getMlStatus()
      .then((r) => setAvailable(r.available))
      .catch((e) => {
        if (isApiUnavailableError(e)) setApiUnavailable(true)
        else setAvailable(false)
      })
  }, [])

  const run = async (cmd: Cmd, fn: () => Promise<{ stdout?: string; stderr?: string }>) => {
    if (!cmd) return
    setRunning(cmd)
    setError(null)
    setOutput(null)
    try {
      const r = await fn()
      const out = [r.stdout, r.stderr].filter(Boolean).join('\n') || 'Done.'
      setOutput(out)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setRunning(null)
    }
  }

  if (apiUnavailable) {
    return (
      <div className="alert-info mb-6" role="status">
        <p className="text-neutral-600 dark:text-neutral-400 text-sm font-medium">
          No API connected. Run <code>make api</code> and ensure the dashboard proxies to it.
        </p>
      </div>
    )
  }

  return (
    <>
      <h1>ML Pipeline</h1>
      <p className="text-neutral-500 dark:text-neutral-400 text-sm mb-6">
        Run ML commands via the API. Only available when the API runs locally (<code>make api</code>).
      </p>

      {available === false && !apiUnavailable && (
        <div className="alert-warning mb-6">
          <p className="text-neutral-600 dark:text-neutral-400 text-sm font-medium">
            ML commands are not available on this deployment. Run the API locally with <code>make api</code> and open the dashboard at localhost:5174.
          </p>
        </div>
      )}

      <div className="card-minimal">
        <h3>Dependency Confusion Model</h3>
        <div className="flex flex-wrap gap-3 mt-4">
          <button
            type="button"
            onClick={() => run('export', runMlExport)}
            disabled={!available || !!running}
            className="px-4 py-2 text-sm font-semibold rounded-md bg-black dark:bg-white text-white dark:text-black cursor-pointer transition-opacity hover:opacity-80 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {running === 'export' ? 'Running...' : 'Export Features'}
          </button>
          <button
            type="button"
            onClick={() => run('train', runMlTrain)}
            disabled={!available || !!running}
            className="px-4 py-2 text-sm font-semibold rounded-md bg-black dark:bg-white text-white dark:text-black cursor-pointer transition-opacity hover:opacity-80 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {running === 'train' ? 'Training...' : 'Train Model'}
          </button>
        </div>
        <p className="text-neutral-500 dark:text-neutral-400 text-xs mt-3">
          Export → train.jsonl. Train → model.pkl (XGBoost).
        </p>
      </div>

      <div className="card-minimal">
        <h3>Behavioral Model</h3>
        <div className="flex flex-wrap gap-3 mt-4">
          <button
            type="button"
            onClick={() => run('export-behavioral', runMlExportBehavioral)}
            disabled={!available || !!running}
            className="px-4 py-2 text-sm font-semibold rounded-md bg-black dark:bg-white text-white dark:text-black cursor-pointer transition-opacity hover:opacity-80 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {running === 'export-behavioral' ? 'Running...' : 'Export Behavioral'}
          </button>
          <button
            type="button"
            onClick={() => run('train-behavioral', runMlTrainBehavioral)}
            disabled={!available || !!running}
            className="px-4 py-2 text-sm font-semibold rounded-md bg-black dark:bg-white text-white dark:text-black cursor-pointer transition-opacity hover:opacity-80 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {running === 'train-behavioral' ? 'Training...' : 'Train Behavioral'}
          </button>
        </div>
        <p className="text-neutral-500 dark:text-neutral-400 text-xs mt-3">
          Export → train-behavioral.jsonl. Train → behavioral-model.pkl.
        </p>
      </div>

      <div className="card-minimal">
        <h3>Serve</h3>
        <p className="text-neutral-500 dark:text-neutral-400 text-sm">
          Start the ML server with <code>make ml-serve</code> or <code>npm run ml:serve</code> (port 8000).
        </p>
      </div>

      {error && (
        <div className="alert-error mb-6">
          {error}
        </div>
      )}

      {output && (
        <div className="card-minimal">
          <h3>Output</h3>
          <pre className="mt-3 p-4 bg-surface-muted dark:bg-dark-muted rounded-md text-xs font-mono text-neutral-700 dark:text-neutral-300 overflow-x-auto whitespace-pre-wrap">
            {output}
          </pre>
        </div>
      )}
    </>
  )
}
