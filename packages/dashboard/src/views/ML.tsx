import { useEffect, useState } from 'react'
import {
  getMlStatus,
  getMlMetrics,
  runMlExport,
  runMlTrain,
  runMlExportBehavioral,
  runMlTrainBehavioral,
  isApiUnavailableError,
} from '../api'

type Cmd = 'export' | 'train' | 'export-behavioral' | 'train-behavioral' | null

function MlMetaBlock({ meta }: { meta: Record<string, unknown> }) {
  const size = meta.dataset_size
  const dist = meta.class_distribution
  const trainMetrics = meta.metrics
  const when = meta.training_date
  const modelType = meta.model_type
  return (
    <dl className="space-y-2 text-xs text-neutral-600 dark:text-neutral-400">
      {modelType != null && (
        <>
          <dt className="text-neutral-500 dark:text-neutral-500 font-medium">Model</dt>
          <dd className="font-mono">{String(modelType)}</dd>
        </>
      )}
      {when != null && (
        <>
          <dt className="text-neutral-500 dark:text-neutral-500 font-medium">Training</dt>
          <dd className="font-mono">{String(when)}</dd>
        </>
      )}
      {size != null && (
        <>
          <dt className="text-neutral-500 dark:text-neutral-500 font-medium">Dataset size</dt>
          <dd className="font-mono">{String(size)}</dd>
        </>
      )}
      {dist != null && (
        <>
          <dt className="text-neutral-500 dark:text-neutral-500 font-medium">Class distribution</dt>
          <dd className="font-mono">{JSON.stringify(dist)}</dd>
        </>
      )}
      {trainMetrics != null && Object.keys(trainMetrics as object).length > 0 && (
        <>
          <dt className="text-neutral-500 dark:text-neutral-500 font-medium">Train holdout metrics</dt>
          <dd>
            <pre className="mt-1 p-2 bg-surface-muted dark:bg-dark-muted rounded text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">
              {JSON.stringify(trainMetrics, null, 2)}
            </pre>
          </dd>
        </>
      )}
    </dl>
  )
}

export default function ML() {
  const [available, setAvailable] = useState<boolean | null>(null)
  const [serveAvailable, setServeAvailable] = useState<boolean | null>(null)
  const [serveHint, setServeHint] = useState<string | null>(null)
  const [serveNote, setServeNote] = useState<string | null>(null)
  const [mlServiceUrl, setMlServiceUrl] = useState<string | null>(null)
  const [running, setRunning] = useState<Cmd>(null)
  const [output, setOutput] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [apiUnavailable, setApiUnavailable] = useState(false)
  const [metrics, setMetrics] = useState<{
    dependency: Record<string, unknown> | null
    behavioral: Record<string, unknown> | null
    hint?: string
  } | null>(null)

  useEffect(() => {
    getMlStatus()
      .then((r) => {
        setAvailable(r.available)
        setServeAvailable(r.serveAvailable ?? false)
        setServeHint(r.serveHint ?? null)
        setServeNote(r.serveNote ?? null)
        setMlServiceUrl(r.mlServiceUrl ?? null)
      })
      .catch((e) => {
        if (isApiUnavailableError(e)) setApiUnavailable(true)
        else setAvailable(false)
      })
  }, [])

  useEffect(() => {
    if (apiUnavailable) return
    getMlMetrics()
      .then((m) => setMetrics(m))
      .catch(() => setMetrics(null))
  }, [apiUnavailable])

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
      {available === false && !apiUnavailable ? (
        <div className="alert-info mb-6">
          <p className="text-sm font-medium">
            ML commands (export, train) run locally only. Use <code>make api</code> and <code>make dashboard</code>, then open localhost:5174.
          </p>
        </div>
      ) : (
        <p className="text-neutral-500 dark:text-neutral-400 text-sm mb-6">
          Export features and train XGBoost models for dependency confusion and behavioral detection.
        </p>
      )}

      {metrics && (metrics.dependency || metrics.behavioral) && (
        <div className="card-minimal mb-6">
          <h3>Last train metrics</h3>
          <p className="text-neutral-500 dark:text-neutral-400 text-xs mt-2 mb-4">
            From <code className="text-xs">ml-model/metadata.json</code> and{' '}
            <code className="text-xs">behavioral-metadata.json</code> on the API host. CI also publishes held-out
            validation metrics as the <code className="text-xs">ml-eval-report</code> artifact.
          </p>
          <div className="grid gap-4 sm:grid-cols-2">
            {metrics.dependency && (
              <div className="rounded-md border border-neutral-200 dark:border-neutral-700 p-3 text-sm">
                <h4 className="font-semibold text-neutral-800 dark:text-neutral-200 mb-2">Dependency model</h4>
                <MlMetaBlock meta={metrics.dependency} />
              </div>
            )}
            {metrics.behavioral && (
              <div className="rounded-md border border-neutral-200 dark:border-neutral-700 p-3 text-sm">
                <h4 className="font-semibold text-neutral-800 dark:text-neutral-200 mb-2">Behavioral model</h4>
                <MlMetaBlock meta={metrics.behavioral} />
              </div>
            )}
          </div>
          {metrics.hint && (
            <p className="text-neutral-500 dark:text-neutral-400 text-xs mt-3">{metrics.hint}</p>
          )}
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
        {serveAvailable ? (
          <>
            <p className="text-green-600 dark:text-green-400 text-sm font-medium">
              ML scoring server is running
              {mlServiceUrl ? (
                <>
                  {' '}
                  (<code className="text-xs break-all">{mlServiceUrl}</code>)
                </>
              ) : null}
              .
            </p>
            {serveNote && (
              <p className="text-neutral-500 dark:text-neutral-400 text-xs mt-2">{serveNote}</p>
            )}
          </>
        ) : (
          <p className="text-neutral-500 dark:text-neutral-400 text-sm">
            {serveHint ?? 'Start the ML server with make ml-serve or npm run ml:serve (port 8000).'}
          </p>
        )}
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
