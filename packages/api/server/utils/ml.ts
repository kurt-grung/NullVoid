import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import type { H3Event } from 'nitro/h3';
import { ML_AVAILABLE, ROOT } from './config';
import { json } from './http';
import { mlRateLimit } from './rateLimit';

const execAsync = promisify(exec);

/** Shared body of POST /ml/{export,train,export-behavioral,train-behavioral} */
export async function runMlCommandRoute(event: H3Event, subcommand: string, failLabel: string) {
  mlRateLimit(event);
  if (!ML_AVAILABLE) {
    return json(event, 503, {
      error: 'ML commands only available when running API locally',
      hint: 'Run `make api` and use the dashboard at localhost:5174',
    });
  }
  try {
    const { stdout, stderr } = await execAsync(`node ts/dist/bin/nullvoid.js ${subcommand}`, {
      cwd: ROOT,
      maxBuffer: 10 * 1024 * 1024,
    });
    return { ok: true, stdout: stdout.trim(), stderr: stderr.trim() };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; message?: string };
    return json(event, 500, {
      error: e.message ?? failLabel,
      stdout: e.stdout?.trim(),
      stderr: e.stderr?.trim(),
    });
  }
}
