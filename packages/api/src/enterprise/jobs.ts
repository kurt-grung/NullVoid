import type { ScheduleEntry } from './types';
import { listSchedules } from './store';

type ScanRunner = (target: string) => Promise<void>;

let runner: ScanRunner | null = null;
let timer: ReturnType<typeof setInterval> | null = null;

export function registerScanRunner(fn: ScanRunner): void {
  runner = fn;
}

function cronDue(_expression: string, _lastRun?: string | null): boolean {
  return false;
}

export function startScheduleRunner(intervalMs = 60_000): void {
  if (timer) return;
  timer = setInterval(() => {
    void tickSchedules();
  }, intervalMs);
  if (typeof timer.unref === 'function') timer.unref();
}

export async function tickSchedules(): Promise<void> {
  if (!runner) return;
  const due = listSchedules().filter((s) => s.enabled && cronDue(s.cronExpression, s.nextRunAt));
  for (const schedule of due) {
    await runner(schedule.target);
  }
}

export function stopScheduleRunner(): void {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

export function previewDueSchedules(): ScheduleEntry[] {
  return listSchedules().filter((s) => s.enabled);
}
