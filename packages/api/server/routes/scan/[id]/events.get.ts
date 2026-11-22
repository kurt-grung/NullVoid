import { defineHandler } from 'nitro';
import { param } from '../../../utils/http';

/** GET /scan/:id/events - SSE stream (connected event, then a heartbeat every 15s) */
export default defineHandler((event) => {
  const scanId = param(event, 'id');
  const enc = new TextEncoder();
  let interval: ReturnType<typeof setInterval> | undefined;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const send = (data: unknown) => controller.enqueue(enc.encode(`data: ${JSON.stringify(data)}\n\n`));
      send({ scanId, status: 'connected' });
      interval = setInterval(() => send({ scanId, heartbeat: Date.now() }), 15000);
      event.req.signal?.addEventListener('abort', () => {
        clearInterval(interval);
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      });
    },
    cancel() {
      clearInterval(interval);
    },
  });
  event.res.headers.set('Content-Type', 'text/event-stream');
  event.res.headers.set('Cache-Control', 'no-cache');
  event.res.headers.set('Connection', 'keep-alive');
  return stream;
});
