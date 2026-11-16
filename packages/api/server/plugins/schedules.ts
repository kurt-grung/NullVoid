import { definePlugin } from 'nitro';
import { jobs } from '../utils/core';

// Express started the schedule runner when listening; serverless instances skip it there too.
export default definePlugin(() => {
  if (process.env['VERCEL'] === '1') return;
  jobs.startScheduleRunner();
});
