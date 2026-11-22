import { defineHandler } from 'nitro';

export default defineHandler(() => ({
  message: 'GraphQL endpoint planned; use REST /scans and /scan/:id for now.',
  plannedQueries: ['scans', 'scan', 'threats', 'trends'],
}));
