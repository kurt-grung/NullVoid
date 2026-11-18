import { defineHandler } from 'nitro';

/** GET / - API info (avoids "Cannot GET /api" when visiting /api directly) */
export default defineHandler(() => ({
  name: 'NullVoid API',
  version: '1.0',
  endpoints: {
    health: 'GET /api/health',
    scans: 'GET /api/scans',
    scan: 'GET /api/scan/:id',
    triggerScan: 'POST /api/scan',
    validateRules: 'POST /api/rules/validate',
    rulesTemplate: 'GET /api/rules/template?format=yaml|json',
    report: 'GET /api/report/:scanId?format=html|markdown&compliance=soc2|iso27001',
    organizations: 'GET /api/organizations',
    teams: 'GET /api/teams',
    mlMetrics: 'GET /api/ml/metrics',
    mlDrift: 'GET /api/ml/drift',
    schedules: 'GET /api/schedules',
    schedule: 'POST /api/schedule',
    webhooks: 'GET /api/webhooks',
    audit: 'GET /api/audit',
    graphql: 'GET /api/graphql',
  },
}));
