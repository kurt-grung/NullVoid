/** OpenAPI 3.0 specification (moved verbatim from the Express app's swagger-jsdoc definition) */
export const openApiSpec = {
  openapi: '3.0.0',
  info: {
    title: 'NullVoid API',
    version: '1.0.0',
    description:
      'NullVoid security scanner REST API — scan orchestration, results, multi-tenant management, and ML operations.',
  },
  components: {
    securitySchemes: {
      apiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    },
    parameters: {
      OrgId: { name: 'X-Organization-Id', in: 'header', schema: { type: 'string' } },
      TeamId: { name: 'X-Team-Id', in: 'header', schema: { type: 'string' } },
    },
  },
  paths: {
    '/health': {
      get: {
        summary: 'Health check',
        parameters: [{ name: 'platform', in: 'query', schema: { type: 'string', enum: ['1'] } }],
        responses: { 200: { description: 'ok' } },
      },
    },
    '/scan': {
      post: {
        summary: 'Trigger a synchronous scan',
        security: [{ apiKey: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: { target: { type: 'string' } },
                required: ['target'],
              },
            },
          },
        },
        responses: {
          200: { description: 'Scan result' },
          400: { description: 'Bad request' },
          401: { description: 'Unauthorized' },
          500: { description: 'Scan failed' },
        },
      },
    },
    '/scan/{id}': {
      get: {
        summary: 'Get scan by ID',
        security: [{ apiKey: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Scan row' },
          403: { description: 'Forbidden' },
          404: { description: 'Not found' },
        },
      },
    },
    '/scans': {
      get: {
        summary: 'List scans',
        security: [{ apiKey: [] }],
        parameters: [
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', minimum: 1, maximum: 100, default: 50 },
          },
          { name: 'offset', in: 'query', schema: { type: 'integer', minimum: 0, default: 0 } },
        ],
        responses: { 200: { description: 'List of scans' } },
      },
    },
    '/report/{scanId}': {
      get: {
        summary: 'Generate report for a completed scan',
        security: [{ apiKey: [] }],
        parameters: [
          { name: 'scanId', in: 'path', required: true, schema: { type: 'string' } },
          {
            name: 'format',
            in: 'query',
            schema: { type: 'string', enum: ['html', 'markdown'], default: 'html' },
          },
          {
            name: 'compliance',
            in: 'query',
            schema: { type: 'string', enum: ['soc2', 'iso27001'] },
          },
        ],
        responses: {
          200: { description: 'Report content' },
          400: { description: 'Scan not completed' },
          403: { description: 'Forbidden' },
          404: { description: 'Not found' },
        },
      },
    },
    '/organizations': {
      get: {
        summary: 'List organizations (scoped to caller org when key is set)',
        security: [{ apiKey: [] }],
        responses: { 200: { description: 'List of organizations' } },
      },
      post: {
        summary: 'Create organization',
        security: [{ apiKey: [] }],
        requestBody: {
          content: {
            'application/json': {
              schema: { type: 'object', properties: { name: { type: 'string' } } },
            },
          },
        },
        responses: { 201: { description: 'Created' } },
      },
    },
    '/teams': {
      get: {
        summary: 'List teams',
        security: [{ apiKey: [] }],
        parameters: [{ name: 'organizationId', in: 'query', schema: { type: 'string' } }],
        responses: { 200: { description: 'List of teams' } },
      },
      post: {
        summary: 'Create team',
        security: [{ apiKey: [] }],
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: { organizationId: { type: 'string' }, name: { type: 'string' } },
                required: ['organizationId'],
              },
            },
          },
        },
        responses: { 201: { description: 'Created' } },
      },
    },
    '/ml/metrics': {
      get: {
        summary: 'ML training metadata',
        security: [{ apiKey: [] }],
        responses: { 200: { description: 'Training metrics' } },
      },
    },
    '/ml/status': {
      get: {
        summary: 'ML service status',
        security: [{ apiKey: [] }],
        responses: { 200: { description: 'Status object' } },
      },
    },
    '/ml/drift': {
      get: {
        summary: 'Model drift statistics',
        security: [{ apiKey: [] }],
        responses: {
          200: { description: 'Drift result' },
          503: { description: 'ML_SERVICE_URL not set' },
        },
      },
    },
    '/ml/feedback': {
      post: {
        summary: 'Submit prediction feedback',
        security: [{ apiKey: [] }],
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  packageName: { type: 'string' },
                  version: { type: 'string' },
                  label: { type: 'integer', enum: [0, 1] },
                  scanId: { type: 'string' },
                },
                required: ['packageName', 'version', 'label', 'scanId'],
              },
            },
          },
        },
        responses: { 200: { description: 'ok' }, 400: { description: 'Invalid payload' } },
      },
    },
  },
  // swagger-jsdoc always added an empty tags list; kept for an identical document.
  tags: [] as string[],
};
