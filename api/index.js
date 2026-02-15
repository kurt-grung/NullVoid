/**
 * Vercel serverless entry - re-exports the built Express app
 * Requires: npm run build (from root) to produce packages/api/dist
 */
let app;
try {
  app = require('../packages/api/dist/index.js');
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  const fallback = (_req, res) => {
    res.statusCode = 503;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        error: 'API failed to load',
        message: msg.includes('Cannot find module')
          ? 'Build output missing. Ensure npm run build runs and produces packages/api/dist.'
          : msg,
        hint: 'Check Vercel build logs. Add TURSO_DATABASE_URL and TURSO_AUTH_TOKEN for database.',
      })
    );
  };
  app = fallback;
}
module.exports = app;
