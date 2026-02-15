/**
 * Vercel serverless entry - re-exports the built Express app
 * Requires: npm run build (from root) to produce packages/api/dist
 */
module.exports = require('../packages/api/dist/index.js');
