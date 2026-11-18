import { defineHandler } from 'nitro';
import { store } from '../utils/core';
import { orgHeader, requireRole } from '../utils/enterprise';
import { query } from '../utils/http';

export default defineHandler((event) => {
  requireRole(event, 'audit');
  const limit = Math.min(parseInt(query(event, 'limit') ?? '100', 10) || 100, 500);
  return { entries: store.listAudit(orgHeader(event), limit) };
});
