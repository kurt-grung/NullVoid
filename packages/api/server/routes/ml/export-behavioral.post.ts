import { defineHandler } from 'nitro';
import { runMlCommandRoute } from '../../utils/ml';

/** POST /ml/export-behavioral - runs `nullvoid export-behavioral` from the repo root (local/Railway only) */
export default defineHandler((event) => runMlCommandRoute(event, 'export-behavioral', 'Export behavioral failed'));
