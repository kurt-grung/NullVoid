import { defineHandler } from 'nitro';
import { runMlCommandRoute } from '../../utils/ml';

/** POST /ml/train-behavioral - runs `nullvoid train-behavioral` from the repo root (local/Railway only) */
export default defineHandler((event) => runMlCommandRoute(event, 'train-behavioral', 'Train behavioral failed'));
