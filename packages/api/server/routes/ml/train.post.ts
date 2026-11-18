import { defineHandler } from 'nitro';
import { runMlCommandRoute } from '../../utils/ml';

/** POST /ml/train - runs `nullvoid train` from the repo root (local/Railway only) */
export default defineHandler((event) => runMlCommandRoute(event, 'train', 'Train failed'));
