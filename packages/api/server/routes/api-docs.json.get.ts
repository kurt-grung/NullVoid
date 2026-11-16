import { defineHandler } from 'nitro';
import { openApiSpec } from '../utils/openapi';

export default defineHandler(() => openApiSpec);
