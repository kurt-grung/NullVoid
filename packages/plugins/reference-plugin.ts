import type { NullVoidPlugin } from './types';

const plugin: NullVoidPlugin = {
  id: 'nullvoid-reference',
  version: '0.1.0',
  async detect(content, filePath) {
    if (content.includes('eval(atob(')) {
      return [
        {
          type: 'PLUGIN_OBFUSCATED_EVAL',
          message: 'Reference plugin: obfuscated eval pattern',
          severity: 'HIGH',
          confidence: 0.75,
        },
      ];
    }
    return [];
  },
};

export default plugin;
