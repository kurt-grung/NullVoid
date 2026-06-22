export interface PluginThreat {
  type: string;
  message: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
}

export interface NullVoidPlugin {
  id: string;
  version: string;
  detect: (content: string, filePath: string) => Promise<PluginThreat[]>;
}
