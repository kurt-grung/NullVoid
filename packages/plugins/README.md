# NullVoid Plugin API (Phase 5)

Third-party detectors register via Node modules exporting:

```typescript
export interface NullVoidPlugin {
  id: string;
  version: string;
  detect(content: string, filePath: string): Promise<Array<{
    type: string;
    message: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    confidence: number;
  }>>;
}
```

Load plugins from `.nullvoid/plugins/` or `NULLVOID_PLUGINS` env (comma-separated paths).

Reference implementation: `reference-plugin.ts`.
