/**
 * Package.json type declaration
 */

export interface PackageJson {
  name: string;
  version: string;
  description: string;
  main: string;
  bin: Record<string, string>;
  scripts: Record<string, string>;
  keywords: string[];
  author: string;
  license: string;
  engines: {
    node: string;
  };
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  repository: {
    type: string;
    url: string;
  };
  bugs: {
    url: string;
  };
  homepage: string;
  publishConfig: {
    access: string;
  };
  files: string[];
}

const packageJson: PackageJson = {
  name: "nullvoid",
  version: "1.3.17",
  description: "Detect malicious code",
  main: "dist/scan.js",
  bin: {
    "nullvoid": "./dist/bin/nullvoid.js"
  },
  scripts: {
    "build": "tsc",
    "build:watch": "tsc --watch",
    "dev": "ts-node src/bin/nullvoid.ts",
    "test": "jest",
    "test:unit": "jest test/unit",
    "test:integration": "jest test/integration",
    "test:performance": "jest test/performance",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "scan": "node dist/scan.js",
    "scan:dev": "ts-node src/scan.ts",
    "badge": "node scripts/generate-badge.js",
    "badge:running": "node -e \"require('./scripts/generate-badge.js').setRunningBadge()\"",
    "badge:update": "npm run badge && git add README.md && git commit -m 'chore: Update dynamic test badge' || true",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "type-check": "tsc --noEmit",
    "prepublishOnly": "npm run build",
    "postinstall": "npm run build"
  },
  keywords: [
    "security",
    "malware",
    "detection",
    "scanner",
    "javascript",
    "nodejs",
    "npm",
    "package",
    "supply-chain",
    "wallet-hijacking",
    "obfuscation",
    "sandbox",
    "static-analysis",
    "cli",
    "production-ready",
    "typescript"
  ],
  author: "NullVoid Team",
  license: "MIT",
  engines: {
    node: ">=14.0.0"
  },
  dependencies: {
    "@babel/parser": "^7.23.0",
    "@babel/traverse": "^7.23.0",
    "@babel/types": "^7.23.0",
    "acorn": "^8.10.0",
    "acorn-walk": "^8.2.0",
    "async-mutex": "^0.5.0",
    "axios": "^1.6.0",
    "commander": "^11.1.0",
    "fs-extra": "^11.1.0",
    "glob": "^10.3.0",
    "js-yaml": "^4.1.0",
    "node-fetch": "^2.7.0",
    "ora": "^5.4.1",
    "tar": "^6.2.0"
  },
  devDependencies: {
    "@jest/globals": "^29.7.0",
    "@types/jest": "^30.0.0",
    "@types/node": "^24.5.2",
    "eslint": "^8.0.0",
    "jest": "^29.7.0",
    "ts-jest": "^29.4.4",
    "ts-node": "^10.9.2",
    "typescript": "^5.9.2"
  },
  repository: {
    type: "git",
    url: "https://github.com/kurt-grung/NullVoid.git"
  },
  bugs: {
    url: "https://github.com/kurt-grung/NullVoid/issues"
  },
  homepage: "https://github.com/kurt-grung/NullVoid#readme",
  publishConfig: {
    access: "public"
  },
  files: [
    "dist/",
    "src/",
    "bin/",
    "lib/",
    "scan.js",
    "colors.js",
    "README.md",
    "LICENSE",
    "tsconfig.json"
  ]
};

export default packageJson;
