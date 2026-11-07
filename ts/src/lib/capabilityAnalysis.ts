/**
 * Capability analysis
 *
 * Resolves which Node capabilities a file uses from its AST (not from text
 * matching) and reports *combinations* that indicate malicious intent. A lone
 * `require('fs')` is what most real packages do and is not a threat; reading
 * `process.env` and sending it over the network is.
 *
 * Capabilities are collected per file:
 *   - fs            : fs / fs/promises / node:fs
 *   - exec          : child_process, or vm.runIn*Context, or eval / new Function
 *   - network       : http, https, net, tls, dns, fetch, XMLHttpRequest, WebSocket
 *   - env           : process.env
 *   - hostInfo      : os.userInfo / os.hostname / os.networkInterfaces
 *   - credentials   : a string literal naming a credential file (~/.npmrc, id_rsa, ...)
 *   - decode        : atob / Buffer.from(x, 'base64') / String.fromCharCode
 *   - dynamicModule : require(<non-literal>) — hides which module is loaded
 *
 * Dynamic construction such as `require(['child_','process'].join(''))` is
 * reported as `dynamicModule`; a module name is never guessed from it.
 */

import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import { createThreat } from '../types/core';
import type { Threat, SeverityLevel } from '../types/core';

export type Capability =
  | 'fs'
  | 'exec'
  | 'network'
  | 'env'
  | 'hostInfo'
  | 'credentials'
  | 'decode'
  | 'dynamicModule';

export interface CapabilityHit {
  capability: Capability;
  /** What triggered it: module name, API name or literal */
  via: string;
  line: number;
}

export interface CapabilityReport {
  capabilities: Set<Capability>;
  hits: CapabilityHit[];
  /** Modules resolved from literal require()/import specifiers */
  modules: Set<string>;
  parsed: boolean;
}

const MODULE_CAPABILITY: Record<string, Capability> = {
  fs: 'fs',
  'fs/promises': 'fs',
  child_process: 'exec',
  vm: 'exec',
  worker_threads: 'exec',
  http: 'network',
  https: 'network',
  http2: 'network',
  net: 'network',
  tls: 'network',
  dgram: 'network',
  dns: 'network',
  'dns/promises': 'network',
  os: 'hostInfo',
};

/** Third-party modules whose only purpose is network I/O */
const NETWORK_PACKAGES = new Set([
  'axios',
  'node-fetch',
  'got',
  'request',
  'superagent',
  'undici',
  'ws',
  'socket.io-client',
  'needle',
  'phin',
]);

const CREDENTIAL_PATTERNS: RegExp[] = [
  /\.npmrc/,
  /\.ssh\/(id_[a-z0-9]+|known_hosts|config)/,
  /\.aws\/(credentials|config)/,
  /\.docker\/config\.json/,
  /\.kube\/config/,
  /\.git-credentials/,
  /\.netrc/,
  /\.env(\.[a-z]+)?$/,
  /\.gnupg/,
  /keychain|login\.keychain/i,
  /Local State|Login Data|Cookies/, // Chromium profile files
  /wallet\.dat|keystore/i,
];

const HOST_INFO_APIS = new Set(['userInfo', 'hostname', 'networkInterfaces', 'cpus', 'homedir']);

function stripNodePrefix(spec: string): string {
  return spec.startsWith('node:') ? spec.slice(5) : spec;
}

function moduleCapability(spec: string): Capability | undefined {
  const name = stripNodePrefix(spec);
  if (MODULE_CAPABILITY[name]) return MODULE_CAPABILITY[name];
  const base = name.startsWith('@')
    ? name.split('/').slice(0, 2).join('/')
    : (name.split('/')[0] ?? name);
  if (NETWORK_PACKAGES.has(base)) return 'network';
  return undefined;
}

function isIdentifier(node: acorn.Node, name: string): boolean {
  return node.type === 'Identifier' && (node as acorn.Identifier).name === name;
}

function memberName(node: acorn.Node): string | undefined {
  if (node.type !== 'MemberExpression') return undefined;
  const m = node as acorn.MemberExpression;
  if (m.property.type === 'Identifier' && !m.computed) return (m.property as acorn.Identifier).name;
  if (m.property.type === 'Literal') return String((m.property as acorn.Literal).value);
  return undefined;
}

function objectName(node: acorn.Node): string | undefined {
  if (node.type !== 'MemberExpression') return undefined;
  const o = (node as acorn.MemberExpression).object;
  return o.type === 'Identifier' ? (o as acorn.Identifier).name : undefined;
}

/**
 * Parse a file and collect the capabilities it uses.
 */
export function analyzeCapabilities(content: string): CapabilityReport {
  const report: CapabilityReport = {
    capabilities: new Set(),
    hits: [],
    modules: new Set(),
    parsed: false,
  };

  let ast: acorn.Program;
  try {
    ast = acorn.parse(content, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      allowHashBang: true,
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true,
      locations: true,
    });
  } catch {
    try {
      ast = acorn.parse(content, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        allowHashBang: true,
        allowReturnOutsideFunction: true,
        locations: true,
      });
    } catch {
      return report;
    }
  }
  report.parsed = true;

  const add = (capability: Capability, via: string, node: acorn.Node): void => {
    report.capabilities.add(capability);
    report.hits.push({ capability, via, line: node.loc?.start.line ?? 0 });
  };

  const addModule = (spec: string, node: acorn.Node): void => {
    const name = stripNodePrefix(spec);
    report.modules.add(name);
    const cap = moduleCapability(spec);
    if (cap) add(cap, name, node);
  };

  walk.simple(ast, {
    ImportDeclaration(node) {
      const src = (node as acorn.ImportDeclaration).source.value;
      if (typeof src === 'string') addModule(src, node);
    },
    ImportExpression(node) {
      const src = (node as acorn.ImportExpression).source;
      if (src.type === 'Literal' && typeof (src as acorn.Literal).value === 'string') {
        addModule((src as acorn.Literal).value as string, node);
      } else {
        add('dynamicModule', 'import(<expr>)', node);
      }
    },
    CallExpression(node) {
      const call = node as acorn.CallExpression;
      const callee = call.callee;
      const first = call.arguments[0];

      // require(...)
      if (isIdentifier(callee, 'require')) {
        if (
          first &&
          first.type === 'Literal' &&
          typeof (first as acorn.Literal).value === 'string'
        ) {
          addModule((first as acorn.Literal).value as string, node);
        } else if (first) {
          add('dynamicModule', 'require(<expr>)', node);
        }
        return;
      }

      // eval(...) / new Function handled below / Function(...)
      if (isIdentifier(callee, 'eval') || isIdentifier(callee, 'Function')) {
        add('exec', (callee as acorn.Identifier).name, node);
        return;
      }

      // fetch(...)
      if (isIdentifier(callee, 'fetch')) {
        add('network', 'fetch', node);
        return;
      }

      // atob(...) / String.fromCharCode(...)
      if (isIdentifier(callee, 'atob')) {
        add('decode', 'atob', node);
        return;
      }
      if (callee.type === 'MemberExpression') {
        const obj = objectName(callee);
        const prop = memberName(callee);
        if (obj === 'String' && prop === 'fromCharCode') add('decode', 'String.fromCharCode', node);
        if (obj === 'Buffer' && prop === 'from') {
          const enc = call.arguments[1];
          if (
            enc &&
            enc.type === 'Literal' &&
            /^(base64|hex)$/i.test(String((enc as acorn.Literal).value))
          ) {
            add('decode', `Buffer.from(…,'${(enc as acorn.Literal).value}')`, node);
          }
        }
        if (obj === 'process' && prop === 'binding') add('dynamicModule', 'process.binding', node);
        if (obj === 'os' && prop && HOST_INFO_APIS.has(prop)) add('hostInfo', `os.${prop}`, node);
        if (obj === 'vm' && prop && /^runIn/.test(prop)) add('exec', `vm.${prop}`, node);
      }
    },
    NewExpression(node) {
      const n = node as acorn.NewExpression;
      if (isIdentifier(n.callee, 'Function')) add('exec', 'new Function', node);
      if (isIdentifier(n.callee, 'XMLHttpRequest')) add('network', 'XMLHttpRequest', node);
      if (isIdentifier(n.callee, 'WebSocket')) add('network', 'WebSocket', node);
    },
    MemberExpression(node) {
      if (objectName(node) === 'process' && memberName(node) === 'env') {
        add('env', 'process.env', node);
      }
    },
    Literal(node) {
      const v = (node as acorn.Literal).value;
      if (typeof v !== 'string' || v.length < 4 || v.length > 200) return;
      for (const re of CREDENTIAL_PATTERNS) {
        if (re.test(v)) {
          add('credentials', v.length > 60 ? v.slice(0, 57) + '…' : v, node);
          break;
        }
      }
    },
    TemplateLiteral(node) {
      const raw = (node as acorn.TemplateLiteral).quasis.map((q) => q.value.cooked ?? '').join('');
      if (raw.length < 4) return;
      for (const re of CREDENTIAL_PATTERNS) {
        if (re.test(raw)) {
          add('credentials', raw.length > 60 ? raw.slice(0, 57) + '…' : raw, node);
          break;
        }
      }
    },
  });

  return report;
}

interface Combination {
  type:
    | 'DATA_EXFILTRATION'
    | 'CREDENTIAL_THEFT'
    | 'REMOTE_CODE_EXECUTION'
    | 'OBFUSCATED_EXECUTION'
    | 'DYNAMIC_MODULE_LOAD';
  requires: Capability[];
  severity: SeverityLevel;
  confidence: number;
  message: string;
}

const COMBINATIONS: Combination[] = [
  {
    type: 'CREDENTIAL_THEFT',
    requires: ['credentials', 'network'],
    severity: 'CRITICAL',
    confidence: 0.9,
    message: 'References credential files and has network access',
  },
  {
    type: 'CREDENTIAL_THEFT',
    requires: ['credentials', 'fs', 'decode'],
    severity: 'HIGH',
    confidence: 0.7,
    message: 'Reads credential files and encodes data',
  },
  {
    type: 'DATA_EXFILTRATION',
    requires: ['env', 'network'],
    severity: 'HIGH',
    confidence: 0.75,
    message: 'Reads environment variables and has network access',
  },
  {
    type: 'DATA_EXFILTRATION',
    requires: ['hostInfo', 'network'],
    severity: 'MEDIUM',
    confidence: 0.6,
    message: 'Collects host information and has network access',
  },
  {
    type: 'REMOTE_CODE_EXECUTION',
    requires: ['network', 'exec'],
    severity: 'HIGH',
    confidence: 0.75,
    message: 'Has network access and executes code or processes',
  },
  {
    type: 'OBFUSCATED_EXECUTION',
    requires: ['decode', 'exec'],
    severity: 'HIGH',
    confidence: 0.8,
    message: 'Decodes data and executes code or processes',
  },
  {
    type: 'DYNAMIC_MODULE_LOAD',
    requires: ['dynamicModule'],
    severity: 'MEDIUM',
    confidence: 0.6,
    message: 'Loads modules from a computed name, hiding which module is used',
  },
];

/** Capabilities worth a visible INFO note on their own (only with --all) */
const INFO_CAPABILITIES: Capability[] = ['exec'];

/**
 * Turn a capability report into threats. Lone capabilities are INFO at most;
 * combinations carry the real severities.
 */
export function capabilityThreats(
  content: string,
  filePath: string,
  options: { isTestFile?: boolean; isConfigFile?: boolean } = {}
): Threat[] {
  const report = analyzeCapabilities(content);
  if (!report.parsed) return [];

  const filename = filePath.split('/').pop() || filePath;
  const threats: Threat[] = [];
  const demote = options.isTestFile || options.isConfigFile;

  const firstHit = (cap: Capability): CapabilityHit | undefined =>
    report.hits.find((h) => h.capability === cap);

  const lineOf = (hit: CapabilityHit | undefined): number | undefined =>
    hit && hit.line > 0 ? hit.line : undefined;

  for (const combo of COMBINATIONS) {
    if (!combo.requires.every((c) => report.capabilities.has(c))) continue;
    const evidence = combo.requires
      .map((c) => {
        const h = firstHit(c);
        return h ? `${c}: ${h.via} (line ${h.line})` : c;
      })
      .join('; ');
    const severity: SeverityLevel = demote ? 'LOW' : combo.severity;
    threats.push(
      createThreat(
        combo.type,
        combo.message,
        filePath,
        filename,
        severity,
        `${combo.message}. Evidence — ${evidence}`,
        {
          confidence: demote ? 0.3 : combo.confidence,
          lineNumber: lineOf(firstHit(combo.requires[0] as Capability)),
          metadata: {
            capabilities: [...report.capabilities],
            modules: [...report.modules],
          },
        }
      )
    );
  }

  // Lone capabilities: INFO notes, never a finding on their own.
  if (threats.length === 0) {
    for (const cap of INFO_CAPABILITIES) {
      const hit = firstHit(cap);
      if (!hit) continue;
      threats.push(
        createThreat(
          'CAPABILITY_NOTE',
          `Uses ${hit.via}`,
          filePath,
          filename,
          'LOW',
          `File uses ${hit.via} (${cap}) with no other risky capability; informational only`,
          {
            confidence: 0.2,
            lineNumber: lineOf(hit),
            metadata: { capabilities: [...report.capabilities], modules: [...report.modules] },
          }
        )
      );
    }
  }

  return threats;
}
