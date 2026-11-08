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
 *   - env           : process.env.<KEY> (config read)
 *   - envDump       : process.env used wholesale: JSON.stringify(process.env), {...process.env},
 *                     Object.keys/entries(process.env), process.env passed as a bare argument
 *   - execNamed     : exec capability that came from a module required BY NAME (child_process, vm)
 *   - evalDynamic   : eval / new Function / vm.runIn* whose input is not a string literal
 *   - chmodExec     : fs.chmod* in a file that also executes a file (download-and-run droppers)
 *   - hostInfo      : one of os.userInfo / os.hostname / os.networkInterfaces / os.cpus
 *   - hostFingerprint: three or more distinct host-info APIs in one file (a beacon, not config)
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
  | 'execNamed'
  | 'evalDynamic'
  | 'chmodExec'
  | 'network'
  | 'env'
  | 'envDump'
  | 'hostInfo'
  | 'hostFingerprint'
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

/** Method names that execute processes or code regardless of the receiver */
/**
 * Method names that execute processes or code regardless of the receiver.
 * `.exec()` is deliberately absent: RegExp.prototype.exec is everywhere.
 * Bare `.exec()` counts only when the receiver is a known child_process
 * binding (see CallExpression below).
 */
const EXEC_METHODS = new Set([
  'execSync',
  'execFile',
  'execFileSync',
  'spawn',
  'spawnSync',
  'fork',
  'runInThisContext',
  'runInNewContext',
  'runInContext',
]);

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

  /** Identifiers bound to a child_process import: const cp = require('child_process') */
  const execReceivers = new Set<string>(['child_process', 'cp', 'childProcess']);

  const addModule = (spec: string, node: acorn.Node): void => {
    const name = stripNodePrefix(spec);
    report.modules.add(name);
    const cap = moduleCapability(spec);
    if (cap) add(cap, name, node);
    if (cap === 'exec') add('execNamed', name, node);
  };

  walk.simple(ast, {
    ImportDeclaration(node) {
      const decl = node as acorn.ImportDeclaration;
      const src = decl.source.value;
      if (typeof src === 'string') {
        addModule(src, node);
        if (stripNodePrefix(src) === 'child_process') {
          for (const sp of decl.specifiers) execReceivers.add(sp.local.name);
        }
      }
    },
    VariableDeclarator(node) {
      const d = node as acorn.VariableDeclarator;
      const init = d.init;
      if (
        init &&
        init.type === 'CallExpression' &&
        isIdentifier((init as acorn.CallExpression).callee, 'require') &&
        d.id.type === 'Identifier'
      ) {
        const a = (init as acorn.CallExpression).arguments[0];
        if (
          a &&
          a.type === 'Literal' &&
          stripNodePrefix(String((a as acorn.Literal).value)) === 'child_process'
        ) {
          execReceivers.add((d.id as acorn.Identifier).name);
        }
      }
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
        if (first && first.type !== 'Literal')
          add('evalDynamic', `${(callee as acorn.Identifier).name}(<expr>)`, node);
        return;
      }

      // process.env passed whole to a serialiser / enumerator / any call
      const isBareEnv = (a: acorn.Node | undefined): boolean =>
        !!a &&
        a.type === 'MemberExpression' &&
        objectName(a) === 'process' &&
        memberName(a) === 'env';
      if (call.arguments.some((a) => isBareEnv(a))) {
        const who =
          callee.type === 'MemberExpression'
            ? `${objectName(callee) ?? '?'}.${memberName(callee) ?? '?'}`
            : callee.type === 'Identifier'
              ? (callee as acorn.Identifier).name
              : 'call';
        add('envDump', `${who}(process.env)`, node);
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
        // String.fromCharCode(c) on one computed value is ordinary string handling
        // (escape parsing); feeding it a list of codes is decoding a payload.
        if (obj === 'String' && prop === 'fromCharCode') {
          const args = call.arguments;
          const spread = args.some((a) => a.type === 'SpreadElement');
          if (spread || args.length >= 4) add('decode', 'String.fromCharCode', node);
        }
        // String.fromCharCode.apply(null, codes) / .call(...)
        if (
          (prop === 'apply' || prop === 'call') &&
          (callee as acorn.MemberExpression).object.type === 'MemberExpression' &&
          objectName((callee as acorn.MemberExpression).object) === 'String' &&
          memberName((callee as acorn.MemberExpression).object) === 'fromCharCode'
        ) {
          add('decode', `String.fromCharCode.${prop}`, node);
        }
        // x.exec(...) / x.spawn(...) etc. on any object: covers modules loaded
        // through a computed require, where the module name is unknown.
        if (
          prop &&
          (EXEC_METHODS.has(prop) ||
            (prop === 'exec' && obj !== undefined && execReceivers.has(obj)))
        ) {
          add('exec', `${obj ?? ''}.${prop}()`, node);
          if (/^runIn/.test(prop) && first && first.type !== 'Literal')
            add('evalDynamic', `.${prop}(<expr>)`, node);
        }
        if (prop === 'chmod' || prop === 'chmodSync') add('chmodExec', `.${prop}()`, node);
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
      }
    },
    NewExpression(node) {
      const n = node as acorn.NewExpression;
      if (isIdentifier(n.callee, 'Function')) {
        add('exec', 'new Function', node);
        if (n.arguments.some((a) => a.type !== 'Literal'))
          add('evalDynamic', 'new Function(<expr>)', node);
      }
      if (isIdentifier(n.callee, 'XMLHttpRequest')) add('network', 'XMLHttpRequest', node);
      if (isIdentifier(n.callee, 'WebSocket')) add('network', 'WebSocket', node);
    },
    MemberExpression(node) {
      if (objectName(node) === 'process' && memberName(node) === 'env') {
        add('env', 'process.env', node);
      }
    },
    Property(node) {
      // { env: process.env } — the whole environment packed into an object
      const v = (node as acorn.Property).value;
      if (v.type === 'MemberExpression' && objectName(v) === 'process' && memberName(v) === 'env') {
        add('envDump', '{ …: process.env }', node);
      }
    },
    SpreadElement(node) {
      const arg = (node as acorn.SpreadElement).argument;
      if (
        arg.type === 'MemberExpression' &&
        objectName(arg) === 'process' &&
        memberName(arg) === 'env'
      ) {
        add('envDump', '{...process.env}', node);
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

  const distinctHostApis = new Set(
    report.hits
      .filter((h) => h.capability === 'hostInfo' && h.via.startsWith('os.'))
      .map((h) => h.via)
  );
  if (distinctHostApis.size >= 3) {
    report.capabilities.add('hostFingerprint');
    report.hits.push({
      capability: 'hostFingerprint',
      via: [...distinctHostApis].join('+'),
      line: 0,
    });
  }

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
    requires: ['envDump', 'network'],
    severity: 'HIGH',
    confidence: 0.8,
    message: 'Serialises the whole environment and has network access',
  },
  {
    type: 'DATA_EXFILTRATION',
    requires: ['hostFingerprint', 'network'],
    severity: 'HIGH',
    confidence: 0.75,
    message: 'Builds a host fingerprint from several OS APIs and has network access',
  },
  {
    type: 'DATA_EXFILTRATION',
    requires: ['hostInfo', 'envDump'],
    severity: 'MEDIUM',
    confidence: 0.6,
    message: 'Collects host information and serialises the environment',
  },
  {
    type: 'DATA_EXFILTRATION',
    requires: ['hostInfo', 'network', 'decode'],
    severity: 'MEDIUM',
    confidence: 0.6,
    message: 'Collects host information, encodes it and has network access',
  },
  {
    type: 'OBFUSCATED_EXECUTION',
    requires: ['decode', 'exec'],
    severity: 'HIGH',
    confidence: 0.8,
    message: 'Decodes data and executes code or processes',
  },
  {
    type: 'REMOTE_CODE_EXECUTION',
    requires: ['network', 'evalDynamic'],
    severity: 'HIGH',
    confidence: 0.85,
    message: 'Has network access and evaluates code from a non-literal source',
  },
  {
    type: 'REMOTE_CODE_EXECUTION',
    requires: ['network', 'chmodExec', 'exec'],
    severity: 'HIGH',
    confidence: 0.8,
    message: 'Has network access, marks a file executable and runs a process',
  },
  {
    type: 'REMOTE_CODE_EXECUTION',
    requires: ['network', 'exec', 'decode'],
    severity: 'HIGH',
    confidence: 0.8,
    message: 'Has network access, decodes data and executes code or processes',
  },
  {
    type: 'REMOTE_CODE_EXECUTION',
    requires: ['network', 'exec'],
    severity: 'MEDIUM',
    confidence: 0.6,
    message: 'Has network access and executes code or processes',
  },
  {
    type: 'DYNAMIC_MODULE_LOAD',
    requires: ['dynamicModule', 'network'],
    severity: 'HIGH',
    confidence: 0.7,
    message: 'Loads a module from a computed name and has network access',
  },
  {
    type: 'DYNAMIC_MODULE_LOAD',
    requires: ['dynamicModule'],
    severity: 'MEDIUM',
    confidence: 0.6,
    message: 'Loads modules from a computed name, hiding which module is used',
  },
];

/**
 * Combinations whose strength depends on what is absent. Evaluated after the
 * table above and may upgrade a result.
 */
function conditionalCombinations(caps: Set<Capability>): Combination[] {
  const out: Combination[] = [];
  // exec reached only through a computed module name: the author hid which
  // module executes things. A CLI that requires child_process by name and
  // also require()s plugins dynamically does not match.
  if (caps.has('dynamicModule') && caps.has('exec') && !caps.has('execNamed')) {
    out.push({
      type: 'DYNAMIC_MODULE_LOAD',
      requires: ['dynamicModule', 'exec'],
      severity: 'HIGH',
      confidence: 0.8,
      message: 'Executes processes through a module loaded from a computed name',
    });
  }
  return out;
}

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

  const emitted = new Set<string>();
  for (const combo of [...conditionalCombinations(report.capabilities), ...COMBINATIONS]) {
    if (!combo.requires.every((c) => report.capabilities.has(c))) continue;
    // COMBINATIONS lists the stronger variant of each type first; keep one per type.
    if (emitted.has(combo.type)) continue;
    emitted.add(combo.type);
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
