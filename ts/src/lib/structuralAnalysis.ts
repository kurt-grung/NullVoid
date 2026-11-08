/**
 * Structural analysis
 *
 * AST-derived signals that a file is obfuscated or has had code appended to
 * it. Replaces the text heuristics in detection.ts (hex-array regex, variable
 * mangling regex, module.exports regex) for files acorn can parse; those
 * heuristics remain as the fallback when parsing fails.
 *
 * Strong signals (any one marks the file):
 *   - obfuscatorIdentifiers : three or more distinct `_0x…` identifiers
 *   - hexEscapeStringArray  : an array of string literals written mostly as \x / \u escapes
 *   - stringArrayRotator    : the javascript-obfuscator `arr.push(arr.shift())` loop
 *   - charCodeArrayDecode   : an array of 16+ small integers in a file that also decodes
 *                             (String.fromCharCode / atob / Buffer.from base64)
 *   - codeAfterExports      : top-level statements after `module.exports = …` that are
 *                             not further exports (the event-stream / appended-payload shape)
 * Weak signals (two mark the file; one adds nothing):
 *   - singleLetterIdentifiers : > 60% of identifier uses are one letter, over 20+ identifiers,
 *                               in a file that is not minified onto a few lines
 *   - highEntropyStrings      : string literals of 40+ chars with Shannon entropy > 4.8
 *
 * Minification (very long lines) is recorded as context, never as a signal.
 */

import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

export type StructuralSignal =
  | 'obfuscatorIdentifiers'
  | 'hexEscapeStringArray'
  | 'stringArrayRotator'
  | 'charCodeArrayDecode'
  | 'codeAfterExports'
  | 'singleLetterIdentifiers'
  | 'highEntropyStrings';

const STRONG: ReadonlySet<StructuralSignal> = new Set([
  'obfuscatorIdentifiers',
  'hexEscapeStringArray',
  'stringArrayRotator',
  'charCodeArrayDecode',
  'codeAfterExports',
]);

export interface StructuralHit {
  signal: StructuralSignal;
  line: number;
  sample: string;
  detail: string;
}

export interface StructuralReport {
  parsed: boolean;
  minified: boolean;
  hits: StructuralHit[];
  strong: number;
  weak: number;
  /** strong >= 1 or weak >= 2 */
  flagged: boolean;
}

const OBFUSCATOR_ID = /^_0x[0-9a-fA-F]{3,}$/;

function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of text) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / text.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function lineOf(node: acorn.Node): number {
  return node.loc?.start.line ?? 0;
}

function sampleOf(code: string, node: acorn.Node, max = 80): string {
  const s = code.slice(node.start, Math.min(node.end, node.start + max));
  return s.replace(/\s+/g, ' ') + (node.end - node.start > max ? '…' : '');
}

function parse(code: string): acorn.Program | undefined {
  const base = {
    ecmaVersion: 'latest' as const,
    allowHashBang: true,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    locations: true,
    ranges: true,
  };
  try {
    return acorn.parse(code, { ...base, sourceType: 'module', allowImportExportEverywhere: true });
  } catch {
    try {
      return acorn.parse(code, { ...base, sourceType: 'script' });
    } catch {
      return undefined;
    }
  }
}

export function analyzeStructure(code: string): StructuralReport {
  const report: StructuralReport = {
    parsed: false,
    minified: false,
    hits: [],
    strong: 0,
    weak: 0,
    flagged: false,
  };

  const lines = code.split('\n');
  const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
  report.minified = longest > 500 && lines.length < code.length / 200;

  const ast = parse(code);
  if (!ast) return report;
  report.parsed = true;

  const hit = (signal: StructuralSignal, node: acorn.Node, detail: string): void => {
    report.hits.push({ signal, line: lineOf(node), sample: sampleOf(code, node), detail });
  };

  // --- identifier statistics
  const obfuscatorNames = new Map<string, acorn.Node>();
  let identifierUses = 0;
  let singleLetterUses = 0;
  let decodes = false;

  // --- arrays
  const hexEscapeArrays: acorn.Node[] = [];
  const charCodeArrays: acorn.Node[] = [];

  // --- string-array rotator: x.push(x.shift())
  const rotators: acorn.Node[] = [];

  // --- high-entropy strings
  const entropyStrings: acorn.Node[] = [];

  // walk.simple skips identifiers in binding positions (declarations, params);
  // walk.full visits every node, which is what identifier statistics need.
  walk.full(ast, (node) => {
    if (node.type !== 'Identifier') return;
    const name = (node as acorn.Identifier).name;
    identifierUses += 1;
    if (name.length === 1) singleLetterUses += 1;
    if (OBFUSCATOR_ID.test(name) && !obfuscatorNames.has(name)) obfuscatorNames.set(name, node);
  });

  walk.simple(ast, {
    ArrayExpression(node) {
      const els = (node as acorn.ArrayExpression).elements;
      if (els.length < 3) return;
      let strings = 0;
      let escaped = 0;
      let smallInts = 0;
      for (const el of els) {
        if (!el || el.type !== 'Literal') continue;
        const lit = el as acorn.Literal;
        if (typeof lit.value === 'string') {
          strings += 1;
          const raw = lit.raw ?? '';
          const escapes = (raw.match(/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g) ?? []).length;
          // an escape is 4 or 6 raw chars; "mostly escapes" = escapes cover > 60% of the literal
          if (escapes > 0 && escapes * 4 > raw.length * 0.6) escaped += 1;
        } else if (
          typeof lit.value === 'number' &&
          Number.isInteger(lit.value) &&
          lit.value >= 0 &&
          lit.value < 256
        ) {
          smallInts += 1;
        }
      }
      if (strings >= 3 && escaped >= Math.max(3, Math.ceil(strings * 0.6)))
        hexEscapeArrays.push(node);
      if (smallInts >= 16 && smallInts === els.length) charCodeArrays.push(node);
    },
    CallExpression(node) {
      const call = node as acorn.CallExpression;
      const callee = call.callee;
      if (callee.type === 'MemberExpression') {
        const m = callee as acorn.MemberExpression;
        const prop =
          m.property.type === 'Identifier' ? (m.property as acorn.Identifier).name : undefined;
        // arr.push(arr.shift())
        if (prop === 'push' && call.arguments.length === 1) {
          const arg = call.arguments[0];
          if (
            arg &&
            arg.type === 'CallExpression' &&
            (arg as acorn.CallExpression).callee.type === 'MemberExpression'
          ) {
            const inner = (arg as acorn.CallExpression).callee as acorn.MemberExpression;
            const innerProp =
              inner.property.type === 'Identifier'
                ? (inner.property as acorn.Identifier).name
                : undefined;
            if (innerProp === 'shift' && sameObject(m.object, inner.object)) rotators.push(node);
          }
        }
        const obj =
          m.object.type === 'Identifier' ? (m.object as acorn.Identifier).name : undefined;
        if (obj === 'String' && prop === 'fromCharCode') decodes = true;
        // String.fromCharCode.apply(null, codes) / .call(...)
        if ((prop === 'apply' || prop === 'call') && m.object.type === 'MemberExpression') {
          const inner = m.object as acorn.MemberExpression;
          const io =
            inner.object.type === 'Identifier'
              ? (inner.object as acorn.Identifier).name
              : undefined;
          const ip =
            inner.property.type === 'Identifier'
              ? (inner.property as acorn.Identifier).name
              : undefined;
          if (io === 'String' && ip === 'fromCharCode') decodes = true;
        }
        if (obj === 'Buffer' && prop === 'from') {
          const enc = call.arguments[1];
          if (
            enc &&
            enc.type === 'Literal' &&
            /^(base64|hex)$/i.test(String((enc as acorn.Literal).value))
          )
            decodes = true;
        }
      } else if (callee.type === 'Identifier' && (callee as acorn.Identifier).name === 'atob') {
        decodes = true;
      }
    },
    Literal(node) {
      const v = (node as acorn.Literal).value;
      if (typeof v !== 'string' || v.length < 40) return;
      // skip things that are obviously URLs / paths / base64 data URIs with structure
      if (/^(https?:|\/|\.\/|data:)/.test(v)) return;
      if (shannonEntropy(v) > 4.8) entropyStrings.push(node);
    },
  });

  // --- code executed after module.exports at top level.
  // Declarations, requires and `X.prototype.y = …` after the export line are
  // ordinary CommonJS style. What marks an appended payload is top-level
  // *execution* after the export: a bare call, an IIFE, a try block wrapping
  // one, or a `new` expression whose result is discarded.
  const body = ast.body;
  const declared = new Set<string>();
  for (const st of body) {
    if (st.type === 'FunctionDeclaration' || st.type === 'ClassDeclaration') {
      const id = (st as acorn.FunctionDeclaration | acorn.ClassDeclaration).id;
      if (id) declared.add(id.name);
    } else if (st.type === 'VariableDeclaration') {
      for (const d of (st as acorn.VariableDeclaration).declarations) {
        if (d.id.type === 'Identifier') declared.add((d.id as acorn.Identifier).name);
      }
    }
  }
  let exportsIndex = -1;
  for (let i = 0; i < body.length; i++) {
    const st = body[i];
    if (st && isModuleExportsAssignment(st)) exportsIndex = i;
  }
  if (exportsIndex >= 0) {
    const executing = body
      .slice(exportsIndex + 1)
      .filter((st) => isTopLevelExecution(st, declared));
    if (executing.length > 0) {
      const first = executing[0] as acorn.Node;
      hit(
        'codeAfterExports',
        first,
        `${executing.length} executing statement(s) after module.exports`
      );
    }
  }

  // --- assemble
  if (obfuscatorNames.size >= 3) {
    const first = [...obfuscatorNames.values()][0] as acorn.Node;
    hit('obfuscatorIdentifiers', first, `${obfuscatorNames.size} distinct _0x identifiers`);
  }
  for (const n of hexEscapeArrays)
    hit('hexEscapeStringArray', n, 'array of \\x/\\u escaped string literals');
  for (const n of rotators) hit('stringArrayRotator', n, 'arr.push(arr.shift()) rotation loop');
  if (decodes)
    for (const n of charCodeArrays)
      hit('charCodeArrayDecode', n, 'byte array in a file that decodes strings');

  if (!report.minified && identifierUses >= 20 && singleLetterUses / identifierUses > 0.6) {
    hit(
      'singleLetterIdentifiers',
      ast,
      `${Math.round((100 * singleLetterUses) / identifierUses)}% of ${identifierUses} identifiers are one letter`
    );
  }
  if (entropyStrings.length > 0) {
    hit(
      'highEntropyStrings',
      entropyStrings[0] as acorn.Node,
      `${entropyStrings.length} string literal(s) with entropy > 4.8`
    );
  }

  for (const h of report.hits) {
    if (STRONG.has(h.signal)) report.strong += 1;
    else report.weak += 1;
  }
  report.flagged = report.strong >= 1 || report.weak >= 2;
  return report;
}

function sameObject(a: acorn.Node, b: acorn.Node): boolean {
  if (a.type !== b.type) return false;
  if (a.type === 'Identifier') return (a as acorn.Identifier).name === (b as acorn.Identifier).name;
  if (a.type === 'MemberExpression') {
    const x = a as acorn.MemberExpression;
    const y = b as acorn.MemberExpression;
    return sameObject(x.object, y.object) && sameObject(x.property, y.property);
  }
  return false;
}

function isModuleExportsAssignment(st: acorn.Statement | acorn.ModuleDeclaration): boolean {
  if (st.type !== 'ExpressionStatement') return false;
  const e = (st as acorn.ExpressionStatement).expression;
  if (e.type !== 'AssignmentExpression') return false;
  const left = (e as acorn.AssignmentExpression).left;
  if (left.type !== 'MemberExpression') return false;
  const m = left as acorn.MemberExpression;
  return (
    m.object.type === 'Identifier' &&
    (m.object as acorn.Identifier).name === 'module' &&
    m.property.type === 'Identifier' &&
    (m.property as acorn.Identifier).name === 'exports'
  );
}

/**
 * A top-level statement that runs code rather than declaring it. Bare calls to
 * well-known module-wiring functions (Object.defineProperty(exports…),
 * require('x') assigned nowhere is still a call and counts) are execution,
 * but exports wiring is exempt.
 */
function isTopLevelExecution(
  st: acorn.Statement | acorn.ModuleDeclaration,
  declared: ReadonlySet<string>
): boolean {
  if (st.type === 'TryStatement') {
    const block = (st as acorn.TryStatement).block;
    return block.body.some((inner) => isTopLevelExecution(inner, declared));
  }
  if (st.type !== 'ExpressionStatement') return false;
  const e = (st as acorn.ExpressionStatement).expression;
  if (e.type === 'CallExpression' || e.type === 'AwaitExpression' || e.type === 'NewExpression') {
    const call = e.type === 'AwaitExpression' ? (e as acorn.AwaitExpression).argument : e;
    if (call.type !== 'CallExpression') return e.type === 'NewExpression';
    const c = (call as acorn.CallExpression).callee;
    // Object.defineProperty(exports, …) / Object.assign(module.exports, …) are wiring
    if (c.type === 'MemberExpression') {
      const m = c as acorn.MemberExpression;
      const obj = m.object.type === 'Identifier' ? (m.object as acorn.Identifier).name : '';
      if (obj === 'Object') {
        const first = (call as acorn.CallExpression).arguments[0];
        const target =
          first && first.type === 'MemberExpression'
            ? rootName(first as acorn.MemberExpression)
            : first && first.type === 'Identifier'
              ? (first as acorn.Identifier).name
              : '';
        if (target === 'module' || target === 'exports') return false;
      }
      // exports.x.y(...) style wiring / module.exports.init() patterns
      if (rootName(m) === 'module' || rootName(m) === 'exports') return false;
    }
    // Class wiring such as inherits(Hook, Runnable), Object.defineProperty(X.prototype, …)
    // or methods.forEach(m => X.prototype[m] = …) references names declared in this
    // file. An appended payload does not: it is an IIFE or a call on literals /
    // require() results / globals.
    const callee = c;
    const args = (call as acorn.CallExpression).arguments;
    const refsLocal = (n: acorn.Node): boolean => {
      let found = false;
      walk.full(n, (node) => {
        if (!found && node.type === 'Identifier' && declared.has((node as acorn.Identifier).name))
          found = true;
      });
      return found;
    };
    if (callee.type !== 'FunctionExpression' && callee.type !== 'ArrowFunctionExpression') {
      if (args.some((a) => refsLocal(a))) return false;
      if (
        callee.type === 'MemberExpression' &&
        refsLocal((callee as acorn.MemberExpression).object)
      )
        return false;
    }
    return true;
  }
  return false;
}

function rootName(m: acorn.MemberExpression): string | undefined {
  let cur: acorn.Node = m;
  while (cur.type === 'MemberExpression') cur = (cur as acorn.MemberExpression).object;
  return cur.type === 'Identifier' ? (cur as acorn.Identifier).name : undefined;
}
