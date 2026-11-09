#!/usr/bin/env node
'use strict';
const { execFileSync } = require('child_process');

function currentBranch(cwd = process.cwd()) {
  return execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd, encoding: 'utf8' }).trim();
}
function listBranches(cwd = process.cwd()) {
  return execFileSync('git', ['branch', '--format=%(refname:short)'], { cwd, encoding: 'utf8' })
    .split('\n')
    .filter(Boolean);
}
if (require.main === module) {
  const cmd = process.argv[2] || 'current';
  if (cmd === 'list') console.log(listBranches().join('\n'));
  else console.log(currentBranch());
}
module.exports = { currentBranch, listBranches };
