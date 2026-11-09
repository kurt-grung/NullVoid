'use strict';
const fs = require('fs');
const path = require('path');

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.md')) out.push(full);
  }
  return out;
}
function render(markdown) {
  return markdown
    .split('\n')
    .map((line) => (line.startsWith('# ') ? `<h1>${line.slice(2)}</h1>` : `<p>${line}</p>`))
    .join('\n');
}
function build(srcDir, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  for (const file of walk(srcDir)) {
    const rel = path.relative(srcDir, file).replace(/\.md$/, '.html');
    const target = path.join(outDir, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, render(fs.readFileSync(file, 'utf8')));
  }
}
module.exports = { build, render, walk };
