# IDE Integration

Run NullVoid from IntelliJ, Sublime Text, and Vim using external tools or build systems. For the **VS Code extension** (recommended), see [packages/vscode-extension/README.md](../packages/vscode-extension/README.md).

---

## IntelliJ / WebStorm

### Option 1: External Tool

1. **File → Settings → Tools → External Tools** → **+** (Add).
2. **Name:** `NullVoid Security Scan`
3. **Program:** `npx` (or full path to `node`)
4. **Arguments:** `nullvoid . --output json` (or `node /path/to/nullvoid.js . --output json` if using local build)
5. **Working directory:** `$ProjectFileDir$`
6. Click **OK**.

Run from **Tools → External Tools → NullVoid Security Scan**, or assign a keymap under **Settings → Keymap**.

### Option 2: Run Configuration

1. **Run → Edit Configurations** → **+** → **Node.js**.
2. **Name:** `NullVoid Scan`
3. **Node interpreter:** your Node 18+ interpreter.
4. **Node parameters:** (leave empty)
5. **Working directory:** `$ProjectFileDir$`
6. **JavaScript file:** leave empty; use **Before launch** → **+** → **Run External tool** and add a step that runs `npx nullvoid .` (or use an npm script).

Alternatively, add an npm script in `package.json`: `"nullvoid": "nullvoid ."`, then use **Run → Edit Configurations → npm** and select the `nullvoid` script.

---

## Sublime Text

### Build system

1. **Tools → Build System → New Build System…**
2. Paste the following (adjust `cmd` if you use a local NullVoid build):

```json
{
  "shell_cmd": "npx nullvoid . --output json",
  "working_dir": "${folder:${project_path}}",
  "file_regex": "(.+):(\\d+):(\\d+): (.*)",
  "selector": "source.js, source.json"
}
```

3. Save as `NullVoid.sublime-build`.
4. Open a project folder, then **Tools → Build System → NullVoid** and press **Ctrl+B** (Windows/Linux) or **Cmd+B** (macOS) to run the scan. Output appears in the build panel.

---

## Vim / Neovim

### Command (one-off)

From the project root in the terminal:

```bash
npx nullvoid . --output json
```

Or from inside Vim, run the same in a terminal buffer (`:term`) or with `:!npx nullvoid . --output json`.

### Script: run NullVoid and show summary

Use the provided script [scripts/nullvoid-vim.sh](../scripts/nullvoid-vim.sh) (from the NullVoid repo root):

```bash
#!/usr/bin/env bash
# Run NullVoid and print a short summary (for use from Vim :! or terminal)
cd "${1:-.}" && npx nullvoid . --output json 2>/dev/null | node -e "
const d = require('fs').readFileSync(0,'utf8');
try {
  const j = JSON.parse(d);
  const n = (j.threats || []).length;
  console.log(n === 0 ? 'NullVoid: 0 issues' : 'NullVoid: ' + n + ' issue(s)');
  (j.threats || []).slice(0,5).forEach((t,i) => console.log((i+1) + '. ' + (t.type || '') + ' - ' + (t.message || '')));
} catch(e) { console.log('NullVoid: scan failed'); }
"
```

Run: `chmod +x scripts/nullvoid-vim.sh` then `./scripts/nullvoid-vim.sh` or `./scripts/nullvoid-vim.sh /path/to/project`. From Vim: `:!./scripts/nullvoid-vim.sh %:h`.

### Optional: keybinding in Neovim

In your `init.vim` or `init.lua`:

```lua
-- Run NullVoid from project root and show output in a split
vim.keymap.set('n', '<leader>nv', ':split term://npx nullvoid . --output json<CR>', { desc = 'NullVoid scan' })
```

---

## Summary

| IDE        | How to run NullVoid |
|-----------|----------------------|
| **VS Code** | Use the [NullVoid extension](packages/vscode-extension) (F5 + Command Palette). |
| **IntelliJ** | External Tool or Run Configuration (npm script or `npx nullvoid .`). |
| **Sublime** | Build system (e.g. `NullVoid.sublime-build`) with **Ctrl+B** / **Cmd+B**. |
| **Vim/Neovim** | `:!npx nullvoid .` or a shell script + optional keymap. |

All of these run the same CLI: `npx nullvoid .` (or `node path/to/nullvoid.js .` when using a local build). For SARIF output use `--sarif-file nullvoid-results.sarif`.
