# NullVoid VS Code Extension

Run [NullVoid](https://github.com/kurt-grung/NullVoid) security scans from the editor with **Problems** panel integration and status bar summary.

## Features

- **NullVoid: Run Security Scan** — Runs a full scan in the workspace root, writes results to a temp file, then:
  - Shows scan output in the **Output** panel (channel: NullVoid).
  - Publishes findings to the **Problems** panel as diagnostics (file, line, severity, message).
  - Updates the **status bar** with a summary (e.g. `NullVoid: 0 issues` or `NullVoid: 3 issue(s)`).
- **Scan on folder open** (optional) — When enabled in settings, runs a scan automatically when you open a workspace folder, after a short delay.

## Setup

1. Build the extension:
   ```bash
   cd packages/vscode-extension
   npm install
   npm run compile
   ```

2. Run from the NullVoid repo (so the extension can use the local `ts/dist/bin/nullvoid.js`):
   - Open the NullVoid repo in VS Code.
   - Press F5 or use **Run > Start Debugging** (launches Extension Development Host).
   - In the new window, open a folder to scan, then run **NullVoid: Run Security Scan** from the Command Palette.

3. Or install NullVoid globally and use the extension from any workspace:
   ```bash
   npm install -g nullvoid
   ```
   The extension will use `npx nullvoid` when the local repo build is not found.

### Install from VSIX (Cursor / no marketplace)

If the extension isn’t in your editor’s marketplace (e.g. Cursor), you can install it from a built `.vsix`:

1. Build the `.vsix` from the extension folder:
   ```bash
   cd packages/vscode-extension
   npm run compile
   npx @vscode/vsce package --no-dependencies
   ```
2. In VS Code or Cursor: **Ctrl+Shift+P** / **Cmd+Shift+P** → **Extensions: Install from VSIX…** → choose the generated `.vsix` file (e.g. `nullvoid-vscode-0.1.0.vsix`).

   Or use the package script: `npm run package` (builds and runs `vsce package`).

### Publish to marketplace

To publish the extension to the **VS Code Marketplace** or **Open VSX**:

1. **Package:** From `packages/vscode-extension` run `npm run package` to produce a `.vsix`.

2. **VS Code Marketplace (Visual Studio Code):**
   - Create a [Personal Access Token (PAT)](https://dev.azure.com) in Azure DevOps with **Marketplace: Manage**.
   - Create a publisher (e.g. `nullvoid`) at [marketplace.visualstudio.com](https://marketplace.visualstudio.com/manage) or via `vsce create-publisher <publisher>`.
   - Run: `npx @vscode/vsce publish -p <PAT>` (or set `VSCE_PAT` and run `npx @vscode/vsce publish`).

3. **Open VSX (VS Codium, Eclipse Theia, etc.):**
   - Create an account at [open-vsx.org](https://open-vsx.org) (linked to GitHub).
   - Create a token at [open-vsx.org/user-settings/tokens](https://open-vsx.org/user-settings/tokens).
   - Install the Open VSX CLI: `npm i -g ovsx`, then run: `ovsx publish --pat <token>`.

4. **Bump version** in `package.json` before each publish.

## Usage

- **Command Palette** (Ctrl+Shift+P / Cmd+Shift+P): run **NullVoid: Run Security Scan**.
- Output appears in **View > Output**, then select **NullVoid** in the dropdown.

### Settings

| Setting | Default | Description |
|--------|---------|-------------|
| `nullvoid.scanOnFolderOpen` | `false` | Run a security scan when a workspace folder is opened. |
| `nullvoid.scanOnFolderOpenDelay` | `2` | Delay in seconds before the auto-scan runs (only when scan on folder open is enabled). |

## License

Same as NullVoid (MIT).
