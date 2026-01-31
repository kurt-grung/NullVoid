# NullVoid VS Code Extension

Run [NullVoid](https://github.com/kurt-grung/NullVoid) security scans from the editor with **Problems** panel integration and status bar summary.

## Features

- **NullVoid: Run Security Scan** — Runs a full scan in the workspace root, writes results to a temp file, then:
  - Shows scan output in the **Output** panel (channel: NullVoid).
  - Publishes findings to the **Problems** panel as diagnostics (file, line, severity, message).
  - Updates the **status bar** with a summary (e.g. `NullVoid: 0 issues` or `NullVoid: 3 issue(s)`).

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

## Usage

- **Command Palette** (Ctrl+Shift+P / Cmd+Shift+P): run **NullVoid: Run Security Scan**.
- Output appears in **View > Output**, then select **NullVoid** in the dropdown.

## License

Same as NullVoid (MIT).
