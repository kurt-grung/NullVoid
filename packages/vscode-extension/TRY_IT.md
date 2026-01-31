# Try the NullVoid VS Code Extension

## 1. Build

```bash
cd packages/vscode-extension
npm install
npm run compile
```

## 2. Launch Extension Development Host

1. Open the **NullVoid** repo in VS Code (or Cursor).
2. Open the `packages/vscode-extension` folder in the same workspace (or have the repo root open).
3. Press **F5** (or **Run > Start Debugging**).
4. A new window opens — this is the Extension Development Host with the NullVoid extension loaded.

## 3. Try "Run Security Scan"

1. In the **new window**, open a folder (e.g. **File > Open Folder** → choose the NullVoid repo or any project with a `package.json`).
2. **Ctrl+Shift+P** (or **Cmd+Shift+P**) → type **NullVoid: Run Security Scan** → Enter.
3. Check:
   - **Output** panel → select **NullVoid** in the dropdown (scan log).
   - **Problems** panel → diagnostics from the scan.
   - **Status bar** (bottom right) → e.g. `NullVoid: 0 issues` or `NullVoid: N issue(s)`.

## 4. Try "Scan on folder open"

1. In the **new window**, open **Settings** (Ctrl+, / Cmd+,).
2. Search for **NullVoid**.
3. Turn on **NullVoid: Scan On Folder Open**.
4. Set **NullVoid: Scan On Folder Open Delay** to **1** (second) if you want a quick test.
5. **File > Close Folder** (or close the workspace).
6. **File > Open Folder** → open the NullVoid repo (or any folder with `package.json`).
7. After 1–2 seconds, a scan should run automatically:
   - Status bar shows **NullVoid scanning…** then the result.
   - **Output > NullVoid** shows `[Auto] Scanning workspace (scan on folder open).`
   - **Problems** and status bar update with results.

## 5. Turn off auto-scan

In Settings, turn off **NullVoid: Scan On Folder Open** so the extension only runs when you use the command.
