import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { spawn } from 'child_process';
import * as os from 'os';

const OUTPUT_CHANNEL_NAME = 'NullVoid';
const DIAGNOSTIC_SOURCE = 'NullVoid';

interface Threat {
  type: string;
  message: string;
  package?: string;
  filePath?: string;
  filename?: string;
  severity: string;
  details?: string;
  lineNumber?: number;
  [key: string]: unknown;
}

interface ScanResult {
  threats: Threat[];
  [key: string]: unknown;
}

function severityToDiagnosticSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return vscode.DiagnosticSeverity.Error;
    case 'MEDIUM':
      return vscode.DiagnosticSeverity.Warning;
    case 'LOW':
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function threatsToDiagnostics(
  threats: Threat[],
  workspaceRoot: string
): Map<string, vscode.Diagnostic[]> {
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const threat of threats) {
    const filePath = threat.filePath ?? threat.package ?? 'package.json';
    let cleanPath = String(filePath).replace(/^\s*[📁📦]\s*/, '').replace(/\x1b\[[0-9;]*m/g, '');
    if (!path.isAbsolute(cleanPath)) {
      cleanPath = path.join(workspaceRoot, cleanPath);
    }
    const line = Math.max(1, threat.lineNumber ?? 1);
    const range = new vscode.Range(line - 1, 0, line - 1, 999);
    const message = threat.details ? `${threat.message} — ${threat.details}` : threat.message;
    const diag = new vscode.Diagnostic(range, message, severityToDiagnosticSeverity(threat.severity));
    diag.source = DIAGNOSTIC_SOURCE;
    diag.code = threat.type;

    const uri = vscode.Uri.file(cleanPath);
    const key = uri.toString();
    if (!byFile.has(key)) byFile.set(key, []);
    byFile.get(key)!.push(diag);
  }

  return byFile;
}

function runScan(
  context: vscode.ExtensionContext,
  channel: vscode.OutputChannel,
  diagnosticCollection: vscode.DiagnosticCollection,
  statusBarItem: vscode.StatusBarItem
): Promise<ScanResult | null> {
  return new Promise((resolve) => {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    const cwd = workspaceFolder?.uri.fsPath ?? process.cwd();

    const root = path.resolve(context.extensionPath, '..', '..');
    const localBin = path.join(root, 'ts', 'dist', 'bin', 'nullvoid.js');
    const useLocal = fs.existsSync(localBin);

    const tempFile = path.join(os.tmpdir(), `nullvoid-scan-${Date.now()}.json`);
    const args = ['.', '--output', tempFile];
    const cmd = useLocal ? 'node' : 'npx';
    const cmdArgs = useLocal ? [localBin, ...args] : ['nullvoid', ...args];

    channel.appendLine(`Running: ${cmd} ${cmdArgs.join(' ')} (cwd: ${cwd})\n`);

    const proc = spawn(cmd, cmdArgs, {
      cwd,
      shell: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    proc.stdout?.on('data', (data: Buffer) => channel.append(data.toString()));
    proc.stderr?.on('data', (data: Buffer) => channel.append(data.toString()));

    proc.on('close', (code) => {
      channel.appendLine(`\nExit code: ${code ?? 'unknown'}`);
      if (code !== 0 && code !== null) {
        vscode.window.showWarningMessage(
          `NullVoid scan finished with code ${code}. See Output > ${OUTPUT_CHANNEL_NAME}.`
        );
      }

      let result: ScanResult | null = null;
      try {
        if (fs.existsSync(tempFile)) {
          const raw = fs.readFileSync(tempFile, 'utf8');
          result = JSON.parse(raw) as ScanResult;
          if (result?.threats && Array.isArray(result.threats)) {
            diagnosticCollection.clear();
            const byFile = threatsToDiagnostics(result.threats, cwd);
            for (const [uriStr, diagnostics] of byFile) {
              diagnosticCollection.set(vscode.Uri.parse(uriStr), diagnostics);
            }
            const count = result.threats.length;
            statusBarItem.text = count === 0
              ? '$(shield) NullVoid: 0 issues'
              : `$(warning) NullVoid: ${count} issue(s)`;
            statusBarItem.tooltip = count === 0
              ? 'No security issues found'
              : `${count} security issue(s) found. Run NullVoid: Run Security Scan for details.`;
            statusBarItem.show();
          }
        }
      } catch (e) {
        channel.appendLine(`Failed to read results: ${e}`);
      } finally {
        try {
          fs.unlinkSync(tempFile);
        } catch {
          /* ignore */
        }
      }
      resolve(result);
    });

    proc.on('error', (err) => {
      channel.appendLine(`Error: ${err.message}`);
      vscode.window.showErrorMessage(`NullVoid scan failed: ${err.message}`);
      resolve(null);
    });
  });
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
  context.subscriptions.push(diagnosticCollection);

  const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  context.subscriptions.push(statusBarItem);

  const runScanDisposable = vscode.commands.registerCommand('nullvoid.runScan', async () => {
    const channel = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
    channel.clear();
    channel.show();
    statusBarItem.text = '$(sync~spin) NullVoid scanning…';
    statusBarItem.show();

    await runScan(context, channel, diagnosticCollection, statusBarItem);

    vscode.window.showInformationMessage(
      'NullVoid scan completed. See Output and Problems panel.'
    );
  });

  context.subscriptions.push(runScanDisposable);
}

export function deactivate(): void {}
