import * as vscode from 'vscode';
import * as path from 'path';
import { spawn } from 'child_process';

const OUTPUT_CHANNEL_NAME = 'NullVoid';

export function activate(context: vscode.ExtensionContext): void {
  const disposable = vscode.commands.registerCommand('nullvoid.runScan', async () => {
    const channel = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
    channel.clear();
    channel.show();

    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    const cwd = workspaceFolder?.uri.fsPath ?? process.cwd();

    // Prefer local nullvoid (e.g. from repo root or node_modules)
    const root = path.resolve(context.extensionPath, '../..');
    const localBin = path.join(root, 'ts', 'dist', 'bin', 'nullvoid.js');
    const fs = await import('fs');
    const useLocal = fs.existsSync(localBin);

    const args = ['.', '--format', 'text'];
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
      if (code !== 0) {
        vscode.window.showWarningMessage(`NullVoid scan finished with code ${code}. See Output > ${OUTPUT_CHANNEL_NAME}.`);
      } else {
        vscode.window.showInformationMessage('NullVoid scan completed. See Output > NullVoid.');
      }
    });

    proc.on('error', (err) => {
      channel.appendLine(`Error: ${err.message}`);
      vscode.window.showErrorMessage(`NullVoid scan failed: ${err.message}`);
    });
  });

  context.subscriptions.push(disposable);
}

export function deactivate(): void {}
