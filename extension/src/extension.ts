import * as vscode from "vscode";
import { AgentShieldEngine } from "../src/engine.js";
import { ComplianceEngine } from "../src/compliance.js";

let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  const engine = new AgentShieldEngine();

  // Create status bar indicator
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBarItem.command = "agentshield.scanWorkspace";
  statusBarItem.text = "$(shield) AgentShield: Active";
  statusBarItem.tooltip = "AgentShield Zero-Leak Guard is actively protecting your workspace.";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Command: Scan Current Workspace
  const scanCmd = vscode.commands.registerCommand(
    "agentshield.scanWorkspace",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage("🛡️ AgentShield: No active document open.");
        return;
      }

      const text = editor.document.getText();
      const result = engine.scanAndRedact(text);

      if (!result.hasSecrets) {
        vscode.window.showInformationMessage("✅ AgentShield: Active file is clean! 0 secrets exposed.");
        statusBarItem.text = "$(shield) AgentShield: Clean";
      } else {
        statusBarItem.text = `$(alert) AgentShield: ${result.totalFound} Exposed!`;
        vscode.window.showWarningMessage(
          `🚨 AgentShield: Detected ${result.totalFound} exposed credential(s) in active file!`
        );
      }
    }
  );

  // Command: Redact Active Document
  const redactCmd = vscode.commands.registerCommand(
    "agentshield.redactActiveFile",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;

      const text = editor.document.getText();
      const result = engine.scanAndRedact(text);

      if (!result.hasSecrets) {
        vscode.window.showInformationMessage("✅ AgentShield: No secrets found to redact.");
        return;
      }

      const fullRange = new vscode.Range(
        editor.document.positionAt(0),
        editor.document.positionAt(text.length)
      );

      await editor.edit((editBuilder) => {
        editBuilder.replace(fullRange, result.sanitizedText);
      });

      vscode.window.showInformationMessage(
        `🛡️ AgentShield: Redacted ${result.totalFound} exposed secret(s) with secure tokens.`
      );
    }
  );

  // Command: Compliance Audit
  const complianceCmd = vscode.commands.registerCommand(
    "agentshield.auditCompliance",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;

      const text = editor.document.getText();
      const scan = engine.scanAndRedact(text);
      const report = ComplianceEngine.evaluate(scan.findings);

      const msg = `📋 Compliance: ${report.status} (${report.score}%). Violations: ${report.summary.totalViolations}`;
      if (report.status === "COMPLIANT") {
        vscode.window.showInformationMessage(msg);
      } else {
        vscode.window.showErrorMessage(msg);
      }
    }
  );

  // Auto-scan on file save
  const onSave = vscode.workspace.onDidSaveTextDocument((doc) => {
    const config = vscode.workspace.getConfiguration("agentshield");
    if (!config.get("autoScanOnSave")) return;

    const result = engine.scanAndRedact(doc.getText());
    if (result.hasSecrets) {
      vscode.window.showWarningMessage(
        `🚨 AgentShield: Guarded file '${doc.fileName}' contains ${result.totalFound} unmasked secret(s)!`
      );
    }
  });

  context.subscriptions.push(scanCmd, redactCmd, complianceCmd, onSave);
}

export function deactivate() {
  if (statusBarItem) {
    statusBarItem.dispose();
  }
}
