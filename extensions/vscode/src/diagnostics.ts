import * as vscode from 'vscode';
import { SecurityFinding, AnalysisResult } from './analysisService';

export class DiagnosticsManager {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('soliditydefend');
    }

    createDiagnostics(analysis: AnalysisResult, uri: vscode.Uri): vscode.Diagnostic[] {
        const diagnostics: vscode.Diagnostic[] = [];

        for (const finding of analysis.findings) {
            const diagnostic = this.createDiagnostic(finding);
            if (diagnostic) {
                diagnostics.push(diagnostic);
            }
        }

        return diagnostics;
    }

    private createDiagnostic(finding: SecurityFinding): vscode.Diagnostic | null {
        try {
            const startLine = Math.max(0, finding.line - 1);
            const startColumn = Math.max(0, finding.column);
            const endLine = finding.endLine ? Math.max(0, finding.endLine - 1) : startLine;
            const endColumn = finding.endColumn || startColumn + 10;

            const range = new vscode.Range(
                new vscode.Position(startLine, startColumn),
                new vscode.Position(endLine, endColumn)
            );

            const diagnostic = new vscode.Diagnostic(
                range,
                finding.description,
                this.getSeverityLevel(finding.severity)
            );

            diagnostic.source = 'SolidityDefend';
            diagnostic.code = {
                value: finding.detector,
                target: vscode.Uri.parse(`https://docs.soliditydefend.dev/detectors/${finding.detector}`)
            };

            // Add additional information
            if (finding.suggestedFix) {
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(vscode.Uri.file(finding.filePath), range),
                        `Suggested fix: ${finding.suggestedFix}`
                    )
                ];
            }

            // Add tags for categorization
            const tags: vscode.DiagnosticTag[] = [];
            if (finding.confidence < 0.5) {
                tags.push(vscode.DiagnosticTag.Unnecessary);
            }
            diagnostic.tags = tags;

            return diagnostic;

        } catch (error) {
            console.error('Error creating diagnostic:', error);
            return null;
        }
    }

    private getSeverityLevel(severity: SecurityFinding['severity']): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'Critical':
            case 'High':
                return vscode.DiagnosticSeverity.Error;
            case 'Medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'Low':
                return vscode.DiagnosticSeverity.Information;
            case 'Info':
                return vscode.DiagnosticSeverity.Hint;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    updateDiagnostics(uri: vscode.Uri, diagnostics: vscode.Diagnostic[]): void {
        this.diagnosticCollection.set(uri, diagnostics);
    }

    clear(): void {
        this.diagnosticCollection.clear();
    }

    clearFile(uri: vscode.Uri): void {
        this.diagnosticCollection.delete(uri);
    }

    getAllDiagnostics(): [vscode.Uri, vscode.Diagnostic[]][] {
        const result: [vscode.Uri, vscode.Diagnostic[]][] = [];
        this.diagnosticCollection.forEach((uri, diagnostics) => {
            result.push([uri, diagnostics]);
        });
        return result;
    }

    getDiagnosticsForFile(uri: vscode.Uri): vscode.Diagnostic[] {
        return this.diagnosticCollection.get(uri) || [];
    }

    getStatistics(): {
        totalFiles: number;
        totalDiagnostics: number;
        severityCounts: Record<string, number>;
    } {
        let totalFiles = 0;
        let totalDiagnostics = 0;
        const severityCounts: Record<string, number> = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        };

        this.diagnosticCollection.forEach((uri, diagnostics) => {
            totalFiles++;
            totalDiagnostics += diagnostics.length;

            diagnostics.forEach(diagnostic => {
                const severity = this.getDiagnosticSeverityName(diagnostic.severity);
                severityCounts[severity]++;
            });
        });

        return {
            totalFiles,
            totalDiagnostics,
            severityCounts
        };
    }

    private getDiagnosticSeverityName(severity: vscode.DiagnosticSeverity): string {
        switch (severity) {
            case vscode.DiagnosticSeverity.Error:
                return 'High';
            case vscode.DiagnosticSeverity.Warning:
                return 'Medium';
            case vscode.DiagnosticSeverity.Information:
                return 'Low';
            case vscode.DiagnosticSeverity.Hint:
                return 'Info';
            default:
                return 'Medium';
        }
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}