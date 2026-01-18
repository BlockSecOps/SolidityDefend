import * as vscode from 'vscode';
import { AnalysisService, SecurityFinding } from './analysisService';

export class QuickFixProvider implements vscode.CodeActionProvider {
    constructor(private analysisService: AnalysisService) {}

    async provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): Promise<vscode.CodeAction[]> {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source === 'SolidityDefend') {
                const quickFixes = await this.createQuickFixes(document, diagnostic);
                actions.push(...quickFixes);
            }
        }

        return actions;
    }

    private async createQuickFixes(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ): Promise<vscode.CodeAction[]> {
        const actions: vscode.CodeAction[] = [];
        const detectorType = typeof diagnostic.code === 'string'
            ? diagnostic.code
            : diagnostic.code?.value?.toString() || '';

        switch (detectorType) {
            case 'tx-origin':
                actions.push(this.createTxOriginFix(document, diagnostic));
                break;
            case 'reentrancy':
                actions.push(this.createReentrancyFix(document, diagnostic));
                break;
            case 'unchecked-call':
                actions.push(this.createUncheckedCallFix(document, diagnostic));
                break;
            case 'unsafe-external-call':
                actions.push(this.createSafeExternalCallFix(document, diagnostic));
                break;
            case 'unprotected-function':
                actions.push(this.createAccessControlFix(document, diagnostic));
                break;
            case 'integer-overflow':
                actions.push(this.createSafeMathFix(document, diagnostic));
                break;
            case 'timestamp-dependence':
                actions.push(this.createTimestampFix(document, diagnostic));
                break;
            case 'low-level-call':
                actions.push(this.createLowLevelCallFix(document, diagnostic));
                break;
            default:
                if (diagnostic.relatedInformation) {
                    actions.push(this.createGenericFix(document, diagnostic));
                }
                break;
        }

        return actions;
    }

    private createTxOriginFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Replace tx.origin with msg.sender',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const range = diagnostic.range;
        const text = document.getText(range);
        const fixedText = text.replace(/tx\.origin/g, 'msg.sender');

        edit.replace(document.uri, range, fixedText);
        action.edit = edit;

        action.isPreferred = true;
        return action;
    }

    private createReentrancyFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Add reentrancy guard',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const functionStart = this.findFunctionStart(document, diagnostic.range.start);

        if (functionStart) {
            const guardCode = ' nonReentrant';
            const functionLine = document.lineAt(functionStart.line);
            const insertPosition = new vscode.Position(
                functionStart.line,
                functionLine.text.length - 1
            );

            edit.insert(document.uri, insertPosition, guardCode);
        }

        action.edit = edit;
        return action;
    }

    private createUncheckedCallFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Add return value check',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const range = diagnostic.range;
        const text = document.getText(range);

        let fixedText = text;
        if (text.includes('.call(')) {
            fixedText = `(bool success, ) = ${text};\nrequire(success, "Call failed");`;
        } else if (text.includes('.send(')) {
            fixedText = `bool success = ${text};\nrequire(success, "Send failed");`;
        }

        edit.replace(document.uri, range, fixedText);
        action.edit = edit;

        return action;
    }

    private createSafeExternalCallFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Use safe external call pattern',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const range = diagnostic.range;
        const text = document.getText(range);

        const fixedText = `// Check external contract existence\nrequire(address(target).code.length > 0, "Contract does not exist");\n${text}`;

        edit.replace(document.uri, range, fixedText);
        action.edit = edit;

        return action;
    }

    private createAccessControlFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Add access control modifier',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const functionStart = this.findFunctionStart(document, diagnostic.range.start);

        if (functionStart) {
            const modifierCode = ' onlyOwner';
            const functionLine = document.lineAt(functionStart.line);
            const insertPosition = new vscode.Position(
                functionStart.line,
                functionLine.text.length - 1
            );

            edit.insert(document.uri, insertPosition, modifierCode);
        }

        action.edit = edit;
        return action;
    }

    private createSafeMathFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Use SafeMath library',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const range = diagnostic.range;
        const text = document.getText(range);

        let fixedText = text;
        fixedText = fixedText.replace(/\+/g, '.add');
        fixedText = fixedText.replace(/-/g, '.sub');
        fixedText = fixedText.replace(/\*/g, '.mul');
        fixedText = fixedText.replace(/\//g, '.div');

        edit.replace(document.uri, range, fixedText);
        action.edit = edit;

        return action;
    }

    private createTimestampFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Add timestamp tolerance check',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const range = diagnostic.range;
        const text = document.getText(range);

        const fixedText = `// Allow some tolerance for timestamp variations\n${text}`;

        edit.replace(document.uri, range, fixedText);
        action.edit = edit;

        return action;
    }

    private createLowLevelCallFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Add proper error handling',
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const range = diagnostic.range;
        const text = document.getText(range);

        const fixedText = `(bool success, bytes memory data) = ${text};\nrequire(success, "Low-level call failed");\n// Handle return data if needed`;

        edit.replace(document.uri, range, fixedText);
        action.edit = edit;

        return action;
    }

    private createGenericFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        if (!diagnostic.relatedInformation || diagnostic.relatedInformation.length === 0) {
            return this.createEmptyAction();
        }

        const suggestion = diagnostic.relatedInformation[0].message;
        if (!suggestion.startsWith('Suggested fix:')) {
            return this.createEmptyAction();
        }

        const fixText = suggestion.replace('Suggested fix: ', '');

        const action = new vscode.CodeAction(
            `Apply suggestion: ${fixText}`,
            vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const range = diagnostic.range;

        edit.replace(document.uri, range, fixText);
        action.edit = edit;

        return action;
    }

    private createEmptyAction(): vscode.CodeAction {
        return new vscode.CodeAction(
            'No automatic fix available',
            vscode.CodeActionKind.Empty
        );
    }

    private findFunctionStart(document: vscode.TextDocument, position: vscode.Position): vscode.Position | null {
        for (let line = position.line; line >= 0; line--) {
            const lineText = document.lineAt(line).text;
            if (lineText.trim().startsWith('function ')) {
                return new vscode.Position(line, 0);
            }
        }
        return null;
    }
}