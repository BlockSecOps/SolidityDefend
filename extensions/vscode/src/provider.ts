import * as vscode from 'vscode';
import { AnalysisService, SecurityFinding } from './analysisService';
import { DiagnosticsManager } from './diagnostics';

export class SolidityDefendProvider implements
    vscode.HoverProvider,
    vscode.CompletionItemProvider {

    constructor(
        private analysisService: AnalysisService,
        private diagnosticsManager: DiagnosticsManager
    ) {}

    async provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): Promise<vscode.Hover | undefined> {
        if (document.languageId !== 'solidity') {
            return undefined;
        }

        const diagnostics = this.diagnosticsManager.getDiagnosticsForFile(document.uri);
        const relevantDiagnostic = diagnostics.find(diagnostic =>
            diagnostic.range.contains(position)
        );

        if (relevantDiagnostic) {
            const markdown = new vscode.MarkdownString();
            markdown.isTrusted = true;

            markdown.appendMarkdown(`**🛡️ SolidityDefend Security Issue**\n\n`);
            markdown.appendMarkdown(`**Severity:** ${this.getSeverityIcon(relevantDiagnostic.severity)} ${this.getSeverityName(relevantDiagnostic.severity)}\n\n`);
            markdown.appendMarkdown(`**Description:** ${relevantDiagnostic.message}\n\n`);

            if (relevantDiagnostic.code) {
                const codeValue = typeof relevantDiagnostic.code === 'string'
                    ? relevantDiagnostic.code
                    : relevantDiagnostic.code.value;
                markdown.appendMarkdown(`**Detector:** \`${codeValue}\`\n\n`);
            }

            if (relevantDiagnostic.relatedInformation) {
                for (const info of relevantDiagnostic.relatedInformation) {
                    if (info.message.startsWith('Suggested fix:')) {
                        markdown.appendMarkdown(`**💡 ${info.message}**\n\n`);
                    }
                }
            }

            markdown.appendMarkdown(`---\n`);
            markdown.appendMarkdown(`[View Documentation](https://docs.soliditydefend.dev) | [Quick Fix](command:soliditydefend.quickFix)`);

            return new vscode.Hover(markdown);
        }

        return undefined;
    }

    async provideCompletionItems(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken,
        context: vscode.CompletionContext
    ): Promise<vscode.CompletionItem[] | undefined> {
        if (document.languageId !== 'solidity') {
            return undefined;
        }

        const items: vscode.CompletionItem[] = [];

        // Add security-focused completion items
        items.push(...this.getSecurityPatternCompletions());
        items.push(...this.getSecureLibraryCompletions());

        return items;
    }

    private getSecurityPatternCompletions(): vscode.CompletionItem[] {
        const items: vscode.CompletionItem[] = [];

        // Reentrancy guard pattern
        const reentrancyGuard = new vscode.CompletionItem(
            'reentrancyGuard',
            vscode.CompletionItemKind.Snippet
        );
        reentrancyGuard.detail = 'Reentrancy Guard Pattern';
        reentrancyGuard.documentation = new vscode.MarkdownString(
            'Implements a reentrancy guard to prevent reentrancy attacks'
        );
        reentrancyGuard.insertText = new vscode.SnippetString(`bool private _locked;

modifier nonReentrant() {
    require(!_locked, "ReentrancyGuard: reentrant call");
    _locked = true;
    _;
    _locked = false;
}`);
        items.push(reentrancyGuard);

        // Access control pattern
        const accessControl = new vscode.CompletionItem(
            'onlyOwner',
            vscode.CompletionItemKind.Snippet
        );
        accessControl.detail = 'Access Control Pattern';
        accessControl.documentation = new vscode.MarkdownString(
            'Implements owner-only access control'
        );
        accessControl.insertText = new vscode.SnippetString(`address public owner;

modifier onlyOwner() {
    require(msg.sender == owner, "Ownable: caller is not the owner");
    _;
}

constructor() {
    owner = msg.sender;
}`);
        items.push(accessControl);

        // Safe math operations
        const safeMath = new vscode.CompletionItem(
            'safeAdd',
            vscode.CompletionItemKind.Snippet
        );
        safeMath.detail = 'Safe Math Addition';
        safeMath.documentation = new vscode.MarkdownString(
            'Safe addition operation that prevents overflow'
        );
        safeMath.insertText = new vscode.SnippetString(
            'require(${1:a} + ${2:b} >= ${1:a}, "SafeMath: addition overflow");'
        );
        items.push(safeMath);

        return items;
    }

    private getSecureLibraryCompletions(): vscode.CompletionItem[] {
        const items: vscode.CompletionItem[] = [];

        // OpenZeppelin imports
        const ozImports = [
            {
                label: 'ReentrancyGuard',
                import: '@openzeppelin/contracts/security/ReentrancyGuard.sol',
                description: 'Protection against reentrancy attacks'
            },
            {
                label: 'Ownable',
                import: '@openzeppelin/contracts/access/Ownable.sol',
                description: 'Basic ownership access control'
            },
            {
                label: 'Pausable',
                import: '@openzeppelin/contracts/security/Pausable.sol',
                description: 'Emergency pause functionality'
            },
            {
                label: 'SafeMath',
                import: '@openzeppelin/contracts/utils/math/SafeMath.sol',
                description: 'Safe mathematical operations'
            }
        ];

        for (const lib of ozImports) {
            const item = new vscode.CompletionItem(
                lib.label,
                vscode.CompletionItemKind.Module
            );
            item.detail = 'OpenZeppelin Security Library';
            item.documentation = new vscode.MarkdownString(lib.description);
            item.insertText = `import "${lib.import}";`;
            item.command = {
                command: 'editor.action.organizeImports',
                title: 'Organize Imports'
            };
            items.push(item);
        }

        return items;
    }

    private getSeverityIcon(severity: vscode.DiagnosticSeverity): string {
        switch (severity) {
            case vscode.DiagnosticSeverity.Error:
                return '🔴';
            case vscode.DiagnosticSeverity.Warning:
                return '🟡';
            case vscode.DiagnosticSeverity.Information:
                return '🔵';
            case vscode.DiagnosticSeverity.Hint:
                return '💡';
            default:
                return '⚠️';
        }
    }

    private getSeverityName(severity: vscode.DiagnosticSeverity): string {
        switch (severity) {
            case vscode.DiagnosticSeverity.Error:
                return 'Critical/High';
            case vscode.DiagnosticSeverity.Warning:
                return 'Medium';
            case vscode.DiagnosticSeverity.Information:
                return 'Low';
            case vscode.DiagnosticSeverity.Hint:
                return 'Info';
            default:
                return 'Unknown';
        }
    }
}