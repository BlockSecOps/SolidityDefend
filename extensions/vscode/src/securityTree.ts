import * as vscode from 'vscode';
import { SecurityFinding } from './analysisService';

export class SecurityTreeProvider implements vscode.TreeDataProvider<SecurityTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<SecurityTreeItem | undefined | null | void> = new vscode.EventEmitter<SecurityTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<SecurityTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private findings: SecurityFinding[] = [];

    constructor() {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    updateFindings(findings: SecurityFinding[]): void {
        this.findings = findings;
        this.refresh();

        // Set context for showing/hiding the view
        vscode.commands.executeCommand('setContext', 'soliditydefend.hasFindings', findings.length > 0);
    }

    clear(): void {
        this.findings = [];
        this.refresh();
        vscode.commands.executeCommand('setContext', 'soliditydefend.hasFindings', false);
    }

    getAllFindings(): SecurityFinding[] {
        return this.findings;
    }

    getTreeItem(element: SecurityTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: SecurityTreeItem): Thenable<SecurityTreeItem[]> {
        if (!element) {
            return Promise.resolve(this.getRootItems());
        }

        switch (element.contextValue) {
            case 'severityGroup':
                return Promise.resolve(this.getFindingsBySeverity(element.severity!));
            case 'fileGroup':
                return Promise.resolve(this.getFindingsByFile(element.filePath!));
            default:
                return Promise.resolve([]);
        }
    }

    private getRootItems(): SecurityTreeItem[] {
        if (this.findings.length === 0) {
            return [new SecurityTreeItem(
                'No security issues found',
                vscode.TreeItemCollapsibleState.None,
                'noIssues'
            )];
        }

        const items: SecurityTreeItem[] = [];

        // Group by severity
        const severityGroups = this.groupBySeverity();
        for (const [severity, count] of severityGroups) {
            const item = new SecurityTreeItem(
                `${severity} (${count})`,
                vscode.TreeItemCollapsibleState.Expanded,
                'severityGroup'
            );
            item.severity = severity;
            item.iconPath = this.getSeverityIcon(severity);
            items.push(item);
        }

        // Add summary item
        const summaryItem = new SecurityTreeItem(
            `Total: ${this.findings.length} issues`,
            vscode.TreeItemCollapsibleState.None,
            'summary'
        );
        summaryItem.iconPath = new vscode.ThemeIcon('info');
        items.unshift(summaryItem);

        return items;
    }

    private getFindingsBySeverity(severity: string): SecurityTreeItem[] {
        const findings = this.findings.filter(f => f.severity === severity);
        return findings.map(finding => this.createFindingItem(finding));
    }

    private getFindingsByFile(filePath: string): SecurityTreeItem[] {
        const findings = this.findings.filter(f => f.filePath === filePath);
        return findings.map(finding => this.createFindingItem(finding));
    }

    private createFindingItem(finding: SecurityFinding): SecurityTreeItem {
        const item = new SecurityTreeItem(
            finding.title,
            vscode.TreeItemCollapsibleState.None,
            'finding'
        );

        item.description = `Line ${finding.line}`;
        item.tooltip = new vscode.MarkdownString(`
**${finding.title}**

**Detector:** ${finding.detector}
**Severity:** ${finding.severity}
**File:** ${finding.filePath}
**Line:** ${finding.line}
**Confidence:** ${Math.round(finding.confidence * 100)}%

${finding.description}

${finding.suggestedFix ? `**Suggested Fix:** ${finding.suggestedFix}` : ''}
        `);

        item.iconPath = this.getSeverityIcon(finding.severity);

        item.command = {
            command: 'vscode.open',
            title: 'Open File',
            arguments: [
                vscode.Uri.file(finding.filePath),
                {
                    selection: new vscode.Range(
                        new vscode.Position(finding.line - 1, finding.column),
                        new vscode.Position(finding.endLine ? finding.endLine - 1 : finding.line - 1, finding.endColumn || finding.column + 10)
                    )
                }
            ]
        };

        item.contextValue = 'finding';
        item.finding = finding;

        return item;
    }

    private groupBySeverity(): Map<string, number> {
        const groups = new Map<string, number>();
        const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'];

        for (const severity of severityOrder) {
            const count = this.findings.filter(f => f.severity === severity).length;
            if (count > 0) {
                groups.set(severity, count);
            }
        }

        return groups;
    }

    private getSeverityIcon(severity: string): vscode.ThemeIcon {
        switch (severity) {
            case 'Critical':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'High':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
            case 'Medium':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('warningForeground'));
            case 'Low':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('foreground'));
            case 'Info':
                return new vscode.ThemeIcon('lightbulb', new vscode.ThemeColor('foreground'));
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }
}

export class SecurityTreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string
    ) {
        super(label, collapsibleState);
    }

    severity?: string;
    filePath?: string;
    finding?: SecurityFinding;
}

// Register tree view commands
export function registerTreeCommands(context: vscode.ExtensionContext, treeProvider: SecurityTreeProvider): void {
    // Refresh command
    const refreshCommand = vscode.commands.registerCommand('soliditydefend.refreshTree', () => {
        treeProvider.refresh();
    });

    // Show finding details
    const showDetailsCommand = vscode.commands.registerCommand('soliditydefend.showFindingDetails', (item: SecurityTreeItem) => {
        if (item.finding) {
            vscode.commands.executeCommand('soliditydefend.showVulnerabilityDetails', item.finding);
        }
    });

    // Copy finding to clipboard
    const copyFindingCommand = vscode.commands.registerCommand('soliditydefend.copyFinding', (item: SecurityTreeItem) => {
        if (item.finding) {
            const text = `${item.finding.title} (${item.finding.severity})\nFile: ${item.finding.filePath}:${item.finding.line}\nDescription: ${item.finding.description}`;
            vscode.env.clipboard.writeText(text);
            vscode.window.showInformationMessage('Finding copied to clipboard');
        }
    });

    // Filter by severity
    const filterCommand = vscode.commands.registerCommand('soliditydefend.filterBySeverity', async () => {
        const severities = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info'];
        const selected = await vscode.window.showQuickPick(severities, {
            placeHolder: 'Select severity level to filter'
        });

        if (selected && selected !== 'All') {
            // Implement filtering logic here
            vscode.window.showInformationMessage(`Filtering by ${selected} severity (feature to be implemented)`);
        }
    });

    context.subscriptions.push(
        refreshCommand,
        showDetailsCommand,
        copyFindingCommand,
        filterCommand
    );
}