import * as vscode from 'vscode';
import { AnalysisService, SecurityFinding, AnalysisResult } from './analysisService';

export class SecurityDashboard {
    private panel: vscode.WebviewPanel | undefined;

    constructor(
        private context: vscode.ExtensionContext,
        private analysisService: AnalysisService
    ) {}

    public show(): void {
        if (this.panel) {
            this.panel.reveal(vscode.ViewColumn.Two);
            return;
        }

        this.panel = vscode.window.createWebviewPanel(
            'soliditydefendDashboard',
            'SolidityDefend Security Dashboard',
            vscode.ViewColumn.Two,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [
                    vscode.Uri.joinPath(this.context.extensionUri, 'resources')
                ]
            }
        );

        this.panel.webview.html = this.getWebviewContent();

        this.panel.webview.onDidReceiveMessage(
            message => this.handleWebviewMessage(message),
            undefined,
            this.context.subscriptions
        );

        this.panel.onDidDispose(
            () => {
                this.panel = undefined;
            },
            null,
            this.context.subscriptions
        );

        this.updateDashboard();
    }

    public showVulnerabilityDetails(vulnerability: SecurityFinding): void {
        this.show();
        this.panel?.webview.postMessage({
            command: 'showVulnerabilityDetails',
            vulnerability: vulnerability
        });
    }

    private async handleWebviewMessage(message: any): Promise<void> {
        switch (message.command) {
            case 'analyzeWorkspace':
                await vscode.commands.executeCommand('soliditydefend.analyzeWorkspace');
                break;
            case 'analyzeFile':
                await vscode.commands.executeCommand('soliditydefend.analyzeFile');
                break;
            case 'exportReport':
                await vscode.commands.executeCommand('soliditydefend.exportReport');
                break;
            case 'openFile':
                if (message.filePath && message.line) {
                    const uri = vscode.Uri.file(message.filePath);
                    const document = await vscode.workspace.openTextDocument(uri);
                    const editor = await vscode.window.showTextDocument(document);
                    const position = new vscode.Position(message.line - 1, message.column || 0);
                    editor.selection = new vscode.Selection(position, position);
                    editor.revealRange(new vscode.Range(position, position));
                }
                break;
            case 'applyQuickFix':
                if (message.filePath && message.line) {
                    const uri = vscode.Uri.file(message.filePath);
                    const document = await vscode.workspace.openTextDocument(uri);
                    await vscode.window.showTextDocument(document);
                    await vscode.commands.executeCommand('soliditydefend.quickFix');
                }
                break;
            case 'refresh':
                this.updateDashboard();
                break;
        }
    }

    private async updateDashboard(): Promise<void> {
        if (!this.panel) {
            return;
        }

        const workspaceStats = await this.getWorkspaceStatistics();
        this.panel.webview.postMessage({
            command: 'updateData',
            data: workspaceStats
        });
    }

    private async getWorkspaceStatistics(): Promise<any> {
        const solidityFiles = await vscode.workspace.findFiles('**/*.sol');
        let totalFindings: SecurityFinding[] = [];
        let analysisResults: AnalysisResult[] = [];

        // Get current analysis results from all open files
        for (const fileUri of solidityFiles) {
            try {
                const document = await vscode.workspace.openTextDocument(fileUri);
                const result = await this.analysisService.analyzeDocument(document);
                analysisResults.push(result);
                totalFindings.push(...result.findings);
            } catch (error) {
                console.error(`Failed to analyze ${fileUri.fsPath}:`, error);
            }
        }

        const severityCounts = this.calculateSeverityCounts(totalFindings);
        const riskScore = this.calculateOverallRiskScore(totalFindings);
        const recommendations = this.generateRecommendations(totalFindings);

        return {
            totalFiles: solidityFiles.length,
            totalFindings: totalFindings.length,
            severityCounts,
            riskScore,
            findings: totalFindings.slice(0, 50), // Limit for performance
            recommendations,
            lastAnalysis: new Date().toISOString()
        };
    }

    private calculateSeverityCounts(findings: SecurityFinding[]): Record<string, number> {
        const counts = {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0,
            Info: 0
        };

        findings.forEach(finding => {
            counts[finding.severity as keyof typeof counts]++;
        });

        return counts;
    }

    private calculateOverallRiskScore(findings: SecurityFinding[]): number {
        let score = 0;
        findings.forEach(finding => {
            switch (finding.severity) {
                case 'Critical':
                    score += 10;
                    break;
                case 'High':
                    score += 5;
                    break;
                case 'Medium':
                    score += 2;
                    break;
                case 'Low':
                    score += 1;
                    break;
            }
        });
        return Math.min(score, 100);
    }

    private generateRecommendations(findings: SecurityFinding[]): string[] {
        const recommendations: string[] = [];
        const severityCounts = this.calculateSeverityCounts(findings);

        if (severityCounts.Critical > 0) {
            recommendations.push('🔴 Critical vulnerabilities found - immediate action required');
        }

        if (severityCounts.High > 3) {
            recommendations.push('⚠️ Multiple high-severity issues detected - conduct security review');
        }

        if (findings.some(f => f.detector.includes('reentrancy'))) {
            recommendations.push('🔒 Implement reentrancy guards for external calls');
        }

        if (findings.some(f => f.detector.includes('access-control'))) {
            recommendations.push('👥 Review and strengthen access control mechanisms');
        }

        if (findings.length === 0) {
            recommendations.push('✅ No security issues detected - maintain good practices');
        }

        return recommendations;
    }

    private getWebviewContent(): string {
        return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SolidityDefend Dashboard</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            background-color: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }

        .header {
            display: flex;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }

        .header h1 {
            margin: 0;
            font-size: 24px;
            color: var(--vscode-titleBar-activeForeground);
        }

        .shield-icon {
            font-size: 28px;
            margin-right: 15px;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .card {
            background-color: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 20px;
        }

        .card h3 {
            margin-top: 0;
            color: var(--vscode-titleBar-activeForeground);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }

        .stat-item {
            text-align: center;
            padding: 10px;
            background-color: var(--vscode-editor-background);
            border-radius: 6px;
        }

        .stat-number {
            font-size: 24px;
            font-weight: bold;
            display: block;
        }

        .stat-label {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
        }

        .severity-critical { color: #f14c4c; }
        .severity-high { color: #ff8c00; }
        .severity-medium { color: #ffcc02; }
        .severity-low { color: #89d185; }
        .severity-info { color: #75beff; }

        .findings-list {
            max-height: 400px;
            overflow-y: auto;
        }

        .finding-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            margin-bottom: 8px;
            background-color: var(--vscode-editor-background);
            border-radius: 6px;
            cursor: pointer;
        }

        .finding-item:hover {
            background-color: var(--vscode-list-hoverBackground);
        }

        .finding-title {
            font-weight: bold;
        }

        .finding-location {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
        }

        .recommendations {
            list-style: none;
            padding: 0;
        }

        .recommendations li {
            padding: 8px 0;
            border-bottom: 1px solid var(--vscode-panel-border);
        }

        .recommendations li:last-child {
            border-bottom: none;
        }

        .action-buttons {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        .btn {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
        }

        .btn:hover {
            background-color: var(--vscode-button-hoverBackground);
        }

        .btn-secondary {
            background-color: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }

        .btn-secondary:hover {
            background-color: var(--vscode-button-secondaryHoverBackground);
        }

        .risk-meter {
            width: 100%;
            height: 20px;
            background-color: var(--vscode-editor-background);
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }

        .risk-fill {
            height: 100%;
            transition: width 0.3s ease;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: var(--vscode-descriptionForeground);
        }
    </style>
</head>
<body>
    <div class="header">
        <span class="shield-icon">🛡️</span>
        <h1>Security Dashboard</h1>
    </div>

    <div id="loading" class="loading">
        Loading security analysis...
    </div>

    <div id="dashboard" style="display: none;">
        <div class="dashboard-grid">
            <div class="card">
                <h3>📊 Overview</h3>
                <div class="stats-grid">
                    <div class="stat-item">
                        <span id="totalFiles" class="stat-number">0</span>
                        <span class="stat-label">Files</span>
                    </div>
                    <div class="stat-item">
                        <span id="totalFindings" class="stat-number">0</span>
                        <span class="stat-label">Issues</span>
                    </div>
                </div>
                <div style="margin-top: 15px;">
                    <span class="stat-label">Risk Score</span>
                    <div class="risk-meter">
                        <div id="riskFill" class="risk-fill" style="width: 0%;"></div>
                    </div>
                    <span id="riskScore">0/100</span>
                </div>
            </div>

            <div class="card">
                <h3>⚠️ Severity Breakdown</h3>
                <div id="severityStats"></div>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="card">
                <h3>🔍 Recent Findings</h3>
                <div id="findingsList" class="findings-list"></div>
            </div>

            <div class="card">
                <h3>💡 Recommendations</h3>
                <ul id="recommendations" class="recommendations"></ul>
            </div>
        </div>

        <div class="action-buttons">
            <button class="btn" onclick="analyzeWorkspace()">Analyze Workspace</button>
            <button class="btn" onclick="analyzeCurrentFile()">Analyze Current File</button>
            <button class="btn btn-secondary" onclick="exportReport()">Export Report</button>
            <button class="btn btn-secondary" onclick="refresh()">Refresh</button>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();

        function analyzeWorkspace() {
            vscode.postMessage({ command: 'analyzeWorkspace' });
        }

        function analyzeCurrentFile() {
            vscode.postMessage({ command: 'analyzeFile' });
        }

        function exportReport() {
            vscode.postMessage({ command: 'exportReport' });
        }

        function refresh() {
            document.getElementById('loading').style.display = 'block';
            document.getElementById('dashboard').style.display = 'none';
            vscode.postMessage({ command: 'refresh' });
        }

        function openFile(filePath, line, column) {
            vscode.postMessage({
                command: 'openFile',
                filePath: filePath,
                line: line,
                column: column
            });
        }

        function applyQuickFix(filePath, line) {
            vscode.postMessage({
                command: 'applyQuickFix',
                filePath: filePath,
                line: line
            });
        }

        window.addEventListener('message', event => {
            const message = event.data;

            switch (message.command) {
                case 'updateData':
                    updateDashboard(message.data);
                    break;
                case 'showVulnerabilityDetails':
                    showVulnerabilityDetails(message.vulnerability);
                    break;
            }
        });

        function updateDashboard(data) {
            document.getElementById('loading').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';

            document.getElementById('totalFiles').textContent = data.totalFiles;
            document.getElementById('totalFindings').textContent = data.totalFindings;
            document.getElementById('riskScore').textContent = data.riskScore + '/100';

            const riskFill = document.getElementById('riskFill');
            riskFill.style.width = data.riskScore + '%';
            riskFill.style.backgroundColor = getRiskColor(data.riskScore);

            updateSeverityStats(data.severityCounts);
            updateFindingsList(data.findings);
            updateRecommendations(data.recommendations);
        }

        function getRiskColor(score) {
            if (score >= 70) return '#f14c4c';
            if (score >= 40) return '#ff8c00';
            if (score >= 20) return '#ffcc02';
            return '#89d185';
        }

        function updateSeverityStats(counts) {
            const container = document.getElementById('severityStats');
            container.innerHTML = '';

            const severities = [
                { name: 'Critical', count: counts.Critical, class: 'severity-critical' },
                { name: 'High', count: counts.High, class: 'severity-high' },
                { name: 'Medium', count: counts.Medium, class: 'severity-medium' },
                { name: 'Low', count: counts.Low, class: 'severity-low' },
                { name: 'Info', count: counts.Info, class: 'severity-info' }
            ];

            severities.forEach(severity => {
                const item = document.createElement('div');
                item.className = 'stat-item';
                item.innerHTML = \`
                    <span class="stat-number \${severity.class}">\${severity.count}</span>
                    <span class="stat-label">\${severity.name}</span>
                \`;
                container.appendChild(item);
            });
        }

        function updateFindingsList(findings) {
            const container = document.getElementById('findingsList');
            container.innerHTML = '';

            if (findings.length === 0) {
                container.innerHTML = '<p style="text-align: center; color: var(--vscode-descriptionForeground);">No security issues found</p>';
                return;
            }

            findings.slice(0, 10).forEach(finding => {
                const item = document.createElement('div');
                item.className = 'finding-item';
                item.onclick = () => openFile(finding.filePath, finding.line, finding.column);

                item.innerHTML = \`
                    <div>
                        <div class="finding-title severity-\${finding.severity.toLowerCase()}">\${finding.title}</div>
                        <div class="finding-location">\${finding.filePath}:\${finding.line}</div>
                    </div>
                    <span class="severity-\${finding.severity.toLowerCase()}">\${finding.severity}</span>
                \`;

                container.appendChild(item);
            });
        }

        function updateRecommendations(recommendations) {
            const container = document.getElementById('recommendations');
            container.innerHTML = '';

            recommendations.forEach(rec => {
                const item = document.createElement('li');
                item.textContent = rec;
                container.appendChild(item);
            });
        }

        function showVulnerabilityDetails(vulnerability) {
            // Scroll to and highlight the relevant finding
            const findingItems = document.querySelectorAll('.finding-item');
            findingItems.forEach(item => {
                if (item.textContent.includes(vulnerability.title)) {
                    item.scrollIntoView({ behavior: 'smooth' });
                    item.style.backgroundColor = 'var(--vscode-list-activeSelectionBackground)';
                    setTimeout(() => {
                        item.style.backgroundColor = '';
                    }, 2000);
                }
            });
        }

        // Request initial data
        refresh();
    </script>
</body>
</html>`;
    }
}