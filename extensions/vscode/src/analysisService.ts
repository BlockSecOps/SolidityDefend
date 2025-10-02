import * as vscode from 'vscode';
import { ConfigurationManager } from './configuration';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execAsync = promisify(exec);

export interface SecurityFinding {
    id: string;
    detector: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
    title: string;
    description: string;
    filePath: string;
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
    confidence: number;
    suggestedFix?: string;
    gasImpact?: string;
    references?: string[];
    cwe?: string[];
    tags?: string[];
}

export interface AnalysisResult {
    findings: SecurityFinding[];
    statistics: {
        totalLines: number;
        totalFunctions: number;
        analysisTime: number;
        riskScore: number;
    };
    metadata: {
        version: string;
        timestamp: string;
        configuration: any;
    };
}

export class AnalysisService {
    private configManager: ConfigurationManager;
    private analysisCache: Map<string, { result: AnalysisResult; timestamp: number }> = new Map();
    private readonly CACHE_TTL = 30000; // 30 seconds

    constructor(configManager: ConfigurationManager) {
        this.configManager = configManager;
    }

    async analyzeDocument(document: vscode.TextDocument): Promise<AnalysisResult> {
        const content = document.getText();
        const filePath = document.uri.fsPath;

        // Check cache first
        const cached = this.getCachedResult(filePath, content);
        if (cached) {
            return cached;
        }

        try {
            // Call SolidityDefend CLI for analysis
            const result = await this.runSolidityDefendAnalysis(filePath, content);

            // Cache the result
            this.setCachedResult(filePath, content, result);

            return result;

        } catch (error) {
            console.error('Analysis error:', error);

            // Return fallback analysis result
            return this.createFallbackResult(filePath, content);
        }
    }

    async analyzeWorkspace(workspacePath: string): Promise<AnalysisResult[]> {
        const solidityFiles = await vscode.workspace.findFiles('**/*.sol');
        const results: AnalysisResult[] = [];

        for (const fileUri of solidityFiles) {
            try {
                const document = await vscode.workspace.openTextDocument(fileUri);
                const result = await this.analyzeDocument(document);
                results.push(result);
            } catch (error) {
                console.error(`Failed to analyze ${fileUri.fsPath}:`, error);
            }
        }

        return results;
    }

    async generateReport(findings: SecurityFinding[], outputPath: string): Promise<string> {
        const reportData = {
            summary: {
                totalFindings: findings.length,
                criticalFindings: findings.filter(f => f.severity === 'Critical').length,
                highFindings: findings.filter(f => f.severity === 'High').length,
                mediumFindings: findings.filter(f => f.severity === 'Medium').length,
                lowFindings: findings.filter(f => f.severity === 'Low').length,
                generatedAt: new Date().toISOString()
            },
            findings: findings
        };

        const extension = path.extname(outputPath).toLowerCase();

        switch (extension) {
            case '.json':
                return JSON.stringify(reportData, null, 2);
            case '.html':
                return this.generateHtmlReport(reportData);
            default:
                return JSON.stringify(reportData, null, 2);
        }
    }

    private async runSolidityDefendAnalysis(filePath: string, content: string): Promise<AnalysisResult> {
        const config = this.configManager.getAnalysisConfiguration();

        // Build command arguments
        const args = [
            '--input', filePath,
            '--format', 'json',
            '--severity-threshold', config.severityThreshold
        ];

        if (config.enableDefiAnalysis) {
            args.push('--enable-defi');
        }

        if (config.enableCrossContractAnalysis) {
            args.push('--enable-cross-contract');
        }

        if (config.enableTaintAnalysis) {
            args.push('--enable-taint');
        }

        // Execute SolidityDefend
        const solidityDefendPath = this.getSolidityDefendPath();
        const command = `${solidityDefendPath} ${args.join(' ')}`;

        try {
            const { stdout, stderr } = await execAsync(command, {
                timeout: config.maxAnalysisTime,
                cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
            });

            if (stderr) {
                console.warn('SolidityDefend stderr:', stderr);
            }

            return this.parseAnalysisOutput(stdout, filePath);

        } catch (error) {
            console.error('SolidityDefend execution failed:', error);
            throw error;
        }
    }

    private parseAnalysisOutput(output: string, filePath: string): AnalysisResult {
        try {
            const parsed = JSON.parse(output);

            return {
                findings: parsed.findings?.map((finding: any) => ({
                    id: finding.id || this.generateFindingId(),
                    detector: finding.detector || 'unknown',
                    severity: finding.severity || 'Low',
                    title: finding.title || finding.message || 'Security Issue',
                    description: finding.description || finding.message || '',
                    filePath: finding.file_path || filePath,
                    line: finding.line_number || 1,
                    column: finding.column || 0,
                    endLine: finding.end_line,
                    endColumn: finding.end_column,
                    confidence: finding.confidence || 0.5,
                    suggestedFix: finding.suggested_fix,
                    gasImpact: finding.gas_impact,
                    references: finding.references,
                    cwe: finding.cwe,
                    tags: finding.tags
                })) || [],
                statistics: {
                    totalLines: parsed.statistics?.total_lines || 0,
                    totalFunctions: parsed.statistics?.total_functions || 0,
                    analysisTime: parsed.statistics?.analysis_time || 0,
                    riskScore: parsed.statistics?.risk_score || 0
                },
                metadata: {
                    version: parsed.metadata?.version || '1.0.0',
                    timestamp: new Date().toISOString(),
                    configuration: this.configManager.getAnalysisConfiguration()
                }
            };

        } catch (error) {
            console.error('Failed to parse analysis output:', error);
            throw new Error('Invalid analysis output format');
        }
    }

    private createFallbackResult(filePath: string, content: string): AnalysisResult {
        // Simple pattern-based analysis as fallback
        const findings: SecurityFinding[] = [];
        const lines = content.split('\n');

        lines.forEach((line, index) => {
            // Check for common vulnerability patterns
            if (line.includes('tx.origin')) {
                findings.push({
                    id: this.generateFindingId(),
                    detector: 'tx-origin',
                    severity: 'Medium',
                    title: 'Use of tx.origin',
                    description: 'tx.origin should not be used for authorization as it can be manipulated in phishing attacks',
                    filePath,
                    line: index + 1,
                    column: line.indexOf('tx.origin'),
                    confidence: 0.8,
                    suggestedFix: 'Use msg.sender instead of tx.origin for authorization checks',
                    cwe: ['CWE-477']
                });
            }

            if (line.includes('selfdestruct') || line.includes('suicide')) {
                findings.push({
                    id: this.generateFindingId(),
                    detector: 'selfdestruct',
                    severity: 'High',
                    title: 'Use of selfdestruct',
                    description: 'selfdestruct can be dangerous and should be carefully reviewed',
                    filePath,
                    line: index + 1,
                    column: Math.max(line.indexOf('selfdestruct'), line.indexOf('suicide')),
                    confidence: 0.9,
                    cwe: ['CWE-404']
                });
            }

            if (line.match(/\.call\s*\(/)) {
                findings.push({
                    id: this.generateFindingId(),
                    detector: 'low-level-call',
                    severity: 'Medium',
                    title: 'Low-level call',
                    description: 'Low-level calls should be used with caution and proper error handling',
                    filePath,
                    line: index + 1,
                    column: line.search(/\.call\s*\(/),
                    confidence: 0.6,
                    suggestedFix: 'Ensure proper error handling and consider using higher-level alternatives',
                    cwe: ['CWE-20']
                });
            }
        });

        return {
            findings,
            statistics: {
                totalLines: lines.length,
                totalFunctions: this.countFunctions(content),
                analysisTime: 0,
                riskScore: this.calculateRiskScore(findings)
            },
            metadata: {
                version: '1.0.0-fallback',
                timestamp: new Date().toISOString(),
                configuration: this.configManager.getAnalysisConfiguration()
            }
        };
    }

    private countFunctions(content: string): number {
        const functionMatches = content.match(/function\s+\w+/g);
        return functionMatches ? functionMatches.length : 0;
    }

    private calculateRiskScore(findings: SecurityFinding[]): number {
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

    private getSolidityDefendPath(): string {
        // Try to find SolidityDefend binary
        const workspaceConfig = vscode.workspace.getConfiguration('soliditydefend');
        const customPath = workspaceConfig.get<string>('binaryPath');

        if (customPath) {
            return customPath;
        }

        // Default paths to try
        const defaultPaths = [
            'soliditydefend',
            './target/release/soliditydefend',
            './target/debug/soliditydefend',
            path.join(__dirname, '../../target/release/soliditydefend')
        ];

        return defaultPaths[0]; // Default to system PATH
    }

    private getCachedResult(filePath: string, content: string): AnalysisResult | null {
        const cacheKey = this.getCacheKey(filePath, content);
        const cached = this.analysisCache.get(cacheKey);

        if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
            return cached.result;
        }

        return null;
    }

    private setCachedResult(filePath: string, content: string, result: AnalysisResult): void {
        const cacheKey = this.getCacheKey(filePath, content);
        this.analysisCache.set(cacheKey, {
            result,
            timestamp: Date.now()
        });

        // Clean old cache entries
        this.cleanCache();
    }

    private getCacheKey(filePath: string, content: string): string {
        // Simple hash function for cache key
        let hash = 0;
        const str = filePath + content;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString();
    }

    private cleanCache(): void {
        const now = Date.now();
        for (const [key, value] of this.analysisCache.entries()) {
            if (now - value.timestamp > this.CACHE_TTL) {
                this.analysisCache.delete(key);
            }
        }
    }

    private generateFindingId(): string {
        return 'finding_' + Math.random().toString(36).substr(2, 9);
    }

    private generateHtmlReport(reportData: any): string {
        return `<!DOCTYPE html>
<html>
<head>
    <title>SolidityDefend Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #e74c3c; }
        .high { border-left: 5px solid #f39c12; }
        .medium { border-left: 5px solid #f1c40f; }
        .low { border-left: 5px solid #27ae60; }
        .severity { font-weight: bold; padding: 2px 8px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SolidityDefend Security Report</h1>
        <p>Generated: ${reportData.summary.generatedAt}</p>
    </div>

    <div class="summary">
        <div class="metric">
            <h3>${reportData.summary.totalFindings}</h3>
            <p>Total Issues</p>
        </div>
        <div class="metric">
            <h3>${reportData.summary.criticalFindings}</h3>
            <p>Critical</p>
        </div>
        <div class="metric">
            <h3>${reportData.summary.highFindings}</h3>
            <p>High</p>
        </div>
        <div class="metric">
            <h3>${reportData.summary.mediumFindings}</h3>
            <p>Medium</p>
        </div>
        <div class="metric">
            <h3>${reportData.summary.lowFindings}</h3>
            <p>Low</p>
        </div>
    </div>

    <h2>Security Findings</h2>
    ${reportData.findings.map((finding: SecurityFinding) => `
        <div class="finding ${finding.severity.toLowerCase()}">
            <h3>${finding.title}</h3>
            <p><strong>Severity:</strong> <span class="severity">${finding.severity}</span></p>
            <p><strong>File:</strong> ${finding.filePath} (Line ${finding.line})</p>
            <p><strong>Description:</strong> ${finding.description}</p>
            ${finding.suggestedFix ? `<p><strong>Suggested Fix:</strong> ${finding.suggestedFix}</p>` : ''}
            <p><strong>Confidence:</strong> ${Math.round(finding.confidence * 100)}%</p>
        </div>
    `).join('')}
</body>
</html>`;
    }
}