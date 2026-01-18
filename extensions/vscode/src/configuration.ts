import * as vscode from 'vscode';

export interface AnalysisConfiguration {
    severityThreshold: string;
    enableDefiAnalysis: boolean;
    enableCrossContractAnalysis: boolean;
    enableTaintAnalysis: boolean;
    maxAnalysisTime: number;
    enableInlineSuggestions: boolean;
    autoFixOnSave: boolean;
}

export class ConfigurationManager {
    private static readonly SECTION = 'soliditydefend';

    getAnalysisConfiguration(): AnalysisConfiguration {
        const config = vscode.workspace.getConfiguration(ConfigurationManager.SECTION);

        return {
            severityThreshold: config.get<string>('severityThreshold', 'Low'),
            enableDefiAnalysis: config.get<boolean>('enableDefiAnalysis', true),
            enableCrossContractAnalysis: config.get<boolean>('enableCrossContractAnalysis', true),
            enableTaintAnalysis: config.get<boolean>('enableTaintAnalysis', true),
            maxAnalysisTime: config.get<number>('maxAnalysisTime', 10000),
            enableInlineSuggestions: config.get<boolean>('enableInlineSuggestions', true),
            autoFixOnSave: config.get<boolean>('autoFixOnSave', false)
        };
    }

    isRealTimeAnalysisEnabled(): boolean {
        const config = vscode.workspace.getConfiguration(ConfigurationManager.SECTION);
        return config.get<boolean>('enableRealTimeAnalysis', true);
    }

    getAnalysisDelay(): number {
        const config = vscode.workspace.getConfiguration(ConfigurationManager.SECTION);
        return config.get<number>('analysisDelay', 500);
    }

    showProgressNotifications(): boolean {
        const config = vscode.workspace.getConfiguration(ConfigurationManager.SECTION);
        return config.get<boolean>('showProgressNotifications', true);
    }

    getBinaryPath(): string | undefined {
        const config = vscode.workspace.getConfiguration(ConfigurationManager.SECTION);
        return config.get<string>('binaryPath');
    }

    async updateConfiguration<T>(key: string, value: T, target?: vscode.ConfigurationTarget): Promise<void> {
        const config = vscode.workspace.getConfiguration(ConfigurationManager.SECTION);
        await config.update(key, value, target);
    }

    onConfigurationChanged(callback: (e: vscode.ConfigurationChangeEvent) => void): vscode.Disposable {
        return vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration(ConfigurationManager.SECTION)) {
                callback(e);
            }
        });
    }

    validateConfiguration(): string[] {
        const errors: string[] = [];
        const config = this.getAnalysisConfiguration();

        if (config.maxAnalysisTime < 1000) {
            errors.push('Analysis timeout must be at least 1000ms');
        }

        const validSeverities = ['Info', 'Low', 'Medium', 'High', 'Critical'];
        if (!validSeverities.includes(config.severityThreshold)) {
            errors.push(`Invalid severity threshold: ${config.severityThreshold}`);
        }

        return errors;
    }
}