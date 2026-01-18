import * as vscode from 'vscode';
import { SolidityDefendProvider } from './provider';
import { SecurityDashboard } from './dashboard';
import { DiagnosticsManager } from './diagnostics';
import { QuickFixProvider } from './quickFix';
import { SecurityTreeProvider } from './securityTree';
import { AnalysisService } from './analysisService';
import { ConfigurationManager } from './configuration';

let solidityDefendProvider: SolidityDefendProvider;
let securityDashboard: SecurityDashboard;
let diagnosticsManager: DiagnosticsManager;
let quickFixProvider: QuickFixProvider;
let securityTreeProvider: SecurityTreeProvider;
let analysisService: AnalysisService;
let configManager: ConfigurationManager;

export function activate(context: vscode.ExtensionContext) {
    console.log('SolidityDefend extension is now active!');

    // Initialize configuration manager
    configManager = new ConfigurationManager();

    // Initialize core services
    analysisService = new AnalysisService(configManager);
    diagnosticsManager = new DiagnosticsManager();
    solidityDefendProvider = new SolidityDefendProvider(analysisService, diagnosticsManager);
    securityDashboard = new SecurityDashboard(context, analysisService);
    quickFixProvider = new QuickFixProvider(analysisService);
    securityTreeProvider = new SecurityTreeProvider();

    // Register providers
    context.subscriptions.push(
        vscode.languages.registerHoverProvider('solidity', solidityDefendProvider),
        vscode.languages.registerCompletionItemProvider('solidity', solidityDefendProvider, '.', ' '),
        vscode.languages.registerCodeActionsProvider('solidity', quickFixProvider),
        vscode.window.registerTreeDataProvider('soliditydefend.securityView', securityTreeProvider)
    );

    // Register commands
    registerCommands(context);

    // Set up file watchers and real-time analysis
    setupFileWatchers(context);

    // Initialize status bar
    setupStatusBar(context);

    // Show welcome message
    showWelcomeMessage();
}

function registerCommands(context: vscode.ExtensionContext) {
    // Analyze current file
    const analyzeFileCommand = vscode.commands.registerCommand('soliditydefend.analyzeFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.document.languageId !== 'solidity') {
            vscode.window.showWarningMessage('Please open a Solidity file to analyze.');
            return;
        }

        await analyzeDocument(editor.document);
    });

    // Analyze workspace
    const analyzeWorkspaceCommand = vscode.commands.registerCommand('soliditydefend.analyzeWorkspace', async () => {
        await analyzeWorkspace();
    });

    // Show security dashboard
    const showDashboardCommand = vscode.commands.registerCommand('soliditydefend.showDashboard', () => {
        securityDashboard.show();
    });

    // Clear diagnostics
    const clearDiagnosticsCommand = vscode.commands.registerCommand('soliditydefend.clearDiagnostics', () => {
        diagnosticsManager.clear();
        securityTreeProvider.clear();
        vscode.window.showInformationMessage('Security diagnostics cleared.');
    });

    // Quick fix
    const quickFixCommand = vscode.commands.registerCommand('soliditydefend.quickFix', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return;
        }

        const position = editor.selection.active;
        const actions = await quickFixProvider.provideCodeActions(
            editor.document,
            new vscode.Range(position, position),
            { diagnostics: [], only: undefined, triggerKind: vscode.CodeActionTriggerKind.Invoke },
            new vscode.CancellationTokenSource().token
        );

        if (actions && actions.length > 0) {
            const items = actions.map(action => ({
                label: action.title,
                action: action
            }));

            const selected = await vscode.window.showQuickPick(items, {
                placeHolder: 'Select a security fix to apply'
            });

            if (selected && selected.action.edit) {
                await vscode.workspace.applyEdit(selected.action.edit);
                vscode.window.showInformationMessage(`Applied fix: ${selected.action.title}`);
            }
        } else {
            vscode.window.showInformationMessage('No security fixes available for current location.');
        }
    });

    // Show vulnerability details
    const showVulnerabilityDetailsCommand = vscode.commands.registerCommand('soliditydefend.showVulnerabilityDetails', (vulnerability: any) => {
        securityDashboard.showVulnerabilityDetails(vulnerability);
    });

    // Export security report
    const exportReportCommand = vscode.commands.registerCommand('soliditydefend.exportReport', async () => {
        await exportSecurityReport();
    });

    context.subscriptions.push(
        analyzeFileCommand,
        analyzeWorkspaceCommand,
        showDashboardCommand,
        clearDiagnosticsCommand,
        quickFixCommand,
        showVulnerabilityDetailsCommand,
        exportReportCommand
    );
}

function setupFileWatchers(context: vscode.ExtensionContext) {
    // Watch for Solidity file changes
    const fileWatcher = vscode.workspace.createFileSystemWatcher('**/*.sol');

    fileWatcher.onDidChange(async (uri) => {
        if (configManager.isRealTimeAnalysisEnabled()) {
            const document = await vscode.workspace.openTextDocument(uri);
            debounceAnalysis(document);
        }
    });

    fileWatcher.onDidCreate(async (uri) => {
        const document = await vscode.workspace.openTextDocument(uri);
        await analyzeDocument(document);
    });

    // Watch for active editor changes
    const editorChangeWatcher = vscode.window.onDidChangeActiveTextEditor(async (editor) => {
        if (editor && editor.document.languageId === 'solidity') {
            if (configManager.isRealTimeAnalysisEnabled()) {
                debounceAnalysis(editor.document);
            }
        }
    });

    // Watch for text document changes
    const documentChangeWatcher = vscode.workspace.onDidChangeTextDocument(async (event) => {
        if (event.document.languageId === 'solidity' && configManager.isRealTimeAnalysisEnabled()) {
            debounceAnalysis(event.document);
        }
    });

    context.subscriptions.push(fileWatcher, editorChangeWatcher, documentChangeWatcher);
}

// Debounced analysis to avoid excessive calls
let analysisTimeout: NodeJS.Timeout;
function debounceAnalysis(document: vscode.TextDocument) {
    clearTimeout(analysisTimeout);
    analysisTimeout = setTimeout(() => {
        analyzeDocument(document);
    }, configManager.getAnalysisDelay());
}

async function analyzeDocument(document: vscode.TextDocument) {
    if (document.languageId !== 'solidity') {
        return;
    }

    const startTime = Date.now();

    try {
        // Show progress notification if enabled
        if (configManager.showProgressNotifications()) {
            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: "SolidityDefend",
                cancellable: false
            }, async (progress) => {
                progress.report({ message: "Analyzing security..." });

                const analysis = await analysisService.analyzeDocument(document);
                const diagnostics = diagnosticsManager.createDiagnostics(analysis, document.uri);

                diagnosticsManager.updateDiagnostics(document.uri, diagnostics);
                securityTreeProvider.updateFindings(analysis.findings);

                const duration = Date.now() - startTime;
                progress.report({
                    message: `Analysis complete (${duration}ms)`,
                    increment: 100
                });

                // Update status bar
                updateStatusBar(analysis.findings.length, duration);
            });
        } else {
            // Silent analysis
            const analysis = await analysisService.analyzeDocument(document);
            const diagnostics = diagnosticsManager.createDiagnostics(analysis, document.uri);

            diagnosticsManager.updateDiagnostics(document.uri, diagnostics);
            securityTreeProvider.updateFindings(analysis.findings);

            const duration = Date.now() - startTime;
            updateStatusBar(analysis.findings.length, duration);
        }

    } catch (error) {
        console.error('Analysis failed:', error);
        vscode.window.showErrorMessage(`SolidityDefend analysis failed: ${error}`);
    }
}

async function analyzeWorkspace() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showWarningMessage('No workspace folder open.');
        return;
    }

    const solidityFiles = await vscode.workspace.findFiles('**/*.sol');

    if (solidityFiles.length === 0) {
        vscode.window.showInformationMessage('No Solidity files found in workspace.');
        return;
    }

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "SolidityDefend Workspace Analysis",
        cancellable: true
    }, async (progress, token) => {
        let processedFiles = 0;
        const totalFiles = solidityFiles.length;

        for (const fileUri of solidityFiles) {
            if (token.isCancellationRequested) {
                break;
            }

            try {
                const document = await vscode.workspace.openTextDocument(fileUri);
                await analyzeDocument(document);

                processedFiles++;
                progress.report({
                    message: `Analyzed ${processedFiles}/${totalFiles} files`,
                    increment: (100 / totalFiles)
                });

            } catch (error) {
                console.error(`Failed to analyze ${fileUri.fsPath}:`, error);
            }
        }

        vscode.window.showInformationMessage(
            `Workspace analysis complete. Analyzed ${processedFiles} Solidity files.`
        );
    });
}

async function exportSecurityReport() {
    const saveUri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('security-report.json'),
        filters: {
            'JSON files': ['json'],
            'HTML files': ['html'],
            'PDF files': ['pdf']
        }
    });

    if (!saveUri) {
        return;
    }

    try {
        const allFindings = securityTreeProvider.getAllFindings();
        const report = await analysisService.generateReport(allFindings, saveUri.fsPath);

        await vscode.workspace.fs.writeFile(saveUri, Buffer.from(report));

        const openReport = await vscode.window.showInformationMessage(
            'Security report exported successfully!',
            'Open Report'
        );

        if (openReport === 'Open Report') {
            await vscode.env.openExternal(saveUri);
        }

    } catch (error) {
        vscode.window.showErrorMessage(`Failed to export report: ${error}`);
    }
}

// Status bar management
let statusBarItem: vscode.StatusBarItem;

function setupStatusBar(context: vscode.ExtensionContext) {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'soliditydefend.showDashboard';
    statusBarItem.text = "$(shield) SolidityDefend";
    statusBarItem.tooltip = "Click to open security dashboard";
    statusBarItem.show();

    context.subscriptions.push(statusBarItem);
}

function updateStatusBar(findingsCount: number, analysisTime: number) {
    if (findingsCount === 0) {
        statusBarItem.text = "$(shield) SolidityDefend: ✓ Secure";
        statusBarItem.color = new vscode.ThemeColor('statusBar.foreground');
        statusBarItem.backgroundColor = undefined;
    } else {
        statusBarItem.text = `$(shield) SolidityDefend: ${findingsCount} issue${findingsCount === 1 ? '' : 's'}`;
        statusBarItem.color = new vscode.ThemeColor('errorForeground');
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }

    statusBarItem.tooltip = `${findingsCount} security issues found (${analysisTime}ms)`;
}

function showWelcomeMessage() {
    const config = vscode.workspace.getConfiguration('soliditydefend');
    const hasShownWelcome = config.get('hasShownWelcome', false);

    if (!hasShownWelcome) {
        vscode.window.showInformationMessage(
            'Welcome to SolidityDefend! Advanced security analysis for your Solidity smart contracts.',
            'Open Dashboard',
            'View Documentation',
            'Don\'t show again'
        ).then((selection) => {
            switch (selection) {
                case 'Open Dashboard':
                    securityDashboard.show();
                    break;
                case 'View Documentation':
                    vscode.env.openExternal(vscode.Uri.parse('https://docs.soliditydefend.dev'));
                    break;
                case 'Don\'t show again':
                    config.update('hasShownWelcome', true, vscode.ConfigurationTarget.Global);
                    break;
            }
        });
    }
}

export function deactivate() {
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}