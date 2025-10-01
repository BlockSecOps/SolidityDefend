import * as vscode from 'vscode';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind,
    RevealOutputChannelOn,
    ExecutableOptions,
    Executable
} from 'vscode-languageclient/node';

import { SecurityReportProvider } from './securityReport';
import { VulnerabilityTreeProvider } from './vulnerabilityTree';
import { SecurityStatusBar } from './statusBar';
import { DiagnosticsManager } from './diagnostics';

let client: LanguageClient;
let outputChannel: vscode.OutputChannel;
let securityReportProvider: SecurityReportProvider;
let vulnerabilityTreeProvider: VulnerabilityTreeProvider;
let statusBar: SecurityStatusBar;
let diagnosticsManager: DiagnosticsManager;

export function activate(context: vscode.ExtensionContext) {
    console.log('SolidityDefend extension is being activated');

    // Create output channel
    outputChannel = vscode.window.createOutputChannel('SolidityDefend');
    outputChannel.appendLine('SolidityDefend extension starting...');

    // Initialize components
    initializeComponents(context);

    // Start LSP client
    startLanguageClient(context);

    // Register commands
    registerCommands(context);

    // Register providers
    registerProviders(context);

    // Setup event listeners
    setupEventListeners(context);

    outputChannel.appendLine('SolidityDefend extension activated successfully');
}

export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }

    outputChannel.appendLine('SolidityDefend extension deactivating...');

    // Cleanup components
    if (statusBar) {
        statusBar.dispose();
    }

    return client.stop();
}

function initializeComponents(context: vscode.ExtensionContext) {
    // Initialize security report provider
    securityReportProvider = new SecurityReportProvider(context);

    // Initialize vulnerability tree provider
    vulnerabilityTreeProvider = new VulnerabilityTreeProvider();

    // Initialize status bar
    statusBar = new SecurityStatusBar();

    // Initialize diagnostics manager
    diagnosticsManager = new DiagnosticsManager();
}

function startLanguageClient(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('soliditydefend');

    // Get server executable
    const serverExecutable = getServerExecutable(config);

    if (!serverExecutable) {
        vscode.window.showErrorMessage(
            'SolidityDefend LSP server not found. Please install SolidityDefend or configure the server path.'
        );
        return;
    }

    // Server options
    const serverOptions: ServerOptions = {
        run: serverExecutable,
        debug: {
            ...serverExecutable,
            options: {
                ...serverExecutable.options,
                env: {
                    ...process.env,
                    RUST_LOG: 'debug'
                }
            }
        }
    };

    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'solidity' }
        ],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/*.sol')
        },
        outputChannel: outputChannel,
        revealOutputChannelOn: RevealOutputChannelOn.Info,
        initializationOptions: {
            enableRealTimeAnalysis: config.get('realTimeAnalysis', true),
            analysisDelay: config.get('analysisDelay', 500),
            maxDiagnostics: config.get('maxDiagnostics', 100),
            enabledDetectors: config.get('enabledDetectors', []),
            severityFilter: config.get('severityFilter', 'medium'),
            excludePatterns: config.get('excludePatterns', [])
        },
        markdown: {
            isTrusted: true,
            supportHtml: true
        }
    };

    // Create and start the client
    client = new LanguageClient(
        'soliditydefend',
        'SolidityDefend Language Server',
        serverOptions,
        clientOptions
    );

    // Start the client and server
    client.start().then(() => {
        outputChannel.appendLine('LSP client started successfully');
        statusBar.updateStatus('ready');

        // Setup client event listeners
        setupClientEventListeners();
    }).catch((error) => {
        outputChannel.appendLine(`Failed to start LSP client: ${error}`);
        vscode.window.showErrorMessage(`Failed to start SolidityDefend: ${error.message}`);
    });
}

function getServerExecutable(config: vscode.WorkspaceConfiguration): Executable | null {
    // Check user-configured path first
    const configuredPath = config.get<string>('server.path');
    if (configuredPath) {
        return {
            command: configuredPath,
            args: config.get<string[]>('server.args', []),
            options: {}
        };
    }

    // Try to find server in common locations
    const possiblePaths = [
        'soliditydefend-lsp',
        './target/release/soliditydefend-lsp',
        './target/debug/soliditydefend-lsp',
        'soliditydefend'
    ];

    for (const path of possiblePaths) {
        try {
            // This would normally check if the executable exists
            // For now, just return the first path (this will fail until server is built)
            return {
                command: path,
                args: ['--lsp'],
                options: {}
            };
        } catch (error) {
            // Continue to next path
        }
    }

    return null;
}

function registerCommands(context: vscode.ExtensionContext) {
    // Analyze current file
    const analyzeCommand = vscode.commands.registerCommand('soliditydefend.analyze', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.document.languageId !== 'solidity') {
            vscode.window.showWarningMessage('Please open a Solidity file to analyze');
            return;
        }

        await analyzeDocument(editor.document);
    });

    // Analyze workspace
    const analyzeWorkspaceCommand = vscode.commands.registerCommand('soliditydefend.analyzeWorkspace', async () => {
        await analyzeWorkspace();
    });

    // Clear diagnostics
    const clearDiagnosticsCommand = vscode.commands.registerCommand('soliditydefend.clearDiagnostics', () => {
        diagnosticsManager.clearAll();
        vscode.window.showInformationMessage('Diagnostics cleared');
    });

    // Open security report
    const openReportCommand = vscode.commands.registerCommand('soliditydefend.openSecurityReport', () => {
        securityReportProvider.showReport();
    });

    // Export results
    const exportResultsCommand = vscode.commands.registerCommand('soliditydefend.exportResults', async () => {
        await exportAnalysisResults();
    });

    // Show vulnerability info
    const showVulnerabilityInfoCommand = vscode.commands.registerCommand('soliditydefend.showVulnerabilityInfo', async () => {
        await showVulnerabilityInfo();
    });

    context.subscriptions.push(
        analyzeCommand,
        analyzeWorkspaceCommand,
        clearDiagnosticsCommand,
        openReportCommand,
        exportResultsCommand,
        showVulnerabilityInfoCommand
    );
}

function registerProviders(context: vscode.ExtensionContext) {
    // Register tree data provider for vulnerabilities
    vscode.window.registerTreeDataProvider('soliditydefendVulnerabilities', vulnerabilityTreeProvider);

    // Register webview provider for security reports
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('soliditydefendReport', securityReportProvider)
    );
}

function setupEventListeners(context: vscode.ExtensionContext) {
    // Listen for configuration changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(event => {
            if (event.affectsConfiguration('soliditydefend')) {
                handleConfigurationChange();
            }
        })
    );

    // Listen for document changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(event => {
            if (event.document.languageId === 'solidity') {
                handleDocumentChange(event);
            }
        })
    );

    // Listen for document saves
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            if (document.languageId === 'solidity') {
                handleDocumentSave(document);
            }
        })
    );
}

function setupClientEventListeners() {
    if (!client) {
        return;
    }

    // Listen for diagnostics
    client.onNotification('textDocument/publishDiagnostics', (params) => {
        diagnosticsManager.updateDiagnostics(params);
        vulnerabilityTreeProvider.updateFromDiagnostics(params.diagnostics);
        statusBar.updateFromDiagnostics(params.diagnostics);
    });

    // Listen for progress notifications
    client.onNotification('$/progress', (params) => {
        handleProgressNotification(params);
    });

    // Listen for custom notifications
    client.onNotification('soliditydefend/analysisComplete', (params) => {
        handleAnalysisComplete(params);
    });

    client.onNotification('soliditydefend/securityAlert', (params) => {
        handleSecurityAlert(params);
    });
}

async function analyzeDocument(document: vscode.TextDocument) {
    if (!client) {
        vscode.window.showErrorMessage('Language server not available');
        return;
    }

    statusBar.updateStatus('analyzing');

    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Analyzing Solidity file...',
            cancellable: false
        }, async () => {
            // Trigger analysis through LSP
            await client.sendRequest('textDocument/diagnostic', {
                textDocument: { uri: document.uri.toString() }
            });
        });
    } catch (error) {
        vscode.window.showErrorMessage(`Analysis failed: ${error}`);
        statusBar.updateStatus('error');
    }
}

async function analyzeWorkspace() {
    const solidityFiles = await vscode.workspace.findFiles('**/*.sol', '**/node_modules/**');

    if (solidityFiles.length === 0) {
        vscode.window.showInformationMessage('No Solidity files found in workspace');
        return;
    }

    statusBar.updateStatus('analyzing');

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Analyzing workspace...',
        cancellable: true
    }, async (progress, token) => {
        const increment = 100 / solidityFiles.length;

        for (let i = 0; i < solidityFiles.length; i++) {
            if (token.isCancellationRequested) {
                break;
            }

            const file = solidityFiles[i];
            progress.report({
                increment,
                message: `Analyzing ${file.fsPath}`
            });

            try {
                const document = await vscode.workspace.openTextDocument(file);
                await analyzeDocument(document);
            } catch (error) {
                outputChannel.appendLine(`Failed to analyze ${file.fsPath}: ${error}`);
            }
        }
    });

    statusBar.updateStatus('ready');
}

async function exportAnalysisResults() {
    const saveLocation = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('security-report.json'),
        filters: {
            'JSON': ['json'],
            'SARIF': ['sarif'],
            'HTML': ['html']
        }
    });

    if (!saveLocation) {
        return;
    }

    try {
        const results = await diagnosticsManager.exportResults();
        await vscode.workspace.fs.writeFile(saveLocation, Buffer.from(JSON.stringify(results, null, 2)));
        vscode.window.showInformationMessage(`Results exported to ${saveLocation.fsPath}`);
    } catch (error) {
        vscode.window.showErrorMessage(`Export failed: ${error}`);
    }
}

async function showVulnerabilityInfo() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        return;
    }

    const position = editor.selection.active;
    const diagnostics = vscode.languages.getDiagnostics(editor.document.uri);

    const diagnosticAtPosition = diagnostics.find(d =>
        d.range.contains(position)
    );

    if (!diagnosticAtPosition) {
        vscode.window.showInformationMessage('No vulnerability found at cursor position');
        return;
    }

    // Show detailed vulnerability information
    const panel = vscode.window.createWebviewPanel(
        'vulnerabilityInfo',
        'Vulnerability Information',
        vscode.ViewColumn.Beside,
        { enableScripts: true }
    );

    panel.webview.html = generateVulnerabilityHtml(diagnosticAtPosition);
}

function generateVulnerabilityHtml(diagnostic: vscode.Diagnostic): string {
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Information</title>
            <style>
                body { font-family: var(--vscode-font-family); padding: 20px; }
                .severity-critical { color: #ff4444; }
                .severity-high { color: #ff8800; }
                .severity-medium { color: #ffaa00; }
                .severity-low { color: #4488ff; }
                .code-block { background: var(--vscode-textCodeBlock-background); padding: 10px; border-radius: 4px; }
            </style>
        </head>
        <body>
            <h1>Security Vulnerability</h1>
            <h2 class="severity-${diagnostic.severity}">${diagnostic.message}</h2>
            <p><strong>Code:</strong> ${diagnostic.code}</p>
            <p><strong>Source:</strong> ${diagnostic.source}</p>
            <div class="code-block">
                <p>For detailed information about this vulnerability, please refer to the SolidityDefend documentation.</p>
            </div>
        </body>
        </html>
    `;
}

function handleConfigurationChange() {
    // Restart LSP client with new configuration
    if (client) {
        client.stop().then(() => {
            const context = {
                subscriptions: []
            } as vscode.ExtensionContext;
            startLanguageClient(context);
        });
    }
}

function handleDocumentChange(event: vscode.TextDocumentChangeEvent) {
    // Handle real-time analysis if enabled
    const config = vscode.workspace.getConfiguration('soliditydefend');
    if (config.get('realTimeAnalysis', true)) {
        // Debounce analysis calls
        setTimeout(() => {
            analyzeDocument(event.document);
        }, config.get('analysisDelay', 500));
    }
}

function handleDocumentSave(document: vscode.TextDocument) {
    // Always analyze on save
    analyzeDocument(document);
}

function handleProgressNotification(params: any) {
    // Handle progress updates from LSP server
    if (params.value && params.value.message) {
        statusBar.updateStatus('analyzing', params.value.message);
    }
}

function handleAnalysisComplete(params: any) {
    statusBar.updateStatus('ready');
    securityReportProvider.updateReport(params);
}

function handleSecurityAlert(params: any) {
    if (params.severity === 'critical') {
        vscode.window.showErrorMessage(
            `Critical security issue found: ${params.message}`,
            'Show Details'
        ).then(selection => {
            if (selection === 'Show Details') {
                showVulnerabilityInfo();
            }
        });
    }
}