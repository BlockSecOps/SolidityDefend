package com.soliditydefend.intellij;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.project.ProjectManager;
import com.intellij.openapi.startup.StartupActivity;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.vfs.VirtualFileManager;
import com.intellij.openapi.vfs.newvfs.BulkFileListener;
import com.intellij.openapi.vfs.newvfs.events.VFileEvent;
import com.intellij.util.messages.MessageBusConnection;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Main plugin class for SolidityDefend IntelliJ integration
 */
public class SolidityDefendPlugin implements StartupActivity {

    private static final String SOLIDITY_EXTENSION = "sol";
    private final ExecutorService analysisExecutor = Executors.newCachedThreadPool();
    private final ConcurrentHashMap<String, Long> analysisCache = new ConcurrentHashMap<>();
    private SolidityDefendLspClient lspClient;
    private MessageBusConnection connection;

    @Override
    public void runActivity(@NotNull Project project) {
        initializePlugin(project);
    }

    private void initializePlugin(Project project) {
        // Initialize LSP client
        try {
            lspClient = new SolidityDefendLspClient(project);
            lspClient.start();
        } catch (Exception e) {
            SolidityDefendNotifications.showError(project, "Failed to start SolidityDefend LSP server: " + e.getMessage());
        }

        // Set up file change listener
        setupFileWatcher(project);

        // Initialize tool windows and UI components
        initializeUI(project);

        SolidityDefendNotifications.showInfo(project, "SolidityDefend security analysis is now active");
    }

    private void setupFileWatcher(Project project) {
        connection = ApplicationManager.getApplication().getMessageBus().connect();
        connection.subscribe(VirtualFileManager.VFS_CHANGES, new BulkFileListener() {
            @Override
            public void after(@NotNull List<? extends VFileEvent> events) {
                for (VFileEvent event : events) {
                    VirtualFile file = event.getFile();
                    if (file != null && isSolidityFile(file)) {
                        scheduleAnalysis(project, file);
                    }
                }
            }
        });
    }

    private void initializeUI(Project project) {
        // Initialize security tool window
        SecurityToolWindow.initialize(project);

        // Register custom inspections
        registerInspections();

        // Set up status bar indicator
        StatusBarIndicator.initialize(project);
    }

    private void registerInspections() {
        // Inspections are registered via plugin.xml
        // This method can be used for dynamic registration if needed
    }

    private boolean isSolidityFile(VirtualFile file) {
        return SOLIDITY_EXTENSION.equals(file.getExtension());
    }

    private void scheduleAnalysis(Project project, VirtualFile file) {
        String filePath = file.getPath();
        long lastModified = file.getTimeStamp();

        // Check cache to avoid redundant analysis
        Long cachedTime = analysisCache.get(filePath);
        if (cachedTime != null && cachedTime >= lastModified) {
            return;
        }

        analysisExecutor.submit(() -> {
            try {
                analyzeFile(project, file);
                analysisCache.put(filePath, lastModified);
            } catch (Exception e) {
                SolidityDefendNotifications.showError(project, "Analysis failed for " + file.getName() + ": " + e.getMessage());
            }
        });
    }

    private void analyzeFile(Project project, VirtualFile file) {
        if (lspClient != null && lspClient.isConnected()) {
            lspClient.analyzeFile(file);
        } else {
            // Fallback to direct analysis
            SolidityDefendAnalyzer analyzer = new SolidityDefendAnalyzer();
            analyzer.analyzeFile(project, file);
        }
    }

    public void dispose() {
        if (connection != null) {
            connection.disconnect();
        }

        if (lspClient != null) {
            lspClient.stop();
        }

        analysisExecutor.shutdown();
        analysisCache.clear();
    }

    public static SolidityDefendPlugin getInstance() {
        return ApplicationManager.getApplication().getService(SolidityDefendPlugin.class);
    }

    public SolidityDefendLspClient getLspClient() {
        return lspClient;
    }
}

/**
 * LSP client for communicating with SolidityDefend language server
 */
class SolidityDefendLspClient {
    private final Project project;
    private Process lspProcess;
    private boolean connected = false;

    public SolidityDefendLspClient(Project project) {
        this.project = project;
    }

    public void start() throws Exception {
        // Start SolidityDefend LSP server
        String serverPath = SolidityDefendSettings.getInstance(project).getLspServerPath();
        if (serverPath == null || serverPath.isEmpty()) {
            throw new Exception("LSP server path not configured");
        }

        ProcessBuilder pb = new ProcessBuilder(serverPath, "--stdio");
        pb.directory(new java.io.File(project.getBasePath()));
        lspProcess = pb.start();

        // Initialize LSP communication
        initializeLspCommunication();
        connected = true;
    }

    private void initializeLspCommunication() {
        // Initialize JSON-RPC communication with LSP server
        // This would typically use a library like lsp4j
    }

    public void stop() {
        if (lspProcess != null) {
            lspProcess.destroy();
        }
        connected = false;
    }

    public boolean isConnected() {
        return connected && lspProcess != null && lspProcess.isAlive();
    }

    public void analyzeFile(VirtualFile file) {
        if (!isConnected()) {
            return;
        }

        // Send analysis request to LSP server
        // Implementation would depend on the LSP protocol
    }
}

/**
 * Direct analyzer as fallback when LSP is not available
 */
class SolidityDefendAnalyzer {
    public void analyzeFile(Project project, VirtualFile file) {
        try {
            String content = new String(file.contentsToByteArray());

            // Simple pattern-based analysis as fallback
            SecurityFinding[] findings = performBasicAnalysis(content, file.getPath());

            // Update UI with findings
            updateFindings(project, file, findings);
        } catch (Exception e) {
            SolidityDefendNotifications.showError(project, "Failed to analyze " + file.getName() + ": " + e.getMessage());
        }
    }

    private SecurityFinding[] performBasicAnalysis(String content, String filePath) {
        // Basic pattern matching for common vulnerabilities
        java.util.List<SecurityFinding> findings = new java.util.ArrayList<>();

        String[] lines = content.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];

            // Check for tx.origin usage
            if (line.contains("tx.origin")) {
                findings.add(new SecurityFinding(
                    "tx-origin",
                    "Use of tx.origin",
                    "tx.origin should not be used for authorization",
                    Severity.MEDIUM,
                    filePath,
                    i + 1,
                    line.indexOf("tx.origin"),
                    "Replace with msg.sender"
                ));
            }

            // Check for reentrancy patterns
            if (line.contains(".call(") && !line.contains("require(")) {
                findings.add(new SecurityFinding(
                    "reentrancy",
                    "Potential reentrancy vulnerability",
                    "External call without proper checks",
                    Severity.HIGH,
                    filePath,
                    i + 1,
                    line.indexOf(".call("),
                    "Add reentrancy guard or check return value"
                ));
            }

            // Check for selfdestruct
            if (line.contains("selfdestruct") || line.contains("suicide")) {
                findings.add(new SecurityFinding(
                    "selfdestruct",
                    "Use of selfdestruct",
                    "selfdestruct can be dangerous and should be carefully reviewed",
                    Severity.HIGH,
                    filePath,
                    i + 1,
                    Math.max(line.indexOf("selfdestruct"), line.indexOf("suicide")),
                    "Ensure proper access control and consider alternatives"
                ));
            }
        }

        return findings.toArray(new SecurityFinding[0]);
    }

    private void updateFindings(Project project, VirtualFile file, SecurityFinding[] findings) {
        ApplicationManager.getApplication().invokeLater(() -> {
            // Update highlighting and inspections
            SecurityHighlighter.updateHighlighting(project, file, findings);

            // Update tool window
            SecurityToolWindow toolWindow = SecurityToolWindow.getInstance(project);
            if (toolWindow != null) {
                toolWindow.updateFindings(file, findings);
            }

            // Update status bar
            StatusBarIndicator.updateStatus(project, findings.length);
        });
    }
}

/**
 * Data class for security findings
 */
class SecurityFinding {
    private final String detector;
    private final String title;
    private final String description;
    private final Severity severity;
    private final String filePath;
    private final int line;
    private final int column;
    private final String suggestedFix;

    public SecurityFinding(String detector, String title, String description, Severity severity,
                          String filePath, int line, int column, String suggestedFix) {
        this.detector = detector;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.filePath = filePath;
        this.line = line;
        this.column = column;
        this.suggestedFix = suggestedFix;
    }

    // Getters
    public String getDetector() { return detector; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public Severity getSeverity() { return severity; }
    public String getFilePath() { return filePath; }
    public int getLine() { return line; }
    public int getColumn() { return column; }
    public String getSuggestedFix() { return suggestedFix; }
}

enum Severity {
    CRITICAL, HIGH, MEDIUM, LOW, INFO
}

/**
 * Notification helper class
 */
class SolidityDefendNotifications {
    public static void showInfo(Project project, String message) {
        com.intellij.notification.Notifications.Bus.notify(
            new com.intellij.notification.Notification(
                "SolidityDefend",
                "SolidityDefend",
                message,
                com.intellij.notification.NotificationType.INFORMATION
            ),
            project
        );
    }

    public static void showError(Project project, String message) {
        com.intellij.notification.Notifications.Bus.notify(
            new com.intellij.notification.Notification(
                "SolidityDefend",
                "SolidityDefend Error",
                message,
                com.intellij.notification.NotificationType.ERROR
            ),
            project
        );
    }
}

/**
 * Settings management
 */
class SolidityDefendSettings {
    private String lspServerPath = "soliditydefend";
    private boolean enableRealTimeAnalysis = true;
    private boolean enableQuickFixes = true;
    private int analysisDelayMs = 500;

    public static SolidityDefendSettings getInstance(Project project) {
        return project.getService(SolidityDefendSettings.class);
    }

    public String getLspServerPath() { return lspServerPath; }
    public void setLspServerPath(String path) { this.lspServerPath = path; }

    public boolean isEnableRealTimeAnalysis() { return enableRealTimeAnalysis; }
    public void setEnableRealTimeAnalysis(boolean enable) { this.enableRealTimeAnalysis = enable; }

    public boolean isEnableQuickFixes() { return enableQuickFixes; }
    public void setEnableQuickFixes(boolean enable) { this.enableQuickFixes = enable; }

    public int getAnalysisDelayMs() { return analysisDelayMs; }
    public void setAnalysisDelayMs(int delay) { this.analysisDelayMs = delay; }
}

/**
 * Placeholder classes for UI components
 */
class SecurityToolWindow {
    public static void initialize(Project project) {
        // Initialize security tool window
    }

    public static SecurityToolWindow getInstance(Project project) {
        return project.getService(SecurityToolWindow.class);
    }

    public void updateFindings(VirtualFile file, SecurityFinding[] findings) {
        // Update tool window with findings
    }
}

class SecurityHighlighter {
    public static void updateHighlighting(Project project, VirtualFile file, SecurityFinding[] findings) {
        // Update editor highlighting
    }
}

class StatusBarIndicator {
    public static void initialize(Project project) {
        // Initialize status bar indicator
    }

    public static void updateStatus(Project project, int findingsCount) {
        // Update status bar with findings count
    }
}