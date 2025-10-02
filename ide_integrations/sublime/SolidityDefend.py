import sublime
import sublime_plugin
import subprocess
import json
import threading
import time
import os
import re
from typing import List, Dict, Optional, Any

# Package constants
PACKAGE_NAME = "SolidityDefend"
SETTINGS_FILE = "SolidityDefend.sublime-settings"
SYNTAX_FILE = "Packages/SolidityDefend/Solidity.sublime-syntax"

class SolidityDefendCommand(sublime_plugin.TextCommand):
    """Main command for SolidityDefend security analysis"""

    def run(self, edit, action="analyze_file"):
        if action == "analyze_file":
            self.analyze_current_file()
        elif action == "analyze_selection":
            self.analyze_selection()
        elif action == "clear_findings":
            self.clear_findings()
        elif action == "export_report":
            self.export_report()

    def analyze_current_file(self):
        """Analyze the current Solidity file"""
        if not self.is_solidity_file():
            sublime.error_message("This is not a Solidity file")
            return

        content = self.view.substr(sublime.Region(0, self.view.size()))
        file_path = self.view.file_name() or "untitled.sol"

        self.run_analysis(content, file_path)

    def analyze_selection(self):
        """Analyze the selected code"""
        if not self.view.sel():
            sublime.error_message("No text selected")
            return

        region = self.view.sel()[0]
        if region.empty():
            sublime.error_message("No text selected")
            return

        content = self.view.substr(region)
        file_path = self.view.file_name() or "selection.sol"

        self.run_analysis(content, file_path, region.begin())

    def run_analysis(self, content: str, file_path: str, offset: int = 0):
        """Run security analysis on the given content"""
        def analyze():
            try:
                analyzer = SolidityDefendAnalyzer()
                findings = analyzer.analyze_code(content, file_path)

                # Update UI in main thread
                sublime.set_timeout(
                    lambda: self.update_findings(findings, offset), 0
                )

            except Exception as e:
                sublime.set_timeout(
                    lambda: sublime.error_message(f"Analysis failed: {str(e)}"), 0
                )

        threading.Thread(target=analyze, daemon=True).start()

    def update_findings(self, findings: List[Dict], offset: int = 0):
        """Update the view with security findings"""
        self.clear_findings()

        if not findings:
            sublime.status_message("No security issues found")
            return

        # Add regions for highlighting
        regions_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

        for finding in findings:
            line = finding.get('line', 1) - 1  # Convert to 0-based
            column = finding.get('column', 0)
            severity = finding.get('severity', 'info').lower()

            # Calculate region
            point = self.view.text_point(line, column) + offset
            region = sublime.Region(point, point + 10)  # Highlight 10 characters

            if severity in regions_by_severity:
                regions_by_severity[severity].append(region)

        # Add regions with different scopes for different severities
        severity_scopes = {
            'critical': 'invalid.illegal',
            'high': 'invalid.deprecated',
            'medium': 'markup.warning',
            'low': 'markup.info',
            'info': 'comment'
        }

        for severity, regions in regions_by_severity.items():
            if regions:
                scope = severity_scopes.get(severity, 'comment')
                self.view.add_regions(
                    f"soliditydefend_{severity}",
                    regions,
                    scope,
                    "dot",
                    sublime.DRAW_SQUIGGLY_UNDERLINE
                )

        # Show findings in output panel
        self.show_findings_panel(findings)

        # Update status
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.get('severity', '').lower() == 'critical')

        status_msg = f"SolidityDefend: {total_findings} issues"
        if critical_count > 0:
            status_msg += f" ({critical_count} critical)"

        sublime.status_message(status_msg)

    def show_findings_panel(self, findings: List[Dict]):
        """Show findings in an output panel"""
        window = self.view.window()
        if not window:
            return

        panel = window.create_output_panel("soliditydefend_findings")
        panel.set_syntax_file("Packages/SolidityDefend/SolidityDefendOutput.sublime-syntax")

        # Format findings for display
        output_lines = ["SolidityDefend Security Analysis Results", "=" * 50, ""]

        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'Unknown')
            title = finding.get('title', 'Security Issue')
            description = finding.get('description', '')
            line = finding.get('line', 0)
            column = finding.get('column', 0)
            detector = finding.get('detector', 'unknown')
            suggested_fix = finding.get('suggested_fix', '')

            output_lines.extend([
                f"{i}. [{severity.upper()}] {title}",
                f"   Location: Line {line}, Column {column}",
                f"   Detector: {detector}",
                f"   Description: {description}",
            ])

            if suggested_fix:
                output_lines.append(f"   Suggested Fix: {suggested_fix}")

            output_lines.append("")

        # Add summary
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        output_lines.extend([
            "Summary:",
            f"Total Issues: {len(findings)}",
        ])

        for severity, count in sorted(severity_counts.items()):
            output_lines.append(f"{severity.capitalize()}: {count}")

        # Set panel content
        panel.run_command("append", {"characters": "\n".join(output_lines)})

        # Show panel
        window.run_command("show_panel", {"panel": "output.soliditydefend_findings"})

    def clear_findings(self):
        """Clear all highlighting and findings"""
        severities = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severities:
            self.view.erase_regions(f"soliditydefend_{severity}")

        sublime.status_message("")

    def export_report(self):
        """Export analysis report"""
        # This would integrate with the main analysis engine
        sublime.error_message("Export functionality coming soon")

    def is_solidity_file(self) -> bool:
        """Check if current file is a Solidity file"""
        file_name = self.view.file_name()
        if file_name and file_name.endswith('.sol'):
            return True

        # Check syntax
        syntax = self.view.settings().get('syntax', '')
        return 'solidity' in syntax.lower()

    def is_enabled(self) -> bool:
        """Enable command only for Solidity files"""
        return self.is_solidity_file()


class SolidityDefendAnalyzer:
    """Security analyzer for Solidity code"""

    def __init__(self):
        self.settings = sublime.load_settings(SETTINGS_FILE)

    def analyze_code(self, content: str, file_path: str) -> List[Dict]:
        """Analyze Solidity code for security vulnerabilities"""
        # Try LSP server first, fall back to pattern matching
        try:
            return self.analyze_with_lsp(content, file_path)
        except Exception:
            return self.analyze_with_patterns(content, file_path)

    def analyze_with_lsp(self, content: str, file_path: str) -> List[Dict]:
        """Analyze using SolidityDefend LSP server"""
        lsp_path = self.settings.get('lsp_server_path', 'soliditydefend')

        # Create temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            # Run analysis
            cmd = [lsp_path, '--analyze', '--format', 'json', temp_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"LSP analysis failed: {result.stderr}")

        finally:
            os.unlink(temp_path)

    def analyze_with_patterns(self, content: str, file_path: str) -> List[Dict]:
        """Fallback pattern-based analysis"""
        findings = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            # Check for tx.origin usage
            if 'tx.origin' in line:
                findings.append({
                    'id': f'tx_origin_{line_num}',
                    'detector': 'tx-origin',
                    'severity': 'Medium',
                    'title': 'Use of tx.origin',
                    'description': 'tx.origin should not be used for authorization as it can be manipulated',
                    'line': line_num,
                    'column': line.find('tx.origin'),
                    'suggested_fix': 'Replace tx.origin with msg.sender'
                })

            # Check for reentrancy patterns
            if '.call(' in line and 'require(' not in line:
                findings.append({
                    'id': f'reentrancy_{line_num}',
                    'detector': 'reentrancy',
                    'severity': 'High',
                    'title': 'Potential reentrancy vulnerability',
                    'description': 'External call without proper checks may be vulnerable to reentrancy',
                    'line': line_num,
                    'column': line.find('.call('),
                    'suggested_fix': 'Add reentrancy guard or check return value'
                })

            # Check for selfdestruct
            if 'selfdestruct' in line or 'suicide' in line:
                findings.append({
                    'id': f'selfdestruct_{line_num}',
                    'detector': 'selfdestruct',
                    'severity': 'High',
                    'title': 'Use of selfdestruct',
                    'description': 'selfdestruct can be dangerous and should be carefully reviewed',
                    'line': line_num,
                    'column': max(line.find('selfdestruct'), line.find('suicide')),
                    'suggested_fix': 'Ensure proper access control and consider alternatives'
                })

            # Check for missing access control
            if re.search(r'function\s+\w+.*public', line) and 'onlyOwner' not in line:
                findings.append({
                    'id': f'access_control_{line_num}',
                    'detector': 'missing-access-control',
                    'severity': 'Medium',
                    'title': 'Missing access control',
                    'description': 'Public function may need access control modifier',
                    'line': line_num,
                    'column': line.find('function'),
                    'suggested_fix': 'Add appropriate access control modifier (e.g., onlyOwner)'
                })

        return findings


class SolidityDefendAutoAnalyzer(sublime_plugin.EventListener):
    """Automatic analysis on file changes"""

    def __init__(self):
        self.last_analysis = {}
        self.analysis_delay = 2.0  # seconds

    def on_modified_async(self, view):
        """Trigger analysis when file is modified"""
        if not self.should_analyze(view):
            return

        file_id = view.file_name() or str(view.id())

        # Cancel previous timer
        if file_id in self.last_analysis:
            timer = self.last_analysis[file_id]
            if timer and timer.is_alive():
                timer.cancel()

        # Schedule new analysis
        timer = threading.Timer(
            self.analysis_delay,
            lambda: self.analyze_view(view)
        )
        timer.start()
        self.last_analysis[file_id] = timer

    def on_load_async(self, view):
        """Analyze when file is loaded"""
        if self.should_analyze(view):
            self.analyze_view(view)

    def should_analyze(self, view) -> bool:
        """Check if view should be analyzed"""
        settings = sublime.load_settings(SETTINGS_FILE)
        if not settings.get('auto_analyze', True):
            return False

        # Check if it's a Solidity file
        file_name = view.file_name()
        if file_name and file_name.endswith('.sol'):
            return True

        syntax = view.settings().get('syntax', '')
        return 'solidity' in syntax.lower()

    def analyze_view(self, view):
        """Analyze the given view"""
        if view.is_valid():
            view.run_command('solidity_defend', {'action': 'analyze_file'})


class SolidityDefendQuickFixCommand(sublime_plugin.TextCommand):
    """Command for applying quick fixes"""

    def run(self, edit, fix_type=None):
        if fix_type == "replace_tx_origin":
            self.replace_tx_origin(edit)
        elif fix_type == "add_reentrancy_guard":
            self.add_reentrancy_guard(edit)

    def replace_tx_origin(self, edit):
        """Replace tx.origin with msg.sender"""
        content = self.view.substr(sublime.Region(0, self.view.size()))
        new_content = content.replace('tx.origin', 'msg.sender')

        if new_content != content:
            self.view.replace(edit, sublime.Region(0, self.view.size()), new_content)
            sublime.status_message("Replaced tx.origin with msg.sender")

    def add_reentrancy_guard(self, edit):
        """Add nonReentrant modifier to vulnerable functions"""
        # This would require more sophisticated parsing
        sublime.status_message("Reentrancy guard feature coming soon")


class SolidityDefendOpenDashboardCommand(sublime_plugin.WindowCommand):
    """Command to open web dashboard"""

    def run(self):
        settings = sublime.load_settings(SETTINGS_FILE)
        dashboard_url = settings.get('dashboard_url', 'http://localhost:8080')

        import webbrowser
        webbrowser.open(dashboard_url)


# Plugin lifecycle
def plugin_loaded():
    """Called when plugin is loaded"""
    print(f"{PACKAGE_NAME} loaded")

def plugin_unloaded():
    """Called when plugin is unloaded"""
    print(f"{PACKAGE_NAME} unloaded")