//! AI Agent Prompt Injection Detector

use anyhow::Result;
use std::any::Any;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct AIAgentPromptInjectionDetector {
    base: BaseDetector,
}

impl AIAgentPromptInjectionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("ai-agent-prompt-injection".to_string()),
                "AI Agent Prompt Injection".to_string(),
                "Detects prompt injection vulnerabilities in AI contracts".to_string(),
                vec![DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Default for AIAgentPromptInjectionDetector {
    fn default() -> Self { Self::new() }
}

impl Detector for AIAgentPromptInjectionDetector {
    fn id(&self) -> DetectorId { self.base.id.clone() }
    fn name(&self) -> &str { &self.base.name }
    fn description(&self) -> &str { &self.base.description }
    fn categories(&self) -> Vec<DetectorCategory> { self.base.categories.clone() }
    fn default_severity(&self) -> Severity { self.base.default_severity }
    fn is_enabled(&self) -> bool { self.base.enabled }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lower = ctx.source_code.to_lowercase();

        if lower.contains("aioracle") || lower.contains("llm") || lower.contains("gpt") {
            if !lower.contains("sanitize") && !lower.contains("validate") {
                findings.push(self.base.create_finding(
                    ctx,
                    "AI oracle input not sanitized - prompt injection possible".to_string(),
                    1, 1, ctx.source_code.len() as u32,
                ).with_fix_suggestion("Sanitize AI inputs: require(isValidPrompt(userInput))".to_string()));
            }
        }
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any { self }
}
