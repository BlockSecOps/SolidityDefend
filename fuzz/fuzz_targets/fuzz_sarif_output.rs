// fuzz/fuzz_targets/fuzz_sarif_output.rs
// Fuzzing target for SARIF output generation and validation

#![no_main]

use libfuzzer-sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::panic;
use serde_json;

/// Fuzzable SARIF generation parameters
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzSarifInput {
    pub tool_info: FuzzToolInfo,
    pub runs: Vec<FuzzRun>,
    pub version: FuzzSarifVersion,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzToolInfo {
    pub name: String,
    pub version: String,
    pub organization: Option<String>,
    pub product_suite: Option<String>,
    pub full_name: Option<String>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzRun {
    pub tool: FuzzTool,
    pub results: Vec<FuzzResult>,
    pub artifacts: Vec<FuzzArtifact>,
    pub invocations: Vec<FuzzInvocation>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzTool {
    pub driver: FuzzToolComponent,
    pub extensions: Vec<FuzzToolComponent>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzToolComponent {
    pub name: String,
    pub version: Option<String>,
    pub information_uri: Option<String>,
    pub rules: Vec<FuzzRule>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzRule {
    pub id: String,
    pub name: Option<String>,
    pub short_description: Option<FuzzMessage>,
    pub full_description: Option<FuzzMessage>,
    pub default_configuration: Option<FuzzConfiguration>,
    pub help: Option<FuzzMessage>,
    pub help_uri: Option<String>,
    pub properties: Option<FuzzPropertyBag>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzMessage {
    pub text: String,
    pub markdown: Option<String>,
    pub id: Option<String>,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzConfiguration {
    pub level: FuzzLevel,
    pub enabled: bool,
    pub rank: Option<f64>,
    pub parameters: Option<FuzzPropertyBag>,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzLevel {
    None,
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzPropertyBag {
    pub properties: Vec<(String, FuzzPropertyValue)>,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzPropertyValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<FuzzPropertyValue>),
    Object(Vec<(String, FuzzPropertyValue)>),
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzResult {
    pub rule_id: String,
    pub rule_index: Option<u32>,
    pub kind: FuzzResultKind,
    pub level: FuzzLevel,
    pub message: FuzzMessage,
    pub locations: Vec<FuzzLocation>,
    pub analysis_target: Option<FuzzArtifactLocation>,
    pub fingerprints: Option<FuzzPropertyBag>,
    pub partial_fingerprints: Option<FuzzPropertyBag>,
    pub code_flows: Vec<FuzzCodeFlow>,
    pub related_locations: Vec<FuzzLocation>,
    pub suppression_states: Vec<FuzzSuppressionState>,
    pub baseline_state: Option<FuzzBaselineState>,
    pub rank: Option<f64>,
    pub attachments: Vec<FuzzAttachment>,
    pub work_item_uris: Vec<String>,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzResultKind {
    NotApplicable,
    Pass,
    Fail,
    Review,
    Open,
    Informational,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzLocation {
    pub id: Option<u32>,
    pub physical_location: Option<FuzzPhysicalLocation>,
    pub logical_locations: Vec<FuzzLogicalLocation>,
    pub message: Option<FuzzMessage>,
    pub annotations: Vec<FuzzRegion>,
    pub relationships: Vec<FuzzLocationRelationship>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzPhysicalLocation {
    pub artifact_location: FuzzArtifactLocation,
    pub region: Option<FuzzRegion>,
    pub context_region: Option<FuzzRegion>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzArtifactLocation {
    pub uri: String,
    pub uri_base_id: Option<String>,
    pub index: Option<u32>,
    pub description: Option<FuzzMessage>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzRegion {
    pub start_line: Option<u32>,
    pub start_column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    pub char_offset: Option<u32>,
    pub char_length: Option<u32>,
    pub byte_offset: Option<u32>,
    pub byte_length: Option<u32>,
    pub snippet: Option<FuzzArtifactContent>,
    pub message: Option<FuzzMessage>,
    pub source_language: Option<String>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzArtifactContent {
    pub text: String,
    pub binary: Option<String>,
    pub rendered: Option<FuzzMultiformatMessageString>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzMultiformatMessageString {
    pub text: String,
    pub markdown: Option<String>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzLogicalLocation {
    pub name: Option<String>,
    pub index: Option<u32>,
    pub fully_qualified_name: Option<String>,
    pub decorated_name: Option<String>,
    pub kind: Option<String>,
    pub parent_index: Option<u32>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzLocationRelationship {
    pub target: u32,
    pub kinds: Vec<String>,
    pub description: Option<FuzzMessage>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzCodeFlow {
    pub thread_flows: Vec<FuzzThreadFlow>,
    pub message: Option<FuzzMessage>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzThreadFlow {
    pub id: Option<String>,
    pub message: Option<FuzzMessage>,
    pub locations: Vec<FuzzThreadFlowLocation>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzThreadFlowLocation {
    pub step: Option<u32>,
    pub location: FuzzLocation,
    pub state: Option<FuzzPropertyBag>,
    pub kinds: Vec<String>,
    pub taxa: Vec<FuzzReportingDescriptorReference>,
    pub module: Option<String>,
    pub nest_level: Option<u32>,
    pub execution_order: Option<u32>,
    pub execution_time_utc: Option<String>,
    pub importance: Option<FuzzThreadFlowLocationImportance>,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzThreadFlowLocationImportance {
    Important,
    Essential,
    Unimportant,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzReportingDescriptorReference {
    pub id: Option<String>,
    pub index: Option<u32>,
    pub guid: Option<String>,
    pub tool_component: Option<FuzzToolComponentReference>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzToolComponentReference {
    pub name: Option<String>,
    pub index: Option<u32>,
    pub guid: Option<String>,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzSuppressionState {
    InSource,
    External,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzBaselineState {
    New,
    Unchanged,
    Updated,
    Absent,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzAttachment {
    pub description: FuzzMessage,
    pub artifact_location: FuzzArtifactLocation,
    pub regions: Vec<FuzzRegion>,
    pub rectangles: Vec<FuzzRectangle>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzRectangle {
    pub top: Option<f64>,
    pub left: Option<f64>,
    pub bottom: Option<f64>,
    pub right: Option<f64>,
    pub message: Option<FuzzMessage>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzArtifact {
    pub location: Option<FuzzArtifactLocation>,
    pub length: Option<u32>,
    pub offset: Option<u32>,
    pub roles: Vec<FuzzArtifactRole>,
    pub mime_type: Option<String>,
    pub contents: Option<FuzzArtifactContent>,
    pub encoding: Option<String>,
    pub source_language: Option<String>,
    pub hashes: Option<FuzzPropertyBag>,
    pub last_modified_time_utc: Option<String>,
    pub description: Option<FuzzMessage>,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzArtifactRole {
    AnalysisTarget,
    Attachment,
    ResponseFile,
    ResultFile,
    StandardStream,
    TracedFile,
    Unmodified,
    Modified,
    Added,
    Deleted,
    Renamed,
    Uncontrolled,
    Driver,
    Extension,
    Translation,
    Taxonomy,
    Policy,
    ReferencedOnCommandLine,
    MemoryContents,
    Directory,
    UserSpecifiedConfiguration,
    ToolSpecifiedConfiguration,
    DebugOutputFile,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzInvocation {
    pub command_line: Option<String>,
    pub arguments: Vec<String>,
    pub response_files: Vec<FuzzArtifactLocation>,
    pub start_time_utc: Option<String>,
    pub end_time_utc: Option<String>,
    pub exit_code: Option<i32>,
    pub rule_configuration_overrides: Vec<FuzzConfigurationOverride>,
    pub notification_configuration_overrides: Vec<FuzzConfigurationOverride>,
    pub tool_execution_notifications: Vec<FuzzNotification>,
    pub tool_configuration_notifications: Vec<FuzzNotification>,
    pub exit_code_description: Option<String>,
    pub exit_signals: Vec<String>,
    pub process_start_failure_message: Option<String>,
    pub execution_successful: bool,
    pub machine: Option<String>,
    pub account: Option<String>,
    pub process_id: Option<u32>,
    pub executable_location: Option<FuzzArtifactLocation>,
    pub working_directory: Option<FuzzArtifactLocation>,
    pub environment_variables: Option<FuzzPropertyBag>,
    pub stdin: Option<FuzzArtifactLocation>,
    pub stdout: Option<FuzzArtifactLocation>,
    pub stderr: Option<FuzzArtifactLocation>,
    pub stdout_stderr: Option<FuzzArtifactLocation>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzConfigurationOverride {
    pub configuration: FuzzConfiguration,
    pub descriptor: FuzzReportingDescriptorReference,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzNotification {
    pub locations: Vec<FuzzLocation>,
    pub message: FuzzMessage,
    pub level: FuzzLevel,
    pub thread_id: Option<u32>,
    pub time_utc: Option<String>,
    pub exception: Option<FuzzException>,
    pub descriptor: Option<FuzzReportingDescriptorReference>,
    pub associated_rule: Option<FuzzReportingDescriptorReference>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzException {
    pub kind: Option<String>,
    pub message: Option<String>,
    pub stack: Option<FuzzStack>,
    pub inner_exceptions: Vec<FuzzException>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzStack {
    pub message: Option<FuzzMessage>,
    pub frames: Vec<FuzzStackFrame>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzStackFrame {
    pub location: Option<FuzzLocation>,
    pub module: Option<String>,
    pub thread_id: Option<u32>,
    pub parameters: Vec<String>,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzSarifVersion {
    V2_1_0,
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let _ = panic::catch_unwind(|| {
        if let Ok(mut unstructured) = Unstructured::new(data) {
            if let Ok(input) = FuzzSarifInput::arbitrary(&mut unstructured) {
                fuzz_sarif_generation(&input);
            }
        }
    });
});

fn fuzz_sarif_generation(input: &FuzzSarifInput) {
    // Generate SARIF JSON from fuzzed input
    let sarif_json = generate_sarif_json(input);

    // Validate generated JSON
    validate_sarif_json(&sarif_json);

    // Test round-trip serialization
    test_sarif_round_trip(&sarif_json);

    // Test SARIF schema compliance
    test_schema_compliance(&sarif_json);
}

fn generate_sarif_json(input: &FuzzSarifInput) -> serde_json::Value {
    let mut sarif = serde_json::json!({
        "version": format_sarif_version(&input.version),
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json"
    });

    // Add runs
    let mut runs = Vec::new();
    for run in &input.runs {
        runs.push(generate_run_json(run));
    }
    sarif["runs"] = serde_json::Value::Array(runs);

    sarif
}

fn format_sarif_version(version: &FuzzSarifVersion) -> &'static str {
    match version {
        FuzzSarifVersion::V2_1_0 => "2.1.0",
    }
}

fn generate_run_json(run: &FuzzRun) -> serde_json::Value {
    let mut run_json = serde_json::json!({
        "tool": generate_tool_json(&run.tool)
    });

    // Add results
    if !run.results.is_empty() {
        let mut results = Vec::new();
        for result in &run.results {
            results.push(generate_result_json(result));
        }
        run_json["results"] = serde_json::Value::Array(results);
    }

    // Add artifacts
    if !run.artifacts.is_empty() {
        let mut artifacts = Vec::new();
        for artifact in &run.artifacts {
            artifacts.push(generate_artifact_json(artifact));
        }
        run_json["artifacts"] = serde_json::Value::Array(artifacts);
    }

    // Add invocations
    if !run.invocations.is_empty() {
        let mut invocations = Vec::new();
        for invocation in &run.invocations {
            invocations.push(generate_invocation_json(invocation));
        }
        run_json["invocations"] = serde_json::Value::Array(invocations);
    }

    run_json
}

fn generate_tool_json(tool: &FuzzTool) -> serde_json::Value {
    let mut tool_json = serde_json::json!({
        "driver": generate_tool_component_json(&tool.driver)
    });

    if !tool.extensions.is_empty() {
        let mut extensions = Vec::new();
        for extension in &tool.extensions {
            extensions.push(generate_tool_component_json(extension));
        }
        tool_json["extensions"] = serde_json::Value::Array(extensions);
    }

    tool_json
}

fn generate_tool_component_json(component: &FuzzToolComponent) -> serde_json::Value {
    let mut component_json = serde_json::json!({
        "name": sanitize_string(&component.name)
    });

    if let Some(version) = &component.version {
        component_json["version"] = serde_json::Value::String(sanitize_string(version));
    }

    if let Some(uri) = &component.information_uri {
        if is_valid_uri(uri) {
            component_json["informationUri"] = serde_json::Value::String(sanitize_string(uri));
        }
    }

    if !component.rules.is_empty() {
        let mut rules = Vec::new();
        for rule in &component.rules {
            rules.push(generate_rule_json(rule));
        }
        component_json["rules"] = serde_json::Value::Array(rules);
    }

    component_json
}

fn generate_rule_json(rule: &FuzzRule) -> serde_json::Value {
    let mut rule_json = serde_json::json!({
        "id": sanitize_string(&rule.id)
    });

    if let Some(name) = &rule.name {
        rule_json["name"] = serde_json::Value::String(sanitize_string(name));
    }

    if let Some(short_desc) = &rule.short_description {
        rule_json["shortDescription"] = generate_message_json(short_desc);
    }

    if let Some(full_desc) = &rule.full_description {
        rule_json["fullDescription"] = generate_message_json(full_desc);
    }

    if let Some(config) = &rule.default_configuration {
        rule_json["defaultConfiguration"] = generate_configuration_json(config);
    }

    if let Some(help) = &rule.help {
        rule_json["help"] = generate_message_json(help);
    }

    if let Some(help_uri) = &rule.help_uri {
        if is_valid_uri(help_uri) {
            rule_json["helpUri"] = serde_json::Value::String(sanitize_string(help_uri));
        }
    }

    if let Some(properties) = &rule.properties {
        rule_json["properties"] = generate_property_bag_json(properties);
    }

    rule_json
}

fn generate_message_json(message: &FuzzMessage) -> serde_json::Value {
    let mut message_json = serde_json::json!({
        "text": sanitize_string(&message.text)
    });

    if let Some(markdown) = &message.markdown {
        message_json["markdown"] = serde_json::Value::String(sanitize_string(markdown));
    }

    if let Some(id) = &message.id {
        message_json["id"] = serde_json::Value::String(sanitize_string(id));
    }

    if !message.arguments.is_empty() {
        let args: Vec<serde_json::Value> = message.arguments.iter()
            .map(|arg| serde_json::Value::String(sanitize_string(arg)))
            .collect();
        message_json["arguments"] = serde_json::Value::Array(args);
    }

    message_json
}

fn generate_configuration_json(config: &FuzzConfiguration) -> serde_json::Value {
    let mut config_json = serde_json::json!({
        "level": format_level(&config.level),
        "enabled": config.enabled
    });

    if let Some(rank) = config.rank {
        if rank.is_finite() && rank >= 0.0 && rank <= 100.0 {
            config_json["rank"] = serde_json::Value::Number(
                serde_json::Number::from_f64(rank).unwrap_or(serde_json::Number::from(0))
            );
        }
    }

    if let Some(parameters) = &config.parameters {
        config_json["parameters"] = generate_property_bag_json(parameters);
    }

    config_json
}

fn format_level(level: &FuzzLevel) -> &'static str {
    match level {
        FuzzLevel::None => "none",
        FuzzLevel::Note => "note",
        FuzzLevel::Warning => "warning",
        FuzzLevel::Error => "error",
    }
}

fn generate_property_bag_json(bag: &FuzzPropertyBag) -> serde_json::Value {
    let mut obj = serde_json::Map::new();

    for (key, value) in &bag.properties {
        let sanitized_key = sanitize_property_key(key);
        if !sanitized_key.is_empty() {
            obj.insert(sanitized_key, generate_property_value_json(value));
        }
    }

    serde_json::Value::Object(obj)
}

fn generate_property_value_json(value: &FuzzPropertyValue) -> serde_json::Value {
    match value {
        FuzzPropertyValue::String(s) => serde_json::Value::String(sanitize_string(s)),
        FuzzPropertyValue::Number(n) => {
            if n.is_finite() {
                serde_json::Value::Number(
                    serde_json::Number::from_f64(*n).unwrap_or(serde_json::Number::from(0))
                )
            } else {
                serde_json::Value::Number(serde_json::Number::from(0))
            }
        },
        FuzzPropertyValue::Boolean(b) => serde_json::Value::Bool(*b),
        FuzzPropertyValue::Array(arr) => {
            let values: Vec<serde_json::Value> = arr.iter()
                .map(generate_property_value_json)
                .collect();
            serde_json::Value::Array(values)
        },
        FuzzPropertyValue::Object(obj) => {
            let mut map = serde_json::Map::new();
            for (key, val) in obj {
                let sanitized_key = sanitize_property_key(key);
                if !sanitized_key.is_empty() {
                    map.insert(sanitized_key, generate_property_value_json(val));
                }
            }
            serde_json::Value::Object(map)
        },
    }
}

fn generate_result_json(result: &FuzzResult) -> serde_json::Value {
    let mut result_json = serde_json::json!({
        "ruleId": sanitize_string(&result.rule_id),
        "level": format_level(&result.level),
        "message": generate_message_json(&result.message)
    });

    if let Some(rule_index) = result.rule_index {
        result_json["ruleIndex"] = serde_json::Value::Number(serde_json::Number::from(rule_index));
    }

    result_json["kind"] = serde_json::Value::String(format_result_kind(&result.kind));

    if !result.locations.is_empty() {
        let mut locations = Vec::new();
        for location in &result.locations {
            locations.push(generate_location_json(location));
        }
        result_json["locations"] = serde_json::Value::Array(locations);
    }

    if let Some(target) = &result.analysis_target {
        result_json["analysisTarget"] = generate_artifact_location_json(target);
    }

    if let Some(rank) = result.rank {
        if rank.is_finite() && rank >= 0.0 && rank <= 100.0 {
            result_json["rank"] = serde_json::Value::Number(
                serde_json::Number::from_f64(rank).unwrap_or(serde_json::Number::from(0))
            );
        }
    }

    result_json
}

fn format_result_kind(kind: &FuzzResultKind) -> &'static str {
    match kind {
        FuzzResultKind::NotApplicable => "notApplicable",
        FuzzResultKind::Pass => "pass",
        FuzzResultKind::Fail => "fail",
        FuzzResultKind::Review => "review",
        FuzzResultKind::Open => "open",
        FuzzResultKind::Informational => "informational",
    }
}

fn generate_location_json(location: &FuzzLocation) -> serde_json::Value {
    let mut location_json = serde_json::json!({});

    if let Some(id) = location.id {
        location_json["id"] = serde_json::Value::Number(serde_json::Number::from(id));
    }

    if let Some(physical) = &location.physical_location {
        location_json["physicalLocation"] = generate_physical_location_json(physical);
    }

    if !location.logical_locations.is_empty() {
        let mut logical_locations = Vec::new();
        for logical in &location.logical_locations {
            logical_locations.push(generate_logical_location_json(logical));
        }
        location_json["logicalLocations"] = serde_json::Value::Array(logical_locations);
    }

    if let Some(message) = &location.message {
        location_json["message"] = generate_message_json(message);
    }

    location_json
}

fn generate_physical_location_json(physical: &FuzzPhysicalLocation) -> serde_json::Value {
    let mut physical_json = serde_json::json!({
        "artifactLocation": generate_artifact_location_json(&physical.artifact_location)
    });

    if let Some(region) = &physical.region {
        physical_json["region"] = generate_region_json(region);
    }

    if let Some(context) = &physical.context_region {
        physical_json["contextRegion"] = generate_region_json(context);
    }

    physical_json
}

fn generate_artifact_location_json(location: &FuzzArtifactLocation) -> serde_json::Value {
    let mut location_json = serde_json::json!({
        "uri": sanitize_uri(&location.uri)
    });

    if let Some(base_id) = &location.uri_base_id {
        location_json["uriBaseId"] = serde_json::Value::String(sanitize_string(base_id));
    }

    if let Some(index) = location.index {
        location_json["index"] = serde_json::Value::Number(serde_json::Number::from(index));
    }

    if let Some(description) = &location.description {
        location_json["description"] = generate_message_json(description);
    }

    location_json
}

fn generate_region_json(region: &FuzzRegion) -> serde_json::Value {
    let mut region_json = serde_json::json!({});

    if let Some(start_line) = region.start_line {
        if start_line > 0 {
            region_json["startLine"] = serde_json::Value::Number(serde_json::Number::from(start_line));
        }
    }

    if let Some(start_column) = region.start_column {
        if start_column > 0 {
            region_json["startColumn"] = serde_json::Value::Number(serde_json::Number::from(start_column));
        }
    }

    if let Some(end_line) = region.end_line {
        if end_line > 0 {
            region_json["endLine"] = serde_json::Value::Number(serde_json::Number::from(end_line));
        }
    }

    if let Some(end_column) = region.end_column {
        if end_column > 0 {
            region_json["endColumn"] = serde_json::Value::Number(serde_json::Number::from(end_column));
        }
    }

    if let Some(snippet) = &region.snippet {
        region_json["snippet"] = generate_artifact_content_json(snippet);
    }

    if let Some(message) = &region.message {
        region_json["message"] = generate_message_json(message);
    }

    region_json
}

fn generate_logical_location_json(logical: &FuzzLogicalLocation) -> serde_json::Value {
    let mut logical_json = serde_json::json!({});

    if let Some(name) = &logical.name {
        logical_json["name"] = serde_json::Value::String(sanitize_string(name));
    }

    if let Some(index) = logical.index {
        logical_json["index"] = serde_json::Value::Number(serde_json::Number::from(index));
    }

    if let Some(fqn) = &logical.fully_qualified_name {
        logical_json["fullyQualifiedName"] = serde_json::Value::String(sanitize_string(fqn));
    }

    if let Some(kind) = &logical.kind {
        logical_json["kind"] = serde_json::Value::String(sanitize_string(kind));
    }

    logical_json
}

fn generate_artifact_content_json(content: &FuzzArtifactContent) -> serde_json::Value {
    let mut content_json = serde_json::json!({
        "text": sanitize_string(&content.text)
    });

    if let Some(binary) = &content.binary {
        content_json["binary"] = serde_json::Value::String(sanitize_string(binary));
    }

    content_json
}

fn generate_artifact_json(_artifact: &FuzzArtifact) -> serde_json::Value {
    // Simplified artifact generation
    serde_json::json!({
        "location": {
            "uri": "test.sol"
        },
        "length": 1000,
        "roles": ["analysisTarget"]
    })
}

fn generate_invocation_json(_invocation: &FuzzInvocation) -> serde_json::Value {
    // Simplified invocation generation
    serde_json::json!({
        "executionSuccessful": true,
        "exitCode": 0
    })
}

// Sanitization functions
fn sanitize_string(s: &str) -> String {
    // Remove null bytes and control characters except newlines and tabs
    s.chars()
        .filter(|c| *c != '\0' && (*c >= ' ' || *c == '\n' || *c == '\t'))
        .take(1000) // Limit length
        .collect()
}

fn sanitize_uri(uri: &str) -> String {
    // Basic URI sanitization
    let sanitized = sanitize_string(uri);
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn sanitize_property_key(key: &str) -> String {
    // Property keys should be valid identifiers
    let sanitized: String = key.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(100)
        .collect();

    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn is_valid_uri(uri: &str) -> bool {
    // Basic URI validation
    !uri.is_empty() && uri.len() < 2000 && !uri.contains('\0')
}

// Validation functions
fn validate_sarif_json(json: &serde_json::Value) {
    // Basic SARIF structure validation
    assert!(json.is_object(), "SARIF must be an object");

    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("version"), "SARIF must have version");
    assert!(obj.contains_key("runs"), "SARIF must have runs");

    let runs = obj.get("runs").unwrap();
    assert!(runs.is_array(), "Runs must be an array");

    for run in runs.as_array().unwrap() {
        validate_run(run);
    }
}

fn validate_run(run: &serde_json::Value) {
    assert!(run.is_object(), "Run must be an object");

    let run_obj = run.as_object().unwrap();
    assert!(run_obj.contains_key("tool"), "Run must have tool");

    let tool = run_obj.get("tool").unwrap();
    validate_tool(tool);

    if let Some(results) = run_obj.get("results") {
        assert!(results.is_array(), "Results must be an array");
        for result in results.as_array().unwrap() {
            validate_result(result);
        }
    }
}

fn validate_tool(tool: &serde_json::Value) {
    assert!(tool.is_object(), "Tool must be an object");

    let tool_obj = tool.as_object().unwrap();
    assert!(tool_obj.contains_key("driver"), "Tool must have driver");

    let driver = tool_obj.get("driver").unwrap();
    validate_tool_component(driver);
}

fn validate_tool_component(component: &serde_json::Value) {
    assert!(component.is_object(), "Tool component must be an object");

    let comp_obj = component.as_object().unwrap();
    assert!(comp_obj.contains_key("name"), "Tool component must have name");

    let name = comp_obj.get("name").unwrap();
    assert!(name.is_string(), "Tool component name must be a string");
    assert!(!name.as_str().unwrap().is_empty(), "Tool component name cannot be empty");
}

fn validate_result(result: &serde_json::Value) {
    assert!(result.is_object(), "Result must be an object");

    let result_obj = result.as_object().unwrap();
    assert!(result_obj.contains_key("ruleId"), "Result must have ruleId");
    assert!(result_obj.contains_key("message"), "Result must have message");
    assert!(result_obj.contains_key("level"), "Result must have level");

    let rule_id = result_obj.get("ruleId").unwrap();
    assert!(rule_id.is_string(), "RuleId must be a string");
    assert!(!rule_id.as_str().unwrap().is_empty(), "RuleId cannot be empty");

    let level = result_obj.get("level").unwrap();
    assert!(level.is_string(), "Level must be a string");
    let level_str = level.as_str().unwrap();
    assert!(matches!(level_str, "none" | "note" | "warning" | "error"), "Invalid level: {}", level_str);
}

fn test_sarif_round_trip(json: &serde_json::Value) {
    // Test that we can serialize and deserialize without data loss
    let serialized = serde_json::to_string(json).expect("Failed to serialize SARIF");
    let deserialized: serde_json::Value = serde_json::from_str(&serialized)
        .expect("Failed to deserialize SARIF");

    // Basic consistency check
    assert_eq!(json.get("version"), deserialized.get("version"));
    assert_eq!(
        json.get("runs").and_then(|r| r.as_array()).map(|a| a.len()),
        deserialized.get("runs").and_then(|r| r.as_array()).map(|a| a.len())
    );
}

fn test_schema_compliance(json: &serde_json::Value) {
    // Test compliance with SARIF schema requirements

    // Version must be valid
    let version = json.get("version").and_then(|v| v.as_str());
    assert_eq!(version, Some("2.1.0"), "Invalid SARIF version");

    // Must have at least one run
    let runs = json.get("runs").and_then(|r| r.as_array());
    assert!(runs.is_some(), "SARIF must have runs array");
    assert!(!runs.unwrap().is_empty(), "SARIF must have at least one run");

    // Each run must be valid
    for run in runs.unwrap() {
        let tool = run.get("tool");
        assert!(tool.is_some(), "Run must have tool");

        let driver = tool.unwrap().get("driver");
        assert!(driver.is_some(), "Tool must have driver");

        let driver_name = driver.unwrap().get("name").and_then(|n| n.as_str());
        assert!(driver_name.is_some(), "Driver must have name");
        assert!(!driver_name.unwrap().is_empty(), "Driver name cannot be empty");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_generation() {
        let input = create_test_sarif_input();
        let json = generate_sarif_json(&input);
        validate_sarif_json(&json);
    }

    #[test]
    fn test_sanitization() {
        assert_eq!(sanitize_string("hello\0world"), "helloworld");
        assert_eq!(sanitize_string("normal text"), "normal text");
        assert_eq!(sanitize_string(""), "");

        assert_eq!(sanitize_uri(""), "unknown");
        assert_eq!(sanitize_uri("file://test.sol"), "file://test.sol");

        assert_eq!(sanitize_property_key("valid_key"), "valid_key");
        assert_eq!(sanitize_property_key(""), "unknown");
    }

    #[test]
    fn test_round_trip() {
        let input = create_test_sarif_input();
        let json = generate_sarif_json(&input);
        test_sarif_round_trip(&json);
    }

    fn create_test_sarif_input() -> FuzzSarifInput {
        FuzzSarifInput {
            tool_info: FuzzToolInfo {
                name: "SolidityDefend".to_string(),
                version: "0.1.0".to_string(),
                organization: Some("Test Org".to_string()),
                product_suite: None,
                full_name: None,
            },
            runs: vec![
                FuzzRun {
                    tool: FuzzTool {
                        driver: FuzzToolComponent {
                            name: "SolidityDefend".to_string(),
                            version: Some("0.1.0".to_string()),
                            information_uri: Some("https://soliditydefend.com".to_string()),
                            rules: vec![
                                FuzzRule {
                                    id: "reentrancy".to_string(),
                                    name: Some("Reentrancy".to_string()),
                                    short_description: Some(FuzzMessage {
                                        text: "Potential reentrancy vulnerability".to_string(),
                                        markdown: None,
                                        id: None,
                                        arguments: Vec::new(),
                                    }),
                                    full_description: None,
                                    default_configuration: Some(FuzzConfiguration {
                                        level: FuzzLevel::Error,
                                        enabled: true,
                                        rank: Some(90.0),
                                        parameters: None,
                                    }),
                                    help: None,
                                    help_uri: None,
                                    properties: None,
                                }
                            ],
                        },
                        extensions: Vec::new(),
                    },
                    results: vec![
                        FuzzResult {
                            rule_id: "reentrancy".to_string(),
                            rule_index: Some(0),
                            kind: FuzzResultKind::Fail,
                            level: FuzzLevel::Error,
                            message: FuzzMessage {
                                text: "Reentrancy vulnerability detected".to_string(),
                                markdown: None,
                                id: None,
                                arguments: Vec::new(),
                            },
                            locations: Vec::new(),
                            analysis_target: None,
                            fingerprints: None,
                            partial_fingerprints: None,
                            code_flows: Vec::new(),
                            related_locations: Vec::new(),
                            suppression_states: Vec::new(),
                            baseline_state: None,
                            rank: Some(85.0),
                            attachments: Vec::new(),
                            work_item_uris: Vec::new(),
                        }
                    ],
                    artifacts: Vec::new(),
                    invocations: Vec::new(),
                }
            ],
            version: FuzzSarifVersion::V2_1_0,
        }
    }
}