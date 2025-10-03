use crate::taint::{
    TaintedData, TaintType, TaintAnalysisResult, TaintFinding, TaintAnalysisConfig,
    DataFlowGraph, TaintStatistics, SourceLocation, PropagationStep, PropagationType,
    TaintUtils, DataFlowNode, DataFlowEdge, DataFlowNodeType
};
use crate::taint::{TaintSource, TaintSink, TaintSanitizer};
use crate::types::{AnalysisContext, Severity};
use std::collections::{HashMap, HashSet, VecDeque};

/// Advanced taint analyzer for data flow tracking
pub struct TaintAnalyzer {
    config: TaintAnalysisConfig,
    taint_sources: HashMap<SourceLocation, TaintSource>,
    taint_sinks: HashMap<SourceLocation, TaintSink>,
    sanitizers: HashMap<SourceLocation, TaintSanitizer>,
}

impl TaintAnalyzer {
    pub fn new(config: TaintAnalysisConfig) -> Self {
        Self {
            config,
            taint_sources: HashMap::new(),
            taint_sinks: HashMap::new(),
            sanitizers: HashMap::new(),
        }
    }

    /// Run comprehensive taint analysis on a contract
    pub fn analyze(&mut self, context: &AnalysisContext) -> TaintAnalysisResult {
        // Step 1: Identify taint sources, sinks, and sanitizers
        self.identify_taint_locations(context);

        // Step 2: Build initial data flow graph
        let mut data_flow_graph = self.build_data_flow_graph(context);

        // Step 3: Propagate taint through the graph
        let taint_map = self.propagate_taint(context, &mut data_flow_graph);

        // Step 4: Detect vulnerable paths
        let findings = self.detect_vulnerable_paths(context, &taint_map);

        // Step 5: Calculate statistics
        let statistics = self.calculate_statistics(&findings, &taint_map);

        TaintAnalysisResult {
            findings,
            taint_map,
            data_flow_graph,
            statistics,
        }
    }

    /// Identify taint sources, sinks, and sanitizers in the code
    fn identify_taint_locations(&mut self, context: &AnalysisContext) {
        let lines: Vec<&str> = context.source.lines().collect();

        for (line_idx, line_content) in lines.iter().enumerate() {
            let line_number = line_idx + 1;

            // Create location for this line
            let location = SourceLocation {
                file: context.file_path.clone(),
                line: line_number,
                column: 0, // Simplified - would need more detailed parsing
                function: self.get_current_function(context, line_number),
            };

            // Check for taint sources
            if let Some(source) = TaintUtils::is_taint_source(&location, &context.source) {
                self.taint_sources.insert(location.clone(), source);
            }

            // Check for taint sinks
            if let Some(sink) = TaintUtils::is_taint_sink(&location, &context.source) {
                self.taint_sinks.insert(location.clone(), sink);
            }

            // Check for sanitizers
            if let Some(sanitizer) = TaintUtils::is_sanitizer(&location, &context.source) {
                self.sanitizers.insert(location.clone(), sanitizer);
            }

            // Check for custom patterns
            self.check_custom_patterns(&location, line_content);
        }
    }

    /// Build initial data flow graph
    fn build_data_flow_graph(&self, context: &AnalysisContext) -> DataFlowGraph {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Add nodes for sources
        for (location, source) in &self.taint_sources {
            nodes.push(DataFlowNode {
                id: format!("source_{}_{}_{}", location.file, location.line, location.column),
                location: location.clone(),
                node_type: DataFlowNodeType::Source,
                taint_level: 1.0,
            });
        }

        // Add nodes for sinks
        for (location, sink) in &self.taint_sinks {
            nodes.push(DataFlowNode {
                id: format!("sink_{}_{}_{}", location.file, location.line, location.column),
                location: location.clone(),
                node_type: DataFlowNodeType::Sink,
                taint_level: 0.0,
            });
        }

        // Add nodes for sanitizers
        for (location, sanitizer) in &self.sanitizers {
            nodes.push(DataFlowNode {
                id: format!("sanitizer_{}_{}_{}", location.file, location.line, location.column),
                location: location.clone(),
                node_type: DataFlowNodeType::Sanitizer,
                taint_level: 0.0,
            });
        }

        // Analyze control flow and add edges
        self.analyze_control_flow(context, &mut nodes, &mut edges);

        DataFlowGraph { nodes, edges }
    }

    /// Propagate taint through the data flow graph
    fn propagate_taint(
        &self,
        context: &AnalysisContext,
        graph: &mut DataFlowGraph
    ) -> HashMap<SourceLocation, Vec<TaintedData>> {
        let mut taint_map = HashMap::new();
        let mut work_queue = VecDeque::new();

        // Initialize work queue with taint sources
        for (location, source) in &self.taint_sources {
            let tainted_data = TaintedData {
                source: source.clone(),
                current_location: location.clone(),
                taint_type: self.map_source_to_taint_type(source),
                confidence: 1.0,
                propagation_path: Vec::new(),
            };

            taint_map.entry(location.clone()).or_insert_with(Vec::new).push(tainted_data.clone());
            work_queue.push_back(tainted_data);
        }

        // Propagate taint using worklist algorithm
        while let Some(current_taint) = work_queue.pop_front() {
            if current_taint.propagation_path.len() >= self.config.max_propagation_depth {
                continue;
            }

            // Find outgoing edges from current location
            let outgoing_edges = self.find_outgoing_edges(graph, &current_taint.current_location);

            for edge in outgoing_edges {
                let target_node = self.find_node_by_id(graph, &edge.to);
                if let Some(target) = target_node {
                    let propagated_taint = self.propagate_taint_along_edge(
                        &current_taint,
                        edge,
                        &target.location
                    );

                    if propagated_taint.confidence >= self.config.min_confidence_threshold {
                        // Check for sanitization
                        if !self.is_sanitized(&propagated_taint, &target.location) {
                            taint_map.entry(target.location.clone())
                                .or_insert_with(Vec::new)
                                .push(propagated_taint.clone());
                            work_queue.push_back(propagated_taint);
                        }
                    }
                }
            }
        }

        taint_map
    }

    /// Detect vulnerable paths from sources to sinks
    fn detect_vulnerable_paths(
        &self,
        context: &AnalysisContext,
        taint_map: &HashMap<SourceLocation, Vec<TaintedData>>
    ) -> Vec<TaintFinding> {
        let mut findings = Vec::new();

        for (sink_location, sink) in &self.taint_sinks {
            if let Some(tainted_data_list) = taint_map.get(sink_location) {
                for tainted_data in tainted_data_list {
                    let vulnerability_type = self.classify_vulnerability(&tainted_data.taint_type, sink);
                    let severity = self.assess_severity(&tainted_data.taint_type, sink);

                    let finding = TaintFinding {
                        source: tainted_data.source.clone(),
                        sink: sink.clone(),
                        taint_path: tainted_data.propagation_path.clone(),
                        severity,
                        vulnerability_type: vulnerability_type.clone(),
                        description: self.generate_finding_description(
                            &tainted_data.source,
                            sink,
                            &vulnerability_type
                        ),
                        confidence: tainted_data.confidence,
                        false_positive_likelihood: TaintUtils::estimate_false_positive_likelihood(
                            &tainted_data.propagation_path,
                            &self.get_sanitizers_in_path(&tainted_data.propagation_path)
                        ),
                    };

                    findings.push(finding);
                }
            }
        }

        // Sort findings by severity and confidence
        findings.sort_by(|a, b| {
            let severity_cmp = self.severity_to_numeric(&a.severity)
                .cmp(&self.severity_to_numeric(&b.severity));
            if severity_cmp == std::cmp::Ordering::Equal {
                b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
            } else {
                severity_cmp
            }
        });

        findings
    }

    /// Calculate analysis statistics
    fn calculate_statistics(
        &self,
        findings: &[TaintFinding],
        taint_map: &HashMap<SourceLocation, Vec<TaintedData>>
    ) -> TaintStatistics {
        let total_sources = self.taint_sources.len();
        let total_sinks = self.taint_sinks.len();
        let total_paths = taint_map.values().map(|v| v.len()).sum();
        let vulnerable_paths = findings.len();

        let sanitized_paths = taint_map.values()
            .flatten()
            .filter(|data| self.path_has_sanitizers(&data.propagation_path))
            .count();

        let path_lengths: Vec<usize> = taint_map.values()
            .flatten()
            .map(|data| data.propagation_path.len())
            .collect();

        let max_path_length = path_lengths.iter().max().copied().unwrap_or(0);
        let avg_path_length = if !path_lengths.is_empty() {
            path_lengths.iter().sum::<usize>() as f64 / path_lengths.len() as f64
        } else {
            0.0
        };

        let taint_coverage = if total_sinks > 0 {
            vulnerable_paths as f64 / total_sinks as f64
        } else {
            0.0
        };

        TaintStatistics {
            total_sources,
            total_sinks,
            total_paths,
            vulnerable_paths,
            sanitized_paths,
            max_path_length,
            avg_path_length,
            taint_coverage,
        }
    }

    // Helper methods

    fn get_current_function(&self, context: &AnalysisContext, line_number: usize) -> String {
        // Simplified - would need proper AST parsing
        for func in &context.contract.functions {
            if func.location.start().line() <= line_number {
                return func.name.to_string();
            }
        }
        "unknown".to_string()
    }

    fn check_custom_patterns(&mut self, location: &SourceLocation, line_content: &str) {
        // Check custom sources
        for custom_source in &self.config.custom_sources {
            if line_content.contains(custom_source) {
                self.taint_sources.insert(
                    location.clone(),
                    TaintSource::Custom(custom_source.clone())
                );
            }
        }

        // Check custom sinks
        for custom_sink in &self.config.custom_sinks {
            if line_content.contains(custom_sink) {
                self.taint_sinks.insert(
                    location.clone(),
                    TaintSink::Custom(custom_sink.clone())
                );
            }
        }

        // Check custom sanitizers
        for custom_sanitizer in &self.config.custom_sanitizers {
            if line_content.contains(custom_sanitizer) {
                self.sanitizers.insert(
                    location.clone(),
                    TaintSanitizer::Custom(custom_sanitizer.clone())
                );
            }
        }
    }

    fn analyze_control_flow(
        &self,
        context: &AnalysisContext,
        nodes: &mut Vec<DataFlowNode>,
        edges: &mut Vec<DataFlowEdge>
    ) {
        // Simplified control flow analysis
        // In a real implementation, this would use proper CFG analysis

        let lines: Vec<&str> = context.source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                // Add sequential flow edge
                let from_id = format!("line_{}", i);
                let to_id = format!("line_{}", i + 1);

                edges.push(DataFlowEdge {
                    from: from_id,
                    to: to_id,
                    edge_type: PropagationType::Direct,
                    taint_preserved: 1.0,
                });
            }

            // Add propagation nodes for assignments
            if line.contains("=") && !line.contains("==") {
                let location = SourceLocation {
                    file: context.file_path.clone(),
                    line: i + 1,
                    column: 0,
                    function: self.get_current_function(context, i + 1),
                };

                nodes.push(DataFlowNode {
                    id: format!("propagation_{}_{}", i + 1, 0),
                    location,
                    node_type: DataFlowNodeType::Propagation,
                    taint_level: 0.0,
                });
            }
        }
    }

    fn find_outgoing_edges<'a>(&self, graph: &'a DataFlowGraph, location: &SourceLocation) -> Vec<&'a DataFlowEdge> {
        let node_id = format!("source_{}_{}_{}", location.file, location.line, location.column);
        graph.edges.iter()
            .filter(|edge| edge.from == node_id)
            .collect()
    }

    fn find_node_by_id<'a>(&self, graph: &'a DataFlowGraph, id: &str) -> Option<&'a DataFlowNode> {
        graph.nodes.iter().find(|node| node.id == id)
    }

    fn propagate_taint_along_edge(
        &self,
        current_taint: &TaintedData,
        edge: &DataFlowEdge,
        target_location: &SourceLocation
    ) -> TaintedData {
        let mut propagated = current_taint.clone();
        propagated.current_location = target_location.clone();
        propagated.confidence *= edge.taint_preserved;

        // Add propagation step
        let step = PropagationStep {
            from_location: current_taint.current_location.clone(),
            to_location: target_location.clone(),
            operation: format!("{:?}", edge.edge_type),
            propagation_type: edge.edge_type.clone(),
        };
        propagated.propagation_path.push(step);

        propagated
    }

    fn is_sanitized(&self, tainted_data: &TaintedData, location: &SourceLocation) -> bool {
        self.sanitizers.contains_key(location)
    }

    fn map_source_to_taint_type(&self, source: &TaintSource) -> TaintType {
        match source {
            TaintSource::MessageSender | TaintSource::TransactionOrigin => TaintType::UserInput,
            TaintSource::MessageData | TaintSource::MessageValue => TaintType::UserInput,
            TaintSource::BlockTimestamp | TaintSource::BlockNumber => TaintType::TimeDependent,
            TaintSource::BlockHash => TaintType::TimeDependent,
            TaintSource::ExternalCall => TaintType::ExternalCall,
            TaintSource::Oracle => TaintType::ExternalData,
            TaintSource::UserInput => TaintType::UserInput,
            TaintSource::Storage => TaintType::UntrustedStorage,
            TaintSource::Custom(name) => TaintType::Custom(name.clone()),
        }
    }

    fn classify_vulnerability(&self, taint_type: &TaintType, sink: &TaintSink) -> String {
        match (taint_type, sink) {
            (TaintType::UserInput, TaintSink::ExternalCall) => "Unvalidated External Call".to_string(),
            (TaintType::UserInput, TaintSink::StateModification) => "Unvalidated State Change".to_string(),
            (TaintType::ExternalCall, TaintSink::StateModification) => "External Data State Change".to_string(),
            (TaintType::TimeDependent, TaintSink::StateModification) => "Time-dependent State Change".to_string(),
            (TaintType::UserInput, TaintSink::EtherTransfer) => "Unvalidated Ether Transfer".to_string(),
            _ => "Data Flow Vulnerability".to_string(),
        }
    }

    fn assess_severity(&self, taint_type: &TaintType, sink: &TaintSink) -> Severity {
        match (taint_type, sink) {
            (TaintType::UserInput, TaintSink::SelfDestruct) => Severity::Critical,
            (TaintType::UserInput, TaintSink::ExternalCall) => Severity::High,
            (TaintType::ExternalCall, TaintSink::StateModification) => Severity::High,
            (TaintType::UserInput, TaintSink::EtherTransfer) => Severity::Medium,
            (TaintType::TimeDependent, _) => Severity::Medium,
            _ => Severity::Low,
        }
    }

    fn generate_finding_description(
        &self,
        source: &TaintSource,
        sink: &TaintSink,
        vulnerability_type: &str
    ) -> String {
        format!(
            "{}: Untrusted data from {:?} flows to {:?} without proper validation. \
            This could allow attackers to manipulate critical contract behavior.",
            vulnerability_type, source, sink
        )
    }

    fn get_sanitizers_in_path(&self, path: &[PropagationStep]) -> Vec<TaintSanitizer> {
        let mut sanitizers = Vec::new();
        for step in path {
            if let Some(sanitizer) = self.sanitizers.get(&step.to_location) {
                sanitizers.push(sanitizer.clone());
            }
        }
        sanitizers
    }

    fn path_has_sanitizers(&self, path: &[PropagationStep]) -> bool {
        path.iter().any(|step| self.sanitizers.contains_key(&step.to_location))
    }

    fn severity_to_numeric(&self, severity: &Severity) -> u8 {
        match severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Contract, Function};

    fn create_mock_context() -> AnalysisContext<'static> {
        AnalysisContext {
            contract: &Contract {
                name: "TestContract".to_string(),
                functions: Vec::new(),
                state_variables: Vec::new(),
                events: Vec::new(),
                modifiers: Vec::new(),
            },
            symbols: HashMap::new(),
            source_code: "function test() { address sender = msg.sender; target.call(); }".to_string(),
            file_path: "test.sol".to_string(),
        }
    }

    #[test]
    fn test_analyzer_creation() {
        let config = TaintAnalysisConfig::default();
        let analyzer = TaintAnalyzer::new(config);
        assert_eq!(analyzer.taint_sources.len(), 0);
        assert_eq!(analyzer.taint_sinks.len(), 0);
    }

    #[test]
    fn test_source_identification() {
        let config = TaintAnalysisConfig::default();
        let mut analyzer = TaintAnalyzer::new(config);
        let context = create_mock_context();

        analyzer.identify_taint_locations(&context);

        // Should find msg.sender as source and call() as sink
        assert!(!analyzer.taint_sources.is_empty());
        assert!(!analyzer.taint_sinks.is_empty());
    }

    #[test]
    fn test_vulnerability_classification() {
        let config = TaintAnalysisConfig::default();
        let analyzer = TaintAnalyzer::new(config);

        let vulnerability = analyzer.classify_vulnerability(
            &TaintType::UserInput,
            &TaintSink::ExternalCall
        );
        assert_eq!(vulnerability, "Unvalidated External Call");
    }

    #[test]
    fn test_severity_assessment() {
        let config = TaintAnalysisConfig::default();
        let analyzer = TaintAnalyzer::new(config);

        let severity = analyzer.assess_severity(&TaintType::UserInput, &TaintSink::SelfDestruct);
        assert_eq!(severity, Severity::Critical);

        let severity = analyzer.assess_severity(&TaintType::UserInput, &TaintSink::ExternalCall);
        assert_eq!(severity, Severity::High);
    }
}