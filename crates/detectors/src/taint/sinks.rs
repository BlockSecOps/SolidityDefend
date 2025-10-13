/// Taint sinks - potential targets for malicious data
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum TaintSink {
    ExternalCall,      // External contract calls
    SelfDestruct,      // selfdestruct()
    EtherTransfer,     // transfer(), send()
    TokenApproval,     // approve()
    StateModification, // State variable assignments
    StorageWrite,      // Storage writes
    EventEmission,     // Event emissions
    Custom(String),    // Custom taint sink
}

/// Detector for taint sinks
pub struct TaintSinkDetector;

impl TaintSinkDetector {
    pub fn detect_sinks(code: &str) -> Vec<(usize, TaintSink)> {
        let mut sinks = Vec::new();
        let lines: Vec<&str> = code.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_number = line_idx + 1;

            // Check for various taint sinks
            if line.contains("call(")
                || line.contains("delegatecall(")
                || line.contains("staticcall(")
            {
                sinks.push((line_number, TaintSink::ExternalCall));
            }
            if line.contains("selfdestruct") {
                sinks.push((line_number, TaintSink::SelfDestruct));
            }
            if line.contains("transfer(") || line.contains("send(") {
                sinks.push((line_number, TaintSink::EtherTransfer));
            }
            if line.contains("approve(") {
                sinks.push((line_number, TaintSink::TokenApproval));
            }
            if line.contains("=") && !line.contains("==") && !line.contains("!=") {
                sinks.push((line_number, TaintSink::StateModification));
            }
            if line.contains("emit ") {
                sinks.push((line_number, TaintSink::EventEmission));
            }
        }

        sinks
    }
}
