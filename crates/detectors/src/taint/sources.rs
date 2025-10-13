/// Taint sources - origins of untrusted data
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum TaintSource {
    MessageSender,     // msg.sender
    TransactionOrigin, // tx.origin
    MessageData,       // msg.data
    MessageValue,      // msg.value
    BlockTimestamp,    // block.timestamp, now
    BlockNumber,       // block.number
    BlockHash,         // blockhash()
    ExternalCall,      // External contract calls
    Oracle,            // Oracle data feeds
    UserInput,         // Function parameters
    Storage,           // Storage reads
    Custom(String),    // Custom taint source
}

/// Detector for taint sources
pub struct TaintSourceDetector;

impl TaintSourceDetector {
    pub fn detect_sources(code: &str) -> Vec<(usize, TaintSource)> {
        let mut sources = Vec::new();
        let lines: Vec<&str> = code.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_number = line_idx + 1;

            // Check for various taint sources
            if line.contains("msg.sender") {
                sources.push((line_number, TaintSource::MessageSender));
            }
            if line.contains("tx.origin") {
                sources.push((line_number, TaintSource::TransactionOrigin));
            }
            if line.contains("msg.data") {
                sources.push((line_number, TaintSource::MessageData));
            }
            if line.contains("msg.value") {
                sources.push((line_number, TaintSource::MessageValue));
            }
            if line.contains("block.timestamp") || line.contains("now") {
                sources.push((line_number, TaintSource::BlockTimestamp));
            }
            if line.contains("block.number") {
                sources.push((line_number, TaintSource::BlockNumber));
            }
            if line.contains("blockhash") {
                sources.push((line_number, TaintSource::BlockHash));
            }
            if line.contains("call(")
                || line.contains("delegatecall(")
                || line.contains("staticcall(")
            {
                sources.push((line_number, TaintSource::ExternalCall));
            }
        }

        sources
    }
}
