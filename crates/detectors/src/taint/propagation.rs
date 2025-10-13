use crate::taint::{PropagationStep, PropagationType, SourceLocation, TaintType, TaintedData};

/// Taint propagation rules and logic
pub struct TaintPropagator {
    rules: Vec<PropagationRule>,
}

/// Rule for taint propagation
#[derive(Debug, Clone)]
pub struct PropagationRule {
    pub operation: String,
    pub source_taint_types: Vec<TaintType>,
    pub propagation_factor: f64,
    pub result_taint_type: TaintType,
}

impl TaintPropagator {
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    /// Add a custom propagation rule
    pub fn add_rule(&mut self, rule: PropagationRule) {
        self.rules.push(rule);
    }

    /// Propagate taint according to operation
    pub fn propagate(
        &self,
        source_taint: &TaintedData,
        operation: &str,
        target_location: &SourceLocation,
    ) -> Option<TaintedData> {
        // Find matching propagation rule
        let rule = self.find_matching_rule(operation, &source_taint.taint_type)?;

        // Calculate new confidence
        let new_confidence = source_taint.confidence * rule.propagation_factor;

        // Create propagation step
        let step = PropagationStep {
            from_location: source_taint.current_location.clone(),
            to_location: target_location.clone(),
            operation: operation.to_string(),
            propagation_type: self.operation_to_propagation_type(operation),
        };

        // Create new tainted data
        let mut new_path = source_taint.propagation_path.clone();
        new_path.push(step);

        Some(TaintedData {
            source: source_taint.source.clone(),
            current_location: target_location.clone(),
            taint_type: rule.result_taint_type.clone(),
            confidence: new_confidence,
            propagation_path: new_path,
        })
    }

    /// Default propagation rules
    fn default_rules() -> Vec<PropagationRule> {
        vec![
            // Direct assignment
            PropagationRule {
                operation: "=".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 1.0,
                result_taint_type: TaintType::UserInput,
            },
            // Arithmetic operations
            PropagationRule {
                operation: "+".to_string(),
                source_taint_types: vec![TaintType::UserInput, TaintType::ExternalCall],
                propagation_factor: 0.9,
                result_taint_type: TaintType::UserInput,
            },
            PropagationRule {
                operation: "-".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 0.9,
                result_taint_type: TaintType::UserInput,
            },
            PropagationRule {
                operation: "*".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 0.8,
                result_taint_type: TaintType::UserInput,
            },
            PropagationRule {
                operation: "/".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 0.8,
                result_taint_type: TaintType::UserInput,
            },
            // Comparison operations (reduce taint)
            PropagationRule {
                operation: "==".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 0.3,
                result_taint_type: TaintType::UserInput,
            },
            PropagationRule {
                operation: "!=".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 0.3,
                result_taint_type: TaintType::UserInput,
            },
            // Logical operations
            PropagationRule {
                operation: "&&".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 0.5,
                result_taint_type: TaintType::UserInput,
            },
            PropagationRule {
                operation: "||".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 0.5,
                result_taint_type: TaintType::UserInput,
            },
            // Hashing (significantly reduces taint)
            PropagationRule {
                operation: "keccak256".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 0.1,
                result_taint_type: TaintType::UserInput,
            },
            // Function calls (context-dependent)
            PropagationRule {
                operation: "call".to_string(),
                source_taint_types: vec![TaintType::UserInput],
                propagation_factor: 0.7,
                result_taint_type: TaintType::ExternalCall,
            },
        ]
    }

    fn find_matching_rule(
        &self,
        operation: &str,
        taint_type: &TaintType,
    ) -> Option<&PropagationRule> {
        self.rules.iter().find(|rule| {
            rule.operation == operation && rule.source_taint_types.contains(taint_type)
        })
    }

    fn operation_to_propagation_type(&self, operation: &str) -> PropagationType {
        match operation {
            "=" => PropagationType::Direct,
            "+" | "-" | "*" | "/" | "%" => PropagationType::Arithmetic,
            "==" | "!=" | "<" | ">" | "<=" | ">=" => PropagationType::Comparison,
            "call" | "delegatecall" | "staticcall" => PropagationType::ExternalCall,
            "return" => PropagationType::Return,
            _ => PropagationType::Direct,
        }
    }
}

impl Default for TaintPropagator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::TaintSource;

    #[test]
    fn test_propagator_creation() {
        let propagator = TaintPropagator::new();
        assert!(!propagator.rules.is_empty());
    }

    #[test]
    fn test_direct_assignment_propagation() {
        let propagator = TaintPropagator::new();

        let source_taint = TaintedData {
            source: TaintSource::MessageSender,
            current_location: SourceLocation {
                file: "test.sol".to_string(),
                line: 1,
                column: 1,
                function: "test".to_string(),
            },
            taint_type: TaintType::UserInput,
            confidence: 1.0,
            propagation_path: Vec::new(),
        };

        let target_location = SourceLocation {
            file: "test.sol".to_string(),
            line: 2,
            column: 1,
            function: "test".to_string(),
        };

        let result = propagator.propagate(&source_taint, "=", &target_location);
        assert!(result.is_some());

        let propagated = result.unwrap();
        assert_eq!(propagated.confidence, 1.0);
        assert_eq!(propagated.propagation_path.len(), 1);
    }

    #[test]
    fn test_arithmetic_operation_propagation() {
        let propagator = TaintPropagator::new();

        let source_taint = TaintedData {
            source: TaintSource::MessageSender,
            current_location: SourceLocation {
                file: "test.sol".to_string(),
                line: 1,
                column: 1,
                function: "test".to_string(),
            },
            taint_type: TaintType::UserInput,
            confidence: 1.0,
            propagation_path: Vec::new(),
        };

        let target_location = SourceLocation {
            file: "test.sol".to_string(),
            line: 2,
            column: 1,
            function: "test".to_string(),
        };

        let result = propagator.propagate(&source_taint, "+", &target_location);
        assert!(result.is_some());

        let propagated = result.unwrap();
        assert_eq!(propagated.confidence, 0.9); // Reduced confidence for arithmetic
    }

    #[test]
    fn test_hashing_operation_propagation() {
        let propagator = TaintPropagator::new();

        let source_taint = TaintedData {
            source: TaintSource::MessageSender,
            current_location: SourceLocation {
                file: "test.sol".to_string(),
                line: 1,
                column: 1,
                function: "test".to_string(),
            },
            taint_type: TaintType::UserInput,
            confidence: 1.0,
            propagation_path: Vec::new(),
        };

        let target_location = SourceLocation {
            file: "test.sol".to_string(),
            line: 2,
            column: 1,
            function: "test".to_string(),
        };

        let result = propagator.propagate(&source_taint, "keccak256", &target_location);
        assert!(result.is_some());

        let propagated = result.unwrap();
        assert_eq!(propagated.confidence, 0.1); // Significantly reduced for hashing
    }
}
