use ast::{AstArena, SourceFile, SourceLocation, Position, Contract, Function, Identifier, ContractType};
use crate::error::{ParseError, ParseResult, ParseErrors};
use solang_parser::{pt, parse, diagnostics};

/// Arena-based parser for converting solang AST to our arena-allocated AST
pub struct ArenaParser<'arena> {
    arena: &'arena AstArena,
}

impl<'arena> ArenaParser<'arena> {
    /// Default file ID used by solang-parser for single file parsing
    const DEFAULT_FILE_ID: usize = 0;

    /// Create a new arena parser
    pub fn new(arena: &'arena AstArena) -> Self {
        Self { arena }
    }

    /// Parse Solidity source code into arena-allocated AST
    pub fn parse(&self, source: &str, file_path: &str) -> Result<SourceFile<'arena>, ParseErrors> {
        // Parse using solang-parser
        let (parse_tree, _comments) = match parse(source, Self::DEFAULT_FILE_ID) {
            Ok((tree, comments)) => (tree, comments),
            Err(errors) => {
                let mut parse_errors = ParseErrors::new();
                for error in errors {
                    let location = self.convert_diagnostic_location(&error, file_path);
                    let parse_error = ParseError::syntax_error(format!("{:?}", error), location);
                    parse_errors.push(parse_error);
                }
                return Err(parse_errors);
            }
        };

        // Convert to our AST
        self.convert_source_unit(&parse_tree, source, file_path)
    }

    /// Convert solang source unit to our SourceFile
    fn convert_source_unit(
        &self,
        source_unit: &pt::SourceUnit,
        source: &str,
        file_path: &str,
    ) -> Result<SourceFile<'arena>, ParseErrors> {
        let path_str = self.arena.alloc_str(file_path);
        let content_str = self.arena.alloc_str(source);

        let location = SourceLocation::new(
            file_path.into(),
            Position::start(),
            Position::from_offset(source, source.len()),
        );

        let mut source_file = SourceFile::new(self.arena, path_str, content_str, location);
        let mut errors = ParseErrors::new();

        // Process each part of the source unit
        for part in &source_unit.0 {
            match self.convert_source_unit_part(part, source, file_path) {
                Ok(Some(contract)) => {
                    source_file.contracts.push(contract);
                }
                Ok(None) => {
                    // Non-contract part (pragma, import, etc.) - skip for now
                }
                Err(error) => {
                    errors.push(error);
                }
            }
        }

        if !errors.is_empty() {
            Err(errors)
        } else {
            Ok(source_file)
        }
    }

    /// Convert a source unit part
    fn convert_source_unit_part(
        &self,
        part: &pt::SourceUnitPart,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Option<Contract<'arena>>> {
        match part {
            pt::SourceUnitPart::ContractDefinition(contract) => {
                let converted = self.convert_contract(contract, source, file_path)?;
                Ok(Some(converted))
            }
            pt::SourceUnitPart::PragmaDirective(_) => {
                // TODO: Convert pragma directives
                Ok(None)
            }
            pt::SourceUnitPart::ImportDirective(_) => {
                // TODO: Convert import directives
                Ok(None)
            }
            _ => {
                // Other parts (using for, error definitions, etc.)
                Ok(None)
            }
        }
    }

    /// Convert solang contract to our Contract
    fn convert_contract(
        &self,
        contract: &pt::ContractDefinition,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Contract<'arena>> {
        let name = match &contract.name {
            Some(name) => self.convert_identifier_with_source(name, source, file_path)?,
            None => {
                let location = self.convert_location_with_source(&contract.loc, file_path, Some(source));
                Identifier::new(self.arena.alloc_str(""), location)
            }
        };
        let contract_type = self.convert_contract_type(&contract.ty);
        let location = self.convert_location_with_source(&contract.loc, file_path, Some(source));

        let mut ast_contract = Contract::new(self.arena, name, contract_type, location);

        // Convert contract parts
        for part in &contract.parts {
            match part {
                pt::ContractPart::FunctionDefinition(func) => {
                    match self.convert_function(func, source, file_path) {
                        Ok(function) => ast_contract.functions.push(function),
                        Err(_) => {
                            // Skip invalid functions for now
                        }
                    }
                }
                pt::ContractPart::VariableDefinition(_var) => {
                    // TODO: Convert state variables
                }
                pt::ContractPart::EventDefinition(_event) => {
                    // TODO: Convert events
                }
                // pt::ContractPart::ModifierDefinition(modifier) => {
                //     // TODO: Convert modifiers
                // }
                _ => {
                    // Other parts
                }
            }
        }

        Ok(ast_contract)
    }

    /// Convert contract type
    fn convert_contract_type(&self, ty: &pt::ContractTy) -> ContractType {
        match ty {
            pt::ContractTy::Contract(_) => ContractType::Contract,
            pt::ContractTy::Interface(_) => ContractType::Interface,
            pt::ContractTy::Library(_) => ContractType::Library,
            pt::ContractTy::Abstract(_) => ContractType::Contract, // Treat abstract as contract
        }
    }

    /// Convert solang function to our Function
    fn convert_function(
        &self,
        func: &pt::FunctionDefinition,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Function<'arena>> {
        let name = match &func.name {
            Some(name) => self.convert_identifier_with_source(name, source, file_path)?,
            None => {
                // Anonymous function (constructor, fallback, etc.)
                let location = self.convert_location_with_source(&func.loc, file_path, Some(source));
                Identifier::new(self.arena.alloc_str(""), location)
            }
        };

        let location = self.convert_location_with_source(&func.loc, file_path, Some(source));
        let function = Function::new(self.arena, name, location);

        // TODO: Convert function parameters, body, etc.

        Ok(function)
    }

    /// Convert solang identifier to our Identifier
    #[allow(dead_code)]
    fn convert_identifier(
        &self,
        ident: &pt::Identifier,
        _source: &str,
        file_path: &str,
    ) -> ParseResult<Identifier<'arena>> {
        let name = self.arena.alloc_str(&ident.name);
        let location = self.convert_location(&ident.loc, file_path);
        Ok(Identifier::new(name, location))
    }

    /// Convert solang identifier to our Identifier with source for position calculation
    fn convert_identifier_with_source(
        &self,
        ident: &pt::Identifier,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Identifier<'arena>> {
        let name = self.arena.alloc_str(&ident.name);
        let location = self.convert_location_with_source(&ident.loc, file_path, Some(source));
        Ok(Identifier::new(name, location))
    }

    /// Convert solang location to our SourceLocation
    #[allow(dead_code)]
    fn convert_location(&self, loc: &pt::Loc, file_path: &str) -> SourceLocation {
        self.convert_location_with_source(loc, file_path, None)
    }

    /// Convert solang location to our SourceLocation with optional source for position calculation
    fn convert_location_with_source(&self, loc: &pt::Loc, file_path: &str, source: Option<&str>) -> SourceLocation {
        match loc {
            pt::Loc::File(_file_no, start, end) => {
                // Calculate actual line/column positions from byte offsets if source is available
                let (start_pos, end_pos) = if let Some(src) = source {
                    let start_pos = Position::from_offset(src, *start);
                    let end_pos = Position::from_offset(src, *end);
                    (start_pos, end_pos)
                } else {
                    // Fallback to offset-only positions if source is not available
                    let start_pos = Position::new(1, 1, *start);
                    let end_pos = Position::new(1, 1, *end);
                    (start_pos, end_pos)
                };
                SourceLocation::new(file_path.into(), start_pos, end_pos)
            }
            pt::Loc::CommandLine => {
                SourceLocation::new(file_path.into(), Position::start(), Position::start())
            }
            pt::Loc::Builtin => {
                SourceLocation::new(file_path.into(), Position::start(), Position::start())
            }
            _ => {
                SourceLocation::new(file_path.into(), Position::start(), Position::start())
            }
        }
    }

    /// Convert diagnostic location for error reporting
    fn convert_diagnostic_location(&self, _error: &diagnostics::Diagnostic, file_path: &str) -> SourceLocation {
        let start_pos = Position::new(1, 1, 0);
        let end_pos = Position::new(1, 1, 0);
        SourceLocation::new(file_path.into(), start_pos, end_pos)
    }
}
