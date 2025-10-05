use ast::{AstArena, SourceFile, SourceLocation, Position, Contract, Function, Identifier, ContractType, Visibility, Block, Statement, Expression, AssignmentOperator};
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
        let mut function = Function::new(self.arena, name, location);

        // Convert function visibility
        for attr in &func.attributes {
            if let pt::FunctionAttribute::Visibility(vis) = attr {
                function.visibility = self.convert_visibility(vis);
            }
        }

        // Convert function body
        if let Some(body_stmt) = &func.body {
            function.body = Some(self.convert_statement_to_block(body_stmt, source, file_path)?);
        }

        Ok(function)
    }

    /// Convert function visibility
    fn convert_visibility(&self, vis: &pt::Visibility) -> Visibility {
        match vis {
            pt::Visibility::Public(_) => Visibility::Public,
            pt::Visibility::Internal(_) => Visibility::Internal,
            pt::Visibility::External(_) => Visibility::External,
            pt::Visibility::Private(_) => Visibility::Private,
        }
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

    /// Convert a solang statement to a Block (for function bodies)
    fn convert_statement_to_block(
        &self,
        stmt: &pt::Statement,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Block<'arena>> {
        match stmt {
            pt::Statement::Block { loc, statements, .. } => {
                let location = self.convert_location_with_source(loc, file_path, Some(source));
                let mut block = Block::new(self.arena, location);

                for stmt in statements {
                    if let Ok(converted) = self.convert_statement(stmt, source, file_path) {
                        block.statements.push(converted);
                    }
                }

                Ok(block)
            }
            _ => {
                // For non-block statements, wrap in a block
                let location = self.convert_location_with_source(&self.get_statement_location(stmt), file_path, Some(source));
                let mut block = Block::new(self.arena, location);

                if let Ok(converted) = self.convert_statement(stmt, source, file_path) {
                    block.statements.push(converted);
                }

                Ok(block)
            }
        }
    }

    /// Convert a solang statement to our Statement
    fn convert_statement(
        &self,
        stmt: &pt::Statement,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Statement<'arena>> {
        let location = self.convert_location_with_source(&self.get_statement_location(stmt), file_path, Some(source));

        match stmt {
            pt::Statement::Block { statements, .. } => {
                let mut block = Block::new(self.arena, location);
                for stmt in statements {
                    if let Ok(converted) = self.convert_statement(stmt, source, file_path) {
                        block.statements.push(converted);
                    }
                }
                Ok(Statement::Block(block))
            }
            pt::Statement::Expression(_, expr) => {
                let converted_expr = self.convert_expression(expr, source, file_path)?;
                Ok(Statement::Expression(converted_expr))
            }
            pt::Statement::Return(_, expr_opt) => {
                let expr = if let Some(expr) = expr_opt {
                    Some(self.convert_expression(expr, source, file_path)?)
                } else {
                    None
                };
                Ok(Statement::Return { value: expr, location })
            }
            pt::Statement::If(_, condition, then_stmt, else_stmt) => {
                let condition_expr = self.convert_expression(condition, source, file_path)?;
                let then_branch = self.arena.alloc(self.convert_statement(then_stmt, source, file_path)?);
                let else_branch = if let Some(else_stmt) = else_stmt {
                    Some(self.arena.alloc(self.convert_statement(else_stmt, source, file_path)?))
                } else {
                    None
                };
                Ok(Statement::If { condition: condition_expr, then_branch, else_branch, location })
            }
            pt::Statement::While(_, condition, body) => {
                let condition_expr = self.convert_expression(condition, source, file_path)?;
                let body_stmt = self.arena.alloc(self.convert_statement(body, source, file_path)?);
                Ok(Statement::While { condition: condition_expr, body: body_stmt, location })
            }
            pt::Statement::For(_, init, condition, increment, body) => {
                let init_stmt = if let Some(init) = init {
                    Some(self.arena.alloc(self.convert_statement(init, source, file_path)?))
                } else {
                    None
                };
                let condition_expr = if let Some(condition) = condition {
                    Some(self.convert_expression(condition, source, file_path)?)
                } else {
                    None
                };
                let update_expr = if let Some(increment) = increment {
                    Some(self.convert_expression(increment, source, file_path)?)
                } else {
                    None
                };
                let body_stmt = if let Some(body) = body {
                    self.arena.alloc(self.convert_statement(body, source, file_path)?)
                } else {
                    // Create empty block if no body
                    let dummy_block = Block::new(self.arena, location.clone());
                    self.arena.alloc(Statement::Block(dummy_block))
                };
                Ok(Statement::For {
                    init: init_stmt,
                    condition: condition_expr,
                    update: update_expr,
                    body: body_stmt,
                    location
                })
            }
            _ => {
                // For unimplemented statement types, create a placeholder
                let dummy_expr = Expression::Literal {
                    value: ast::LiteralValue::Number("0".into()),
                    location: location.clone(),
                };
                Ok(Statement::Expression(dummy_expr))
            }
        }
    }

    /// Convert a solang expression to our Expression
    fn convert_expression(
        &self,
        expr: &pt::Expression,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Expression<'arena>> {
        let location = self.convert_location_with_source(&self.get_expression_location(expr), file_path, Some(source));

        match expr {
            pt::Expression::FunctionCall(_, function, args) => {
                // Handle regular function calls, including those where the function
                // might be a FunctionCallBlock (like call{value: amount}(""))
                let function_expr = self.arena.alloc(self.convert_expression(function, source, file_path)?);
                let mut arguments = bumpalo::collections::Vec::new_in(&self.arena.bump);

                // Convert the regular arguments
                for arg in args {
                    if let Ok(converted_arg) = self.convert_expression(arg, source, file_path) {
                        arguments.push(converted_arg);
                    }
                }

                let names = bumpalo::collections::Vec::new_in(&self.arena.bump);

                Ok(Expression::FunctionCall {
                    function: function_expr,
                    arguments,
                    names,
                    location,
                })
            }
            pt::Expression::FunctionCallBlock(_, function, _block) => {
                // Handle function calls with blocks like msg.sender.call{value: amount}
                // For now, treat this exactly like a regular FunctionCall to test basic functionality
                let function_expr = self.arena.alloc(self.convert_expression(function, source, file_path)?);
                let arguments = bumpalo::collections::Vec::new_in(&self.arena.bump);
                let names = bumpalo::collections::Vec::new_in(&self.arena.bump);

                // TODO: Parse the block to extract call options (like {value: amount})
                // For now, ignore the block and just make this detectable as an external call

                Ok(Expression::FunctionCall {
                    function: function_expr,
                    arguments,
                    names,
                    location,
                })
            }
            pt::Expression::MemberAccess(_, expr, member) => {
                let expr_converted = self.arena.alloc(self.convert_expression(expr, source, file_path)?);
                let member_converted = self.convert_identifier_with_source(member, source, file_path)?;

                Ok(Expression::MemberAccess {
                    expression: expr_converted,
                    member: member_converted,
                    location,
                })
            }
            pt::Expression::Variable(ident) => {
                let identifier = self.convert_identifier_with_source(ident, source, file_path)?;
                Ok(Expression::Identifier(identifier))
            }
            pt::Expression::Assign(_, left, right) => {
                let left_expr = self.arena.alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self.arena.alloc(self.convert_expression(right, source, file_path)?);

                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::Assign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::NamedFunctionCall(_, function, named_args) => {
                // Handle named function calls like function({name: value})
                let function_expr = self.arena.alloc(self.convert_expression(function, source, file_path)?);
                let mut arguments = bumpalo::collections::Vec::new_in(&self.arena.bump);
                let mut names = bumpalo::collections::Vec::new_in(&self.arena.bump);

                // Convert named arguments
                for named_arg in named_args {
                    if let Ok(arg_expr) = self.convert_expression(&named_arg.expr, source, file_path) {
                        arguments.push(arg_expr);
                        let name_ident = self.convert_identifier_with_source(&named_arg.name, source, file_path)?;
                        names.push(name_ident);
                    }
                }

                Ok(Expression::FunctionCall {
                    function: function_expr,
                    arguments,
                    names,
                    location,
                })
            }
            _ => {
                // For unimplemented expression types, create a literal placeholder
                // TODO: Add proper logging here to debug what expression types are being missed
                Ok(Expression::Literal {
                    value: ast::LiteralValue::Number("0".into()),
                    location,
                })
            }
        }
    }

    /// Extract location from solang Statement
    fn get_statement_location(&self, stmt: &pt::Statement) -> pt::Loc {
        match stmt {
            pt::Statement::Block { loc, .. } => *loc,
            pt::Statement::Assembly { loc, .. } => *loc,
            pt::Statement::Args(loc, _) => *loc,
            pt::Statement::If(loc, ..) => *loc,
            pt::Statement::While(loc, ..) => *loc,
            pt::Statement::Expression(loc, _) => *loc,
            pt::Statement::VariableDefinition(loc, ..) => *loc,
            pt::Statement::For(loc, ..) => *loc,
            pt::Statement::DoWhile(loc, ..) => *loc,
            pt::Statement::Continue(loc) => *loc,
            pt::Statement::Break(loc) => *loc,
            pt::Statement::Return(loc, _) => *loc,
            pt::Statement::Revert(loc, ..) => *loc,
            pt::Statement::RevertNamedArgs(loc, ..) => *loc,
            pt::Statement::Emit(loc, _) => *loc,
            pt::Statement::Try(loc, ..) => *loc,
            pt::Statement::Error(loc) => *loc,
        }
    }

    /// Extract location from solang Expression
    fn get_expression_location(&self, expr: &pt::Expression) -> pt::Loc {
        match expr {
            pt::Expression::PostIncrement(loc, _) => *loc,
            pt::Expression::PostDecrement(loc, _) => *loc,
            pt::Expression::New(loc, _) => *loc,
            pt::Expression::ArraySubscript(loc, ..) => *loc,
            pt::Expression::ArraySlice(loc, ..) => *loc,
            pt::Expression::Parenthesis(loc, _) => *loc,
            pt::Expression::MemberAccess(loc, ..) => *loc,
            pt::Expression::FunctionCall(loc, ..) => *loc,
            pt::Expression::FunctionCallBlock(loc, ..) => *loc,
            pt::Expression::NamedFunctionCall(loc, ..) => *loc,
            pt::Expression::Not(loc, _) => *loc,
            pt::Expression::BitwiseNot(loc, _) => *loc,
            pt::Expression::Delete(loc, _) => *loc,
            pt::Expression::PreIncrement(loc, _) => *loc,
            pt::Expression::PreDecrement(loc, _) => *loc,
            pt::Expression::UnaryPlus(loc, _) => *loc,
            pt::Expression::Negate(loc, _) => *loc,
            pt::Expression::Power(loc, ..) => *loc,
            pt::Expression::Multiply(loc, ..) => *loc,
            pt::Expression::Divide(loc, ..) => *loc,
            pt::Expression::Modulo(loc, ..) => *loc,
            pt::Expression::Add(loc, ..) => *loc,
            pt::Expression::Subtract(loc, ..) => *loc,
            pt::Expression::ShiftLeft(loc, ..) => *loc,
            pt::Expression::ShiftRight(loc, ..) => *loc,
            pt::Expression::BitwiseAnd(loc, ..) => *loc,
            pt::Expression::BitwiseXor(loc, ..) => *loc,
            pt::Expression::BitwiseOr(loc, ..) => *loc,
            pt::Expression::Less(loc, ..) => *loc,
            pt::Expression::More(loc, ..) => *loc,
            pt::Expression::LessEqual(loc, ..) => *loc,
            pt::Expression::MoreEqual(loc, ..) => *loc,
            pt::Expression::Equal(loc, ..) => *loc,
            pt::Expression::NotEqual(loc, ..) => *loc,
            pt::Expression::And(loc, ..) => *loc,
            pt::Expression::Or(loc, ..) => *loc,
            pt::Expression::ConditionalOperator(loc, ..) => *loc,
            pt::Expression::Assign(loc, ..) => *loc,
            pt::Expression::AssignOr(loc, ..) => *loc,
            pt::Expression::AssignAnd(loc, ..) => *loc,
            pt::Expression::AssignXor(loc, ..) => *loc,
            pt::Expression::AssignShiftLeft(loc, ..) => *loc,
            pt::Expression::AssignShiftRight(loc, ..) => *loc,
            pt::Expression::AssignAdd(loc, ..) => *loc,
            pt::Expression::AssignSubtract(loc, ..) => *loc,
            pt::Expression::AssignMultiply(loc, ..) => *loc,
            pt::Expression::AssignDivide(loc, ..) => *loc,
            pt::Expression::AssignModulo(loc, ..) => *loc,
            pt::Expression::BoolLiteral(loc, _) => *loc,
            pt::Expression::NumberLiteral(loc, ..) => *loc,
            pt::Expression::RationalNumberLiteral(loc, ..) => *loc,
            pt::Expression::HexNumberLiteral(loc, ..) => *loc,
            pt::Expression::StringLiteral(string_lits) => {
                if let Some(first) = string_lits.first() {
                    first.loc
                } else {
                    pt::Loc::Builtin
                }
            }
            pt::Expression::Type(loc, _) => *loc,
            pt::Expression::HexLiteral(hex_lits) => {
                if let Some(first) = hex_lits.first() {
                    first.loc
                } else {
                    pt::Loc::Builtin
                }
            }
            pt::Expression::AddressLiteral(loc, _) => *loc,
            pt::Expression::Variable(ident) => ident.loc,
            pt::Expression::List(loc, _) => *loc,
            pt::Expression::ArrayLiteral(loc, _) => *loc,
        }
    }
}
