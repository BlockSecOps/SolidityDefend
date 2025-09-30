# Contributing to SolidityDefend

Thank you for your interest in contributing to SolidityDefend! This document provides guidelines for contributing to the project.

## Development Setup

1. **Install Prerequisites**
   - Rust 1.75.0 or later
   - Git
   - Pre-commit (optional but recommended)

2. **Clone and Setup**
   ```bash
   git clone https://github.com/soliditydefend/cli.git
   cd cli

   # Install pre-commit hooks (optional)
   pip install pre-commit
   pre-commit install
   ```

3. **Build and Test**
   ```bash
   cargo build
   cargo test --all-features
   cargo clippy -- -D warnings
   cargo fmt --check
   ```

## Development Workflow

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Follow the existing code style and conventions
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   cargo test --all-features
   cargo clippy -- -D warnings
   cargo fmt
   ```

4. **Submit a Pull Request**
   - Provide a clear description of your changes
   - Reference any related issues
   - Ensure all CI checks pass

## Code Style

- Follow standard Rust conventions
- Use `cargo fmt` for code formatting
- Ensure `cargo clippy` passes without warnings
- Write comprehensive tests for new functionality
- Add documentation for public APIs

## Testing

- Unit tests should be co-located with the code they test
- Integration tests go in the `tests/` directory
- Use `cargo nextest` for running tests when available
- Aim for high test coverage

## Submitting Issues

When submitting bug reports or feature requests:

1. **Check existing issues** to avoid duplicates
2. **Use issue templates** when available
3. **Provide clear reproduction steps** for bugs
4. **Include relevant information** (OS, Rust version, etc.)

## Pull Request Guidelines

- **Small, focused changes** are preferred over large PRs
- **Include tests** for new functionality
- **Update documentation** as needed
- **Follow commit message conventions**
- **Ensure CI passes** before requesting review

## Commit Message Format

Use conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(parser): add support for Solidity 0.8.25`
- `fix(detector): correct false positive in reentrancy detection`
- `docs: update installation instructions`

## Adding New Detectors

When adding new vulnerability detectors:

1. **Create the detector** in the appropriate module under `crates/detectors/src/`
2. **Add comprehensive tests** including true positive and false positive cases
3. **Update documentation** with detector description and examples
4. **Add configuration options** if needed
5. **Include benchmark tests** for performance validation

## Documentation

- Use rustdoc for API documentation
- Include examples in documentation
- Update README.md for user-facing changes
- Add entries to CHANGELOG.md for releases

## Community Guidelines

- Be respectful and inclusive
- Help newcomers get started
- Provide constructive feedback
- Follow the code of conduct

## Getting Help

- Join our Discord community
- Ask questions in GitHub issues
- Check the documentation
- Review existing code for examples

Thank you for contributing to SolidityDefend!