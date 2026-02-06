//! Integration tests for the project crate using real framework projects

use project::{Framework, Project, detect_framework};
use std::path::Path;

const FOUNDRY_PROJECT: &str = "/tmp/framework-tests/foundry-project";
const HARDHAT_PROJECT: &str = "/tmp/framework-tests/hardhat-project";

#[test]
#[ignore = "requires framework test projects in /tmp"]
fn test_detect_foundry_project() {
    let path = Path::new(FOUNDRY_PROJECT);
    if !path.exists() {
        eprintln!(
            "Skipping: Foundry test project not found at {}",
            FOUNDRY_PROJECT
        );
        return;
    }

    let framework = detect_framework(path);
    assert_eq!(framework, Framework::Foundry);
}

#[test]
#[ignore = "requires framework test projects in /tmp"]
fn test_detect_hardhat_project() {
    let path = Path::new(HARDHAT_PROJECT);
    if !path.exists() {
        eprintln!(
            "Skipping: Hardhat test project not found at {}",
            HARDHAT_PROJECT
        );
        return;
    }

    let framework = detect_framework(path);
    assert_eq!(framework, Framework::Hardhat);
}

#[test]
#[ignore = "requires framework test projects in /tmp"]
fn test_load_foundry_project() {
    let path = Path::new(FOUNDRY_PROJECT);
    if !path.exists() {
        eprintln!(
            "Skipping: Foundry test project not found at {}",
            FOUNDRY_PROJECT
        );
        return;
    }

    let project = Project::load(path).expect("Failed to load Foundry project");

    assert_eq!(project.framework, Framework::Foundry);
    assert!(
        !project.solidity_files.is_empty(),
        "Expected to find Solidity files"
    );

    println!("Foundry project loaded:");
    println!("  Framework: {:?}", project.framework);
    println!("  Root: {:?}", project.root);
    println!("  Solidity files: {}", project.solidity_files.len());
    for file in &project.solidity_files {
        println!("    - {:?}", file);
    }
    println!("  Remappings: {:?}", project.remappings);
}

#[test]
#[ignore = "requires framework test projects in /tmp"]
fn test_load_hardhat_project() {
    let path = Path::new(HARDHAT_PROJECT);
    if !path.exists() {
        eprintln!(
            "Skipping: Hardhat test project not found at {}",
            HARDHAT_PROJECT
        );
        return;
    }

    let project = Project::load(path).expect("Failed to load Hardhat project");

    assert_eq!(project.framework, Framework::Hardhat);
    assert!(
        !project.solidity_files.is_empty(),
        "Expected to find Solidity files"
    );

    println!("Hardhat project loaded:");
    println!("  Framework: {:?}", project.framework);
    println!("  Root: {:?}", project.root);
    println!("  Solidity files: {}", project.solidity_files.len());
    for file in &project.solidity_files {
        println!("    - {:?}", file);
    }
    println!("  Remappings: {:?}", project.remappings);
}

#[test]
#[ignore = "requires framework test projects in /tmp"]
fn test_foundry_project_structure() {
    let path = Path::new(FOUNDRY_PROJECT);
    if !path.exists() {
        return;
    }

    let project = Project::load(path).expect("Failed to load Foundry project");

    // Verify source directory
    let source_dir = project.source_dir();
    assert!(
        source_dir.exists(),
        "Source directory should exist: {:?}",
        source_dir
    );

    // Verify lib directories
    let lib_dirs = project.lib_dirs();
    println!("Library directories: {:?}", lib_dirs);
}

#[test]
#[ignore = "requires framework test projects in /tmp"]
fn test_hardhat_project_structure() {
    let path = Path::new(HARDHAT_PROJECT);
    if !path.exists() {
        return;
    }

    let project = Project::load(path).expect("Failed to load Hardhat project");

    // Verify source directory (contracts for Hardhat)
    let source_dir = project.source_dir();
    assert!(
        source_dir.exists(),
        "Source directory should exist: {:?}",
        source_dir
    );

    // Check for Solidity version
    if let Some(version) = project.solc_version() {
        println!("Solidity version: {}", version);
    }
}
