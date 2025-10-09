// build.rs - Build-time version information generation

use std::process::Command;

fn main() {
    // Tell Cargo to rerun if version files change
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=../../Cargo.toml");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    // Generate build timestamp
    let build_timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", build_timestamp);

    // Get Git information
    if let Ok(git_hash) = get_git_hash() {
        println!("cargo:rustc-env=GIT_HASH={}", git_hash);
    } else {
        println!("cargo:rustc-env=GIT_HASH=unknown");
    }

    if let Ok(git_branch) = get_git_branch() {
        println!("cargo:rustc-env=GIT_BRANCH={}", git_branch);
    } else {
        println!("cargo:rustc-env=GIT_BRANCH=unknown");
    }

    // Check if git workspace is dirty
    let git_dirty = is_git_dirty().unwrap_or(false);
    println!("cargo:rustc-env=GIT_DIRTY={}", git_dirty);

    // Generate build number (commits since tag)
    if let Ok(build_number) = get_build_number() {
        println!("cargo:rustc-env=BUILD_NUMBER={}", build_number);
    } else {
        println!("cargo:rustc-env=BUILD_NUMBER=0");
    }

    // Get Rust version
    if let Ok(rust_version) = get_rust_version() {
        println!("cargo:rustc-env=RUST_VERSION={}", rust_version);
    } else {
        println!("cargo:rustc-env=RUST_VERSION=unknown");
    }

    // Target information
    println!("cargo:rustc-env=TARGET={}", std::env::var("TARGET").unwrap_or_default());
    println!("cargo:rustc-env=PROFILE={}", std::env::var("PROFILE").unwrap_or_default());

    // Generate version suffix for pre-releases
    let version_suffix = generate_version_suffix();
    if !version_suffix.is_empty() {
        println!("cargo:rustc-env=VERSION_SUFFIX={}", version_suffix);
    }
}

fn get_git_hash() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()?;

    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    } else {
        Err("Git command failed".into())
    }
}

fn get_git_branch() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()?;

    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    } else {
        Err("Git command failed".into())
    }
}

fn is_git_dirty() -> Result<bool, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()?;

    if output.status.success() {
        Ok(!output.stdout.is_empty())
    } else {
        Err("Git command failed".into())
    }
}

fn get_build_number() -> Result<String, Box<dyn std::error::Error>> {
    // Get number of commits since last tag
    let output = Command::new("git")
        .args(["rev-list", "--count", "HEAD"])
        .output()?;

    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    } else {
        Err("Git command failed".into())
    }
}

fn get_rust_version() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("rustc")
        .args(["--version"])
        .output()?;

    if output.status.success() {
        let version = String::from_utf8(output.stdout)?;
        // Extract just the version number
        if let Some(version_part) = version.split_whitespace().nth(1) {
            Ok(version_part.to_string())
        } else {
            Ok(version.trim().to_string())
        }
    } else {
        Err("Rustc command failed".into())
    }
}

fn generate_version_suffix() -> String {
    // Generate suffix for development builds
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let git_branch = std::env::var("GIT_BRANCH").unwrap_or_default();

    if profile == "debug" || git_branch != "main" {
        if let Ok(git_hash) = get_git_hash() {
            if git_branch != "main" && git_branch != "master" {
                return format!("-{}.{}", git_branch.replace('/', "-"), git_hash);
            } else {
                return format!("-dev.{}", git_hash);
            }
        }
    }

    String::new()
}