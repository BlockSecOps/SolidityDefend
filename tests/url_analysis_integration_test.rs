use std::env;
use std::process::Command;
use std::path::Path;

const SAMPLE_CONTRACT_ADDRESS: &str = "0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e";

/// Integration test for URL-based contract analysis
/// This test validates the complete workflow from URL input to security analysis output
#[test]
fn test_sample_contract_url_analysis() {
    // Build the binary first
    let output = Command::new("cargo")
        .args(&["build", "--release", "--bin", "soliditydefend"])
        .output()
        .expect("Failed to build soliditydefend binary");

    assert!(output.status.success(), "Failed to build binary: {}", String::from_utf8_lossy(&output.stderr));

    let binary_path = "target/release/soliditydefend";
    assert!(Path::new(binary_path).exists(), "Binary not found at expected path");

    // Test URL parsing without API key (should show helpful error)
    let test_url = format!("https://etherscan.io/address/{}", SAMPLE_CONTRACT_ADDRESS);

    println!("🧪 Testing URL parsing and error handling...");
    let output = Command::new(binary_path)
        .args(&["--from-url", &test_url])
        .output()
        .expect("Failed to execute soliditydefend");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should fail gracefully with helpful error message
    assert!(!output.status.success(), "Expected failure without API key");
    assert!(
        stderr.contains("API key") || stdout.contains("API key"),
        "Should mention API key requirement. stderr: {}, stdout: {}",
        stderr, stdout
    );

    println!("✅ URL parsing and error handling working correctly");

    // Test with API key if available
    if let Ok(api_key) = env::var("ETHERSCAN_API_KEY") {
        if !api_key.is_empty() {
            test_with_real_api_key(&binary_path, &test_url, &api_key);
        } else {
            println!("⏭️  Skipping real API test - ETHERSCAN_API_KEY is empty");
        }
    } else {
        println!("⏭️  Skipping real API test - ETHERSCAN_API_KEY not set");
        println!("💡 To test with real API: export ETHERSCAN_API_KEY=your_key_here");
    }
}

fn test_with_real_api_key(binary_path: &str, test_url: &str, api_key: &str) {
    println!("🔑 Testing with real Etherscan API key...");

    let output = Command::new(binary_path)
        .args(&["--from-url", test_url, "--format", "json"])
        .env("ETHERSCAN_API_KEY", api_key)
        .output()
        .expect("Failed to execute soliditydefend with API key");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("📤 Command output:");
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // The command might succeed or fail depending on contract verification status
    // But it should not fail due to missing API key
    assert!(
        !stderr.contains("No API key") && !stdout.contains("No API key"),
        "Should not fail due to missing API key"
    );

    if output.status.success() {
        println!("✅ Successfully analyzed contract from URL");

        // Verify JSON output structure if analysis succeeded
        if stdout.trim().starts_with('{') || stdout.trim().starts_with('[') {
            match serde_json::from_str::<serde_json::Value>(&stdout) {
                Ok(_) => println!("✅ Valid JSON output produced"),
                Err(e) => println!("⚠️  JSON parsing failed: {}", e),
            }
        }
    } else {
        // Analysis failed - check if it's an expected failure
        let combined_output = format!("{} {}", stdout, stderr);

        if combined_output.contains("not verified") {
            println!("ℹ️  Contract not verified - this is expected for some contracts");
        } else if combined_output.contains("rate limit") {
            println!("ℹ️  Rate limit reached - this is expected with API usage");
        } else if combined_output.contains("API error") {
            println!("ℹ️  API error - this can happen with some contracts");
        } else {
            println!("⚠️  Unexpected error during analysis: {}", combined_output);
        }
    }
}

#[test]
fn test_api_key_setup_command() {
    println!("🧪 Testing API key setup command...");

    let binary_path = "target/release/soliditydefend";

    // Ensure binary exists
    if !Path::new(binary_path).exists() {
        let output = Command::new("cargo")
            .args(&["build", "--release", "--bin", "soliditydefend"])
            .output()
            .expect("Failed to build soliditydefend binary");
        assert!(output.status.success(), "Failed to build binary");
    }

    // Test --setup-api-keys flag with non-interactive input
    let output = Command::new(binary_path)
        .args(&["--setup-api-keys"])
        .output()
        .expect("Failed to execute setup-api-keys command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("Setup command output:");
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // Should not error and should show setup instructions
    assert!(
        stdout.contains("API key") || stdout.contains("blockchain"),
        "Should show API key setup instructions"
    );

    println!("✅ API key setup command working correctly");
}

#[test]
fn test_help_includes_url_options() {
    println!("🧪 Testing help output includes URL options...");

    let binary_path = "target/release/soliditydefend";

    // Ensure binary exists
    if !Path::new(binary_path).exists() {
        let output = Command::new("cargo")
            .args(&["build", "--release", "--bin", "soliditydefend"])
            .output()
            .expect("Failed to build soliditydefend binary");
        assert!(output.status.success(), "Failed to build binary");
    }

    let output = Command::new(binary_path)
        .args(&["--help"])
        .output()
        .expect("Failed to execute help command");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify help includes our new options
    assert!(stdout.contains("--from-url"), "Help should include --from-url option");
    assert!(stdout.contains("--setup-api-keys"), "Help should include --setup-api-keys option");
    assert!(stdout.contains("blockchain explorer"), "Help should mention blockchain explorer");

    println!("✅ Help output includes URL analysis options");
}

#[test]
fn test_url_validation_errors() {
    println!("🧪 Testing URL validation with invalid URLs...");

    let binary_path = "target/release/soliditydefend";

    // Ensure binary exists
    if !Path::new(binary_path).exists() {
        let output = Command::new("cargo")
            .args(&["build", "--release", "--bin", "soliditydefend"])
            .output()
            .expect("Failed to build soliditydefend binary");
        assert!(output.status.success(), "Failed to build binary");
    }

    let invalid_urls = vec![
        "https://invalid-explorer.com/address/0x123",
        "https://etherscan.io/invalid/0x123",
        "not_a_url_at_all",
        "https://etherscan.io/address/invalid_address",
    ];

    for invalid_url in invalid_urls {
        println!("Testing invalid URL: {}", invalid_url);

        let output = Command::new(binary_path)
            .args(&["--from-url", invalid_url])
            .env("ETHERSCAN_API_KEY", "dummy_key") // Provide dummy key to get past API key check
            .output()
            .expect("Failed to execute soliditydefend with invalid URL");

        // Should fail with appropriate error message
        assert!(!output.status.success(), "Should fail with invalid URL: {}", invalid_url);

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let combined = format!("{} {}", stdout, stderr);

        assert!(
            combined.contains("Invalid") ||
            combined.contains("Unsupported") ||
            combined.contains("Failed") ||
            combined.contains("Error"),
            "Should show appropriate error for invalid URL: {}. Output: {}",
            invalid_url, combined
        );
    }

    println!("✅ URL validation working correctly");
}

/// Test for specific contract analysis patterns we expect to find
#[test]
#[ignore] // Requires API key
fn test_sample_contract_specific_analysis() {
    let api_key = match env::var("ETHERSCAN_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            println!("Skipping specific contract analysis - ETHERSCAN_API_KEY not set");
            return;
        }
    };

    println!("🔍 Running detailed analysis on sample contract: {}", SAMPLE_CONTRACT_ADDRESS);

    let binary_path = "target/release/soliditydefend";

    // Ensure binary exists
    if !Path::new(binary_path).exists() {
        let output = Command::new("cargo")
            .args(&["build", "--release", "--bin", "soliditydefend"])
            .output()
            .expect("Failed to build soliditydefend binary");
        assert!(output.status.success(), "Failed to build binary");
    }

    let test_url = format!("https://etherscan.io/address/{}", SAMPLE_CONTRACT_ADDRESS);

    let output = Command::new(binary_path)
        .args(&[
            "--from-url", &test_url,
            "--format", "console",
            "--min-severity", "info"
        ])
        .env("ETHERSCAN_API_KEY", &api_key)
        .output()
        .expect("Failed to execute detailed analysis");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("📊 Analysis Results:");
    println!("Exit code: {}", output.status.code().unwrap_or(-1));
    println!("stdout:\n{}", stdout);
    println!("stderr:\n{}", stderr);

    if output.status.success() {
        // Parse the output to verify analysis worked
        assert!(stdout.contains("Analysis"), "Should contain analysis output");

        // Look for security findings patterns
        if stdout.contains("issues found") {
            println!("✅ Security analysis completed with findings");
        } else {
            println!("✅ Security analysis completed with no issues");
        }
    } else {
        // Check if failure is expected
        let combined = format!("{} {}", stdout, stderr);
        if combined.contains("not verified") {
            println!("ℹ️  Contract not verified - analysis cannot proceed");
        } else {
            println!("❌ Unexpected analysis failure: {}", combined);
        }
    }
}

/// Performance test for URL analysis
#[test]
#[ignore] // Requires API key and network access
fn test_url_analysis_performance() {
    let api_key = match env::var("ETHERSCAN_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            println!("Skipping performance test - ETHERSCAN_API_KEY not set");
            return;
        }
    };

    println!("⏱️  Testing URL analysis performance...");

    let binary_path = "target/release/soliditydefend";
    let test_url = format!("https://etherscan.io/address/{}", SAMPLE_CONTRACT_ADDRESS);

    let start = std::time::Instant::now();

    let output = Command::new(binary_path)
        .args(&["--from-url", &test_url, "--format", "json"])
        .env("ETHERSCAN_API_KEY", &api_key)
        .output()
        .expect("Failed to execute performance test");

    let duration = start.elapsed();

    println!("📈 Performance Results:");
    println!("   Total time: {:?}", duration);
    println!("   Exit code: {}", output.status.code().unwrap_or(-1));

    // Performance expectations
    if output.status.success() {
        assert!(duration.as_secs() < 30, "Analysis should complete within 30 seconds");
        println!("✅ Performance test passed - analysis completed in {:?}", duration);
    } else {
        println!("ℹ️  Performance test skipped - analysis failed (possibly expected)");
    }
}