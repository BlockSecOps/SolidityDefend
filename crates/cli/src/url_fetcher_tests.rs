#[cfg(test)]
mod tests {
    use crate::url_fetcher::{ContractSource, ExplorerPlatform, UrlFetcher, UrlType};
    use std::env;

    const SAMPLE_CONTRACT_ADDRESS: &str = "0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e";

    #[test]
    fn test_url_parsing_basic() {
        let fetcher = UrlFetcher::new();

        // Test transaction URLs
        let test_cases = vec![
            (
                "https://etherscan.io/tx/0x1234567890abcdef",
                ExplorerPlatform::Etherscan,
                UrlType::Transaction("0x1234567890abcdef".to_string()),
            ),
            (
                "https://polygonscan.com/tx/0xabcdef1234567890",
                ExplorerPlatform::Polygonscan,
                UrlType::Transaction("0xabcdef1234567890".to_string()),
            ),
            (
                "https://bscscan.com/tx/0x9876543210fedcba",
                ExplorerPlatform::BscScan,
                UrlType::Transaction("0x9876543210fedcba".to_string()),
            ),
        ];

        for (url, expected_platform, expected_type) in test_cases {
            let result = fetcher.parse_url(url);
            assert!(result.is_ok(), "Failed to parse URL: {}", url);

            let (platform, url_type) = result.unwrap();
            assert_eq!(platform, expected_platform);
            assert_eq!(url_type, expected_type);
        }
    }

    #[test]
    fn test_url_parsing_contract_addresses() {
        let fetcher = UrlFetcher::new();

        // Test contract URLs with our sample address
        let test_cases = vec![
            (
                format!("https://etherscan.io/address/{}", SAMPLE_CONTRACT_ADDRESS),
                ExplorerPlatform::Etherscan,
                UrlType::Contract(SAMPLE_CONTRACT_ADDRESS.to_string()),
            ),
            (
                format!(
                    "https://polygonscan.com/address/{}",
                    SAMPLE_CONTRACT_ADDRESS
                ),
                ExplorerPlatform::Polygonscan,
                UrlType::Contract(SAMPLE_CONTRACT_ADDRESS.to_string()),
            ),
            (
                format!("https://bscscan.com/address/{}", SAMPLE_CONTRACT_ADDRESS),
                ExplorerPlatform::BscScan,
                UrlType::Contract(SAMPLE_CONTRACT_ADDRESS.to_string()),
            ),
            (
                format!("https://arbiscan.io/address/{}", SAMPLE_CONTRACT_ADDRESS),
                ExplorerPlatform::Arbiscan,
                UrlType::Contract(SAMPLE_CONTRACT_ADDRESS.to_string()),
            ),
        ];

        for (url, expected_platform, expected_type) in test_cases {
            let result = fetcher.parse_url(&url);
            assert!(result.is_ok(), "Failed to parse URL: {}", url);

            let (platform, url_type) = result.unwrap();
            assert_eq!(platform, expected_platform);
            assert_eq!(url_type, expected_type);
        }
    }

    #[test]
    fn test_url_parsing_invalid_urls() {
        let fetcher = UrlFetcher::new();

        let invalid_urls = vec![
            "https://invalid-explorer.com/address/0x123",
            "https://etherscan.io/invalid/0x123",
            "not_a_url_at_all",
            "ftp://etherscan.io/address/0x123",
            "https://etherscan.io/address/", // Missing address
            "https://etherscan.io/tx/",      // Missing transaction hash
        ];

        for url in invalid_urls {
            let result = fetcher.parse_url(url);
            assert!(result.is_err(), "Expected error for invalid URL: {}", url);
        }
    }

    #[test]
    fn test_platform_detection() {
        let fetcher = UrlFetcher::new();

        let platform_tests = vec![
            ("https://etherscan.io/tx/0x123", ExplorerPlatform::Etherscan),
            (
                "https://goerli.etherscan.io/tx/0x123",
                ExplorerPlatform::Etherscan,
            ),
            (
                "https://sepolia.etherscan.io/tx/0x123",
                ExplorerPlatform::Etherscan,
            ),
            (
                "https://polygonscan.com/address/0x123",
                ExplorerPlatform::Polygonscan,
            ),
            (
                "https://mumbai.polygonscan.com/address/0x123",
                ExplorerPlatform::Polygonscan,
            ),
            ("https://bscscan.com/tx/0x123", ExplorerPlatform::BscScan),
            (
                "https://testnet.bscscan.com/tx/0x123",
                ExplorerPlatform::BscScan,
            ),
            (
                "https://arbiscan.io/address/0x123",
                ExplorerPlatform::Arbiscan,
            ),
            (
                "https://goerli.arbiscan.io/address/0x123",
                ExplorerPlatform::Arbiscan,
            ),
        ];

        for (url, expected_platform) in platform_tests {
            let result = fetcher.parse_url(url);
            assert!(result.is_ok(), "Failed to parse URL: {}", url);

            let (platform, _) = result.unwrap();
            assert_eq!(
                platform, expected_platform,
                "Wrong platform for URL: {}",
                url
            );
        }
    }

    #[test]
    fn test_api_key_management() {
        let mut fetcher = UrlFetcher::new();

        // Test adding API keys
        fetcher = fetcher.with_api_key(ExplorerPlatform::Etherscan, "test_key_1".to_string());
        fetcher = fetcher.with_api_key(ExplorerPlatform::Polygonscan, "test_key_2".to_string());

        // Test checking API keys
        assert!(fetcher.has_api_key(&ExplorerPlatform::Etherscan));
        assert!(fetcher.has_api_key(&ExplorerPlatform::Polygonscan));
        assert!(!fetcher.has_api_key(&ExplorerPlatform::BscScan));

        // Test getting configured platforms
        let configured = fetcher.get_configured_platforms();
        assert!(configured.contains(&ExplorerPlatform::Etherscan));
        assert!(configured.contains(&ExplorerPlatform::Polygonscan));
        assert_eq!(configured.len(), 2);
    }

    #[test]
    fn test_api_key_loading_from_env() {
        // Set test environment variables
        env::set_var("ETHERSCAN_API_KEY", "test_etherscan_key");
        env::set_var("POLYGONSCAN_API_KEY", "test_polygonscan_key");

        // Test loading from environment
        let result = UrlFetcher::with_user_api_keys();
        assert!(result.is_ok(), "Failed to create fetcher with env API keys");

        let fetcher = result.unwrap();
        assert!(fetcher.has_api_key(&ExplorerPlatform::Etherscan));
        assert!(fetcher.has_api_key(&ExplorerPlatform::Polygonscan));

        // Clean up environment variables
        env::remove_var("ETHERSCAN_API_KEY");
        env::remove_var("POLYGONSCAN_API_KEY");
    }

    #[test]
    fn test_contract_source_temp_file_creation() {
        let fetcher = UrlFetcher::new();

        let sample_contract = ContractSource {
            address: SAMPLE_CONTRACT_ADDRESS.to_string(),
            name: "TestContract".to_string(),
            source_code: r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function greet() public pure returns (string memory) {
        return "Hello, World!";
    }
}
"#
            .to_string(),
            compiler_version: "v0.8.19+commit.7dd6d404".to_string(),
            optimization: true,
            optimization_runs: 200,
            constructor_arguments: None,
            abi: Some("[]".to_string()),
            is_verified: true,
            platform: "Etherscan".to_string(),
        };

        // Test file creation
        let result = fetcher.save_contract_to_temp(&sample_contract);
        assert!(result.is_ok(), "Failed to create temporary file");

        let temp_path = result.unwrap();

        // Verify file exists and contains expected content
        assert!(
            std::path::Path::new(&temp_path).exists(),
            "Temporary file does not exist"
        );

        let content = std::fs::read_to_string(&temp_path).unwrap();
        assert!(
            content.contains("TestContract"),
            "File content missing contract name"
        );
        assert!(
            content.contains(SAMPLE_CONTRACT_ADDRESS),
            "File content missing contract address"
        );
        assert!(
            content.contains("pragma solidity"),
            "File content missing Solidity pragma"
        );
        assert!(
            content.contains("Hello, World!"),
            "File content missing contract code"
        );

        // Clean up
        let _ = std::fs::remove_file(&temp_path);
    }

    #[test]
    fn test_json_source_extraction() {
        let fetcher = UrlFetcher::new();

        // Test multi-file JSON source code (common for verified contracts)
        let json_source = r#"{
            "language": "Solidity",
            "sources": {
                "contracts/TestContract.sol": {
                    "content": "pragma solidity ^0.8.0;\n\ncontract TestContract {\n    string public message = \"Hello World\";\n}"
                },
                "contracts/interfaces/ITest.sol": {
                    "content": "pragma solidity ^0.8.0;\n\ninterface ITest {\n    function getMessage() external view returns (string memory);\n}"
                }
            },
            "settings": {
                "optimizer": {
                    "enabled": true,
                    "runs": 200
                }
            }
        }"#;

        let result = fetcher.extract_main_contract_from_json(json_source);
        assert!(result.is_ok(), "Failed to extract main contract from JSON");

        let extracted = result.unwrap();
        assert!(
            extracted.contains("contract TestContract"),
            "Extracted content missing main contract"
        );
        assert!(
            extracted.contains("Hello World"),
            "Extracted content missing contract content"
        );
    }

    // Integration test - requires API key to run
    #[tokio::test]
    #[ignore] // Ignored by default to avoid API calls in CI
    async fn test_real_contract_analysis() {
        // Only run if API key is available
        let api_key = match env::var("ETHERSCAN_API_KEY") {
            Ok(key) if !key.is_empty() => key,
            _ => {
                println!("Skipping real contract test - ETHERSCAN_API_KEY not set");
                return;
            }
        };

        let fetcher = UrlFetcher::new().with_api_key(ExplorerPlatform::Etherscan, api_key);

        let test_url = format!("https://etherscan.io/address/{}", SAMPLE_CONTRACT_ADDRESS);

        // Test contract source fetching
        let result = fetcher.fetch_contract_source(&test_url).await;

        match result {
            Ok(contracts) => {
                assert!(!contracts.is_empty(), "No contracts found");

                let contract = &contracts[0];
                assert_eq!(
                    contract.address.to_lowercase(),
                    SAMPLE_CONTRACT_ADDRESS.to_lowercase()
                );
                assert!(
                    !contract.source_code.is_empty(),
                    "Contract source code is empty"
                );
                assert!(!contract.name.is_empty(), "Contract name is empty");
                assert!(contract.is_verified, "Contract should be verified");

                println!("✅ Successfully fetched contract: {}", contract.name);
                println!("   Address: {}", contract.address);
                println!("   Compiler: {}", contract.compiler_version);
                println!("   Verified: {}", contract.is_verified);
                println!("   Source length: {} chars", contract.source_code.len());
            }
            Err(e) => {
                // Allow certain errors that don't indicate test failure
                let error_msg = e.to_string();
                if error_msg.contains("not verified")
                    || error_msg.contains("rate limit")
                    || error_msg.contains("API error")
                {
                    println!("⚠️  Test skipped due to expected API limitation: {}", e);
                } else {
                    panic!("Unexpected error fetching contract: {}", e);
                }
            }
        }
    }

    #[test]
    fn test_api_url_building() {
        let fetcher =
            UrlFetcher::new().with_api_key(ExplorerPlatform::Etherscan, "test_key".to_string());

        // Test building API URLs for different platforms
        let test_cases = vec![
            (ExplorerPlatform::Etherscan, "https://api.etherscan.io/api"),
            (
                ExplorerPlatform::Polygonscan,
                "https://api.polygonscan.com/api",
            ),
            (ExplorerPlatform::BscScan, "https://api.bscscan.com/api"),
            (ExplorerPlatform::Arbiscan, "https://api.arbiscan.io/api"),
        ];

        for (platform, expected_base) in test_cases {
            let result = fetcher.build_api_url(
                &platform,
                "getsourcecode",
                &[("address", SAMPLE_CONTRACT_ADDRESS)],
            );
            assert!(
                result.is_ok(),
                "Failed to build API URL for platform: {:?}",
                platform
            );

            let url = result.unwrap();
            assert!(
                url.starts_with(expected_base),
                "URL doesn't start with expected base for {:?}",
                platform
            );
            assert!(
                url.contains("getsourcecode"),
                "URL missing action parameter"
            );
            assert!(
                url.contains(SAMPLE_CONTRACT_ADDRESS),
                "URL missing address parameter"
            );
        }
    }

    #[test]
    fn test_contract_source_serialization() {
        let contract = ContractSource {
            address: SAMPLE_CONTRACT_ADDRESS.to_string(),
            name: "TestContract".to_string(),
            source_code: "pragma solidity ^0.8.0; contract TestContract {}".to_string(),
            compiler_version: "v0.8.19".to_string(),
            optimization: true,
            optimization_runs: 200,
            constructor_arguments: Some("0x123".to_string()),
            abi: Some("[{}]".to_string()),
            is_verified: true,
            platform: "Etherscan".to_string(),
        };

        // Test JSON serialization/deserialization
        let json = serde_json::to_string(&contract).unwrap();
        let deserialized: ContractSource = serde_json::from_str(&json).unwrap();

        assert_eq!(contract.address, deserialized.address);
        assert_eq!(contract.name, deserialized.name);
        assert_eq!(contract.source_code, deserialized.source_code);
        assert_eq!(contract.is_verified, deserialized.is_verified);
    }
}
