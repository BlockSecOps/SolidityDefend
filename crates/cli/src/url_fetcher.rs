use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

/// Supported blockchain explorer platforms
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExplorerPlatform {
    Etherscan,
    Polygonscan,
    BscScan,
    Arbiscan,
    OptimismEtherscan,
    BaseScan,
    Snowtrace, // Avalanche
}

/// Type of URL being processed
#[derive(Debug, Clone, PartialEq)]
pub enum UrlType {
    Transaction(String), // Transaction hash
    Contract(String),    // Contract address
}

/// Contract source code information from blockchain explorer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSource {
    pub address: String,
    pub name: String,
    pub source_code: String,
    pub compiler_version: String,
    pub optimization: bool,
    pub optimization_runs: u32,
    pub constructor_arguments: Option<String>,
    pub abi: Option<String>,
    pub is_verified: bool,
    pub platform: String,
}

/// Transaction information for contract creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub block_number: u64,
    pub from: String,
    pub to: Option<String>,
    pub contract_address: Option<String>,
    pub is_contract_creation: bool,
}

/// URL parser and contract fetcher
pub struct UrlFetcher {
    client: Client,
    api_keys: HashMap<ExplorerPlatform, String>,
}

impl Default for UrlFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl UrlFetcher {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("SolidityDefend/0.8.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_keys: HashMap::new(),
        }
    }

    /// Create fetcher with API keys from environment variables and config
    pub fn with_user_api_keys() -> Result<Self> {
        let mut fetcher = Self::new();

        // Load from environment variables (highest priority)
        if let Ok(key) = std::env::var("ETHERSCAN_API_KEY") {
            fetcher.api_keys.insert(ExplorerPlatform::Etherscan, key);
        }
        if let Ok(key) = std::env::var("POLYGONSCAN_API_KEY") {
            fetcher.api_keys.insert(ExplorerPlatform::Polygonscan, key);
        }
        if let Ok(key) = std::env::var("BSCSCAN_API_KEY") {
            fetcher.api_keys.insert(ExplorerPlatform::BscScan, key);
        }
        if let Ok(key) = std::env::var("ARBISCAN_API_KEY") {
            fetcher.api_keys.insert(ExplorerPlatform::Arbiscan, key);
        }

        // Try to load from config file if environment variables not set
        if fetcher.api_keys.is_empty() {
            if let Ok(config_keys) = Self::load_api_keys_from_config() {
                fetcher.api_keys.extend(config_keys);
            }
        }

        Ok(fetcher)
    }

    /// Load API keys from configuration file
    fn load_api_keys_from_config() -> Result<HashMap<ExplorerPlatform, String>> {
        use crate::config::SolidityDefendConfig;

        let keys = HashMap::new();

        // Try to load configuration
        if let Ok(_config) = SolidityDefendConfig::load_from_defaults_and_file(None) {
            // This would require extending the config structure
            // For now, we'll implement basic file-based loading
        }

        Ok(keys)
    }

    /// Add API key for a specific platform
    pub fn with_api_key(mut self, platform: ExplorerPlatform, api_key: String) -> Self {
        self.api_keys.insert(platform, api_key);
        self
    }

    /// Check if platform has API key configured
    pub fn has_api_key(&self, platform: &ExplorerPlatform) -> bool {
        self.api_keys.contains_key(platform)
    }

    /// Get available platforms with configured API keys
    pub fn get_configured_platforms(&self) -> Vec<ExplorerPlatform> {
        self.api_keys.keys().cloned().collect()
    }

    /// Parse URL and extract platform and type
    pub fn parse_url(&self, url_str: &str) -> Result<(ExplorerPlatform, UrlType)> {
        let url =
            Url::parse(url_str).with_context(|| format!("Invalid URL format: {}", url_str))?;

        // Validate URL scheme is HTTP or HTTPS
        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(anyhow!(
                    "Unsupported URL scheme: {}. Only HTTP and HTTPS are supported",
                    scheme
                ));
            }
        }

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("URL missing host: {}", url_str))?;

        let platform = match host {
            "etherscan.io" | "goerli.etherscan.io" | "sepolia.etherscan.io" => {
                ExplorerPlatform::Etherscan
            }
            "polygonscan.com" | "mumbai.polygonscan.com" => ExplorerPlatform::Polygonscan,
            "bscscan.com" | "testnet.bscscan.com" => ExplorerPlatform::BscScan,
            "arbiscan.io" | "goerli.arbiscan.io" => ExplorerPlatform::Arbiscan,
            "optimistic.etherscan.io" | "goerli-optimism.etherscan.io" => {
                ExplorerPlatform::OptimismEtherscan
            }
            "basescan.org" | "goerli.basescan.org" => ExplorerPlatform::BaseScan,
            "snowtrace.io" | "testnet.snowtrace.io" => ExplorerPlatform::Snowtrace,
            _ => return Err(anyhow!("Unsupported blockchain explorer: {}", host)),
        };

        let path = url.path();
        let url_type = if path.starts_with("/tx/") {
            let tx_hash = path
                .strip_prefix("/tx/")
                .ok_or_else(|| anyhow!("Invalid transaction URL format"))?
                .to_string();
            if tx_hash.is_empty() {
                return Err(anyhow!("Transaction hash cannot be empty"));
            }
            UrlType::Transaction(tx_hash)
        } else if path.starts_with("/address/") {
            let address = path
                .strip_prefix("/address/")
                .ok_or_else(|| anyhow!("Invalid address URL format"))?
                .to_string();
            if address.is_empty() {
                return Err(anyhow!("Contract address cannot be empty"));
            }
            UrlType::Contract(address)
        } else {
            return Err(anyhow!(
                "URL must be either a transaction (/tx/) or address (/address/) URL"
            ));
        };

        Ok((platform, url_type))
    }

    /// Fetch contract source from transaction or contract URL
    pub async fn fetch_contract_source(&self, url_str: &str) -> Result<Vec<ContractSource>> {
        let (platform, url_type) = self.parse_url(url_str)?;

        match url_type {
            UrlType::Transaction(tx_hash) => {
                // First get transaction info to find contract address
                let tx_info = self.fetch_transaction_info(&platform, &tx_hash).await?;

                if let Some(contract_address) = tx_info.contract_address {
                    // Fetch contract source from the created contract
                    self.fetch_contract_source_by_address(&platform, &contract_address)
                        .await
                } else {
                    // Transaction might be interacting with an existing contract
                    if let Some(to_address) = tx_info.to {
                        self.fetch_contract_source_by_address(&platform, &to_address)
                            .await
                    } else {
                        Err(anyhow!("Transaction does not involve a smart contract"))
                    }
                }
            }
            UrlType::Contract(address) => {
                self.fetch_contract_source_by_address(&platform, &address)
                    .await
            }
        }
    }

    /// Fetch transaction information
    async fn fetch_transaction_info(
        &self,
        platform: &ExplorerPlatform,
        tx_hash: &str,
    ) -> Result<TransactionInfo> {
        let api_url =
            self.build_api_url(platform, "eth_getTransactionByHash", &[("txhash", tx_hash)])?;

        let response = self
            .client
            .get(&api_url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch transaction info for {}", tx_hash))?;

        let api_response: ApiResponse = response
            .json()
            .await
            .with_context(|| "Failed to parse transaction API response")?;

        if api_response.status != "1" {
            return Err(anyhow!(
                "API error: {}",
                api_response.message.unwrap_or_default()
            ));
        }

        // Parse transaction data
        let tx_data: TransactionData = serde_json::from_value(api_response.result)
            .with_context(|| "Failed to parse transaction data")?;

        let is_contract_creation = tx_data.to.is_none();
        Ok(TransactionInfo {
            hash: tx_hash.to_string(),
            block_number: u64::from_str_radix(&tx_data.block_number[2..], 16).unwrap_or_default(),
            from: tx_data.from,
            to: tx_data.to,
            contract_address: tx_data.contract_address,
            is_contract_creation,
        })
    }

    /// Fetch contract source code by address
    async fn fetch_contract_source_by_address(
        &self,
        platform: &ExplorerPlatform,
        address: &str,
    ) -> Result<Vec<ContractSource>> {
        let api_url = self.build_api_url(platform, "getsourcecode", &[("address", address)])?;

        let response = self
            .client
            .get(&api_url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch contract source for {}", address))?;

        let api_response: ApiResponse = response
            .json()
            .await
            .with_context(|| "Failed to parse contract source API response")?;

        if api_response.status != "1" {
            return Err(anyhow!(
                "API error: {}",
                api_response.message.unwrap_or_default()
            ));
        }

        let source_data: Vec<ContractSourceData> = serde_json::from_value(api_response.result)
            .with_context(|| "Failed to parse contract source data")?;

        let mut contracts = Vec::new();

        for (index, data) in source_data.iter().enumerate() {
            if data.source_code.is_empty() {
                if index == 0 {
                    return Err(anyhow!(
                        "Contract source code not available - contract may not be verified"
                    ));
                }
                continue;
            }

            // Handle multi-file contracts (JSON format)
            let source_code = if data.source_code.starts_with('{') {
                self.extract_main_contract_from_json(&data.source_code)?
            } else {
                data.source_code.clone()
            };

            contracts.push(ContractSource {
                address: address.to_string(),
                name: data.contract_name.clone(),
                source_code,
                compiler_version: data.compiler_version.clone(),
                optimization: data.optimization_used == "1",
                optimization_runs: data.runs.parse().unwrap_or(200),
                constructor_arguments: if data.constructor_arguments.is_empty() {
                    None
                } else {
                    Some(data.constructor_arguments.clone())
                },
                abi: if data.abi == "Contract source code not verified" {
                    None
                } else {
                    Some(data.abi.clone())
                },
                is_verified: !data.source_code.is_empty(),
                platform: format!("{:?}", platform),
            });
        }

        if contracts.is_empty() {
            Err(anyhow!(
                "No verified contracts found at address {}",
                address
            ))
        } else {
            Ok(contracts)
        }
    }

    /// Extract main contract source from JSON format (multi-file projects)
    fn extract_main_contract_from_json(&self, json_source: &str) -> Result<String> {
        // For JSON-formatted multi-file contracts, extract the main contract
        let parsed: serde_json::Value = serde_json::from_str(json_source)
            .with_context(|| "Failed to parse JSON source code")?;

        if let Some(sources) = parsed.get("sources").and_then(|s| s.as_object()) {
            // Find main contract file (usually the one with the same name as contract)
            for (_file_path, file_data) in sources {
                if let Some(content) = file_data.get("content").and_then(|c| c.as_str()) {
                    // Return first non-empty contract (could be improved with better heuristics)
                    if content.contains("contract ") || content.contains("library ") {
                        return Ok(content.to_string());
                    }
                }
            }
        }

        // Fallback: return the JSON as-is for manual inspection
        Ok(json_source.to_string())
    }

    /// Build API URL for different platforms
    fn build_api_url(
        &self,
        platform: &ExplorerPlatform,
        module_action: &str,
        params: &[(&str, &str)],
    ) -> Result<String> {
        let base_url = match platform {
            ExplorerPlatform::Etherscan => "https://api.etherscan.io/api",
            ExplorerPlatform::Polygonscan => "https://api.polygonscan.com/api",
            ExplorerPlatform::BscScan => "https://api.bscscan.com/api",
            ExplorerPlatform::Arbiscan => "https://api.arbiscan.io/api",
            ExplorerPlatform::OptimismEtherscan => "https://api-optimistic.etherscan.io/api",
            ExplorerPlatform::BaseScan => "https://api.basescan.org/api",
            ExplorerPlatform::Snowtrace => "https://api.snowtrace.io/api",
        };

        let mut url = format!("{}?module=contract&action={}", base_url, module_action);

        // Add parameters
        for (key, value) in params {
            url.push_str(&format!("&{}={}", key, value));
        }

        // Add API key if available
        if let Some(api_key) = self.api_keys.get(platform) {
            url.push_str(&format!("&apikey={}", api_key));
        }

        Ok(url)
    }

    /// Save contract to temporary file for analysis
    pub fn save_contract_to_temp(&self, contract: &ContractSource) -> Result<String> {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let filename = format!(
            "{}_{}.sol",
            contract.platform.to_lowercase(),
            contract.address[2..8].to_lowercase() // Remove 0x prefix, take first 6 chars
        );
        let temp_path = temp_dir.join(filename);

        let mut file = std::fs::File::create(&temp_path)
            .with_context(|| format!("Failed to create temporary file: {:?}", temp_path))?;

        // Add metadata as comments
        writeln!(file, "// Contract: {}", contract.name)?;
        writeln!(file, "// Address: {}", contract.address)?;
        writeln!(file, "// Platform: {}", contract.platform)?;
        writeln!(file, "// Compiler: {}", contract.compiler_version)?;
        writeln!(
            file,
            "// Optimization: {} (runs: {})",
            contract.optimization, contract.optimization_runs
        )?;
        writeln!(file, "// Verified: {}", contract.is_verified)?;
        writeln!(file)?;

        file.write_all(contract.source_code.as_bytes())?;
        file.flush()?;

        Ok(temp_path.to_string_lossy().to_string())
    }
}

/// API response structure for blockchain explorers
#[derive(Debug, Deserialize)]
struct ApiResponse {
    status: String,
    message: Option<String>,
    result: serde_json::Value,
}

/// Transaction data from API
#[derive(Debug, Deserialize)]
struct TransactionData {
    #[serde(rename = "blockNumber")]
    block_number: String,
    from: String,
    to: Option<String>,
    #[serde(rename = "contractAddress")]
    contract_address: Option<String>,
}

/// Contract source data from API
#[derive(Debug, Deserialize)]
struct ContractSourceData {
    #[serde(rename = "SourceCode")]
    source_code: String,
    #[serde(rename = "ABI")]
    abi: String,
    #[serde(rename = "ContractName")]
    contract_name: String,
    #[serde(rename = "CompilerVersion")]
    compiler_version: String,
    #[serde(rename = "OptimizationUsed")]
    optimization_used: String,
    #[serde(rename = "Runs")]
    runs: String,
    #[serde(rename = "ConstructorArguments")]
    constructor_arguments: String,
}

// Include tests from separate module
#[cfg(test)]
#[path = "url_fetcher_tests.rs"]
mod url_fetcher_tests;
