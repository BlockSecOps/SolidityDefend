use crate::types::AnalysisContext;

/// Contract type classification for domain-specific detectors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractType {
    Bridge,
    AMM,
    ZKRollup,
    Vault,
    Token,
    Generic,
}

/// Detect if contract is an L2 bridge
///
/// Bridges facilitate cross-chain message/token transfers between L1 and L2.
///
/// Indicators:
/// - Keywords: L1, L2, bridge, cross-chain, relay, messenger
/// - Functions: withdraw, deposit with merkle proofs
/// - State roots, merkle trees, message passing
pub fn is_bridge_contract(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Strong bridge indicators (any 2 means likely bridge)
    let mut indicator_count = 0;

    // Keyword indicators
    if source_lower.contains("l1") && source_lower.contains("l2") {
        indicator_count += 1;
    }

    if source_lower.contains("bridge") {
        indicator_count += 1;
    }

    if source_lower.contains("crosschain") || source_lower.contains("cross-chain") {
        indicator_count += 1;
    }

    if source_lower.contains("relay") || source_lower.contains("messenger") {
        indicator_count += 1;
    }

    // Technical indicators
    if source.contains("merkleProof") || source.contains("merkleRoot") {
        indicator_count += 1;
    }

    if source.contains("stateRoot") || source.contains("blockHash") {
        indicator_count += 1;
    }

    if source_lower.contains("finalize") && source_lower.contains("withdrawal") {
        indicator_count += 1;
    }

    if source.contains("MessagePassed") || source.contains("MessageRelayed") {
        indicator_count += 1;
    }

    // Contract/interface names
    if ctx.contract.name.name.to_lowercase().contains("bridge") {
        indicator_count += 2; // Strong signal
    }

    if ctx.contract.name.name.to_lowercase().contains("messenger") {
        indicator_count += 2;
    }

    // Need at least 2 indicators to classify as bridge
    indicator_count >= 2
}

/// Detect if contract is an AMM (Automated Market Maker)
///
/// AMMs are decentralized exchanges using algorithmic pricing.
///
/// Indicators:
/// - Functions: swap, addLiquidity, removeLiquidity
/// - State variables: reserves, token0, token1
/// - Constant product formula: k = x * y
/// - Price calculation functions
pub fn is_amm_contract(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    let mut indicator_count = 0;

    // Core AMM functions
    if source_lower.contains("swap") {
        indicator_count += 1;
    }

    if source_lower.contains("addliquidity") || source_lower.contains("add_liquidity") {
        indicator_count += 1;
    }

    if source_lower.contains("removeliquidity") || source_lower.contains("remove_liquidity") {
        indicator_count += 1;
    }

    // AMM state variables
    if source.contains("reserve0") && source.contains("reserve1") {
        indicator_count += 2; // Strong signal
    }

    if source.contains("token0") && source.contains("token1") {
        indicator_count += 1;
    }

    // Pricing functions
    if source_lower.contains("getamountout") || source_lower.contains("get_amount_out") {
        indicator_count += 1;
    }

    if source_lower.contains("getamountin") || source_lower.contains("get_amount_in") {
        indicator_count += 1;
    }

    // Constant product formula indicator
    if source.contains(" * ")
        && (source.contains("reserve") || source.contains("balance"))
        && (source.contains("k =") || source_lower.contains("invariant"))
    {
        indicator_count += 1;
    }

    // Contract name
    if ctx.contract.name.name.to_lowercase().contains("pair")
        || ctx.contract.name.name.to_lowercase().contains("pool")
        || ctx.contract.name.name.to_lowercase().contains("swap")
    {
        indicator_count += 1;
    }

    // Uniswap-specific
    if source.contains("IUniswapV2") || source.contains("IUniswapV3") {
        indicator_count += 2;
    }

    // Need at least 2 indicators to classify as AMM
    indicator_count >= 2
}

/// Detect if contract is a ZK rollup
///
/// ZK rollups use zero-knowledge proofs for L2 scalability.
///
/// Indicators:
/// - Functions: verifyProof, submitBatch
/// - ZK proof verification
/// - Batch processing
/// - Commitment schemes
pub fn is_zk_rollup_contract(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    let mut indicator_count = 0;

    // ZK-specific keywords
    if source_lower.contains("zk") || source_lower.contains("zero-knowledge") {
        indicator_count += 2; // Strong signal
    }

    if source_lower.contains("snark") || source_lower.contains("stark") {
        indicator_count += 2;
    }

    if source_lower.contains("plonk") || source_lower.contains("groth16") {
        indicator_count += 2;
    }

    // Proof verification
    if source_lower.contains("verifyproof") || source_lower.contains("verify_proof") {
        indicator_count += 2;
    }

    if source.contains("proof") && (source.contains("verify") || source.contains("Verify")) {
        indicator_count += 1;
    }

    // Pairing/elliptic curve operations
    if source.contains("pairing") || source.contains("bn256") || source.contains("bls12") {
        indicator_count += 1;
    }

    // Batch/commitment
    if source_lower.contains("submitbatch") || source_lower.contains("submit_batch") {
        indicator_count += 1;
    }

    if (source_lower.contains("commitment") || source_lower.contains("stateroot"))
        && source_lower.contains("proof")
    {
        indicator_count += 1;
    }

    // Contract name
    if ctx.contract.name.name.to_lowercase().contains("zk")
        || ctx.contract.name.name.to_lowercase().contains("rollup")
        || ctx.contract.name.name.to_lowercase().contains("verifier")
    {
        indicator_count += 1;
    }

    // Need at least 2 indicators to classify as ZK rollup
    indicator_count >= 2
}

/// Detect if contract is an ERC4626 vault
pub fn is_vault_contract(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // ERC4626 interface
    if source.contains("ERC4626") || source.contains("IERC4626") {
        return true;
    }

    // Vault-specific function names
    let has_vault_functions = source_lower.contains("deposit")
        && source_lower.contains("withdraw")
        && (source_lower.contains("shares") || source_lower.contains("totalassets"));

    // Contract name
    let has_vault_name = ctx.contract.name.name.to_lowercase().contains("vault");

    has_vault_functions && has_vault_name
}

/// Detect if contract is a token
pub fn is_token_contract(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // ERC20/ERC721/ERC1155 interfaces
    if source.contains("ERC20") || source.contains("ERC721") || source.contains("ERC1155") {
        return true;
    }

    // Standard token functions
    let has_transfer = source.contains("function transfer(");
    let has_balance = source.contains("balanceOf");
    let has_total_supply = source.contains("totalSupply");

    has_transfer && has_balance && has_total_supply
}

/// Classify contract type
pub fn classify_contract(ctx: &AnalysisContext) -> ContractType {
    // Check specific types first (more specific to less specific)
    if is_zk_rollup_contract(ctx) {
        return ContractType::ZKRollup;
    }

    if is_bridge_contract(ctx) {
        return ContractType::Bridge;
    }

    if is_amm_contract(ctx) {
        return ContractType::AMM;
    }

    if is_vault_contract(ctx) {
        return ContractType::Vault;
    }

    if is_token_contract(ctx) {
        return ContractType::Token;
    }

    ContractType::Generic
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_context(source: &str) -> AnalysisContext<'static> {
        crate::types::test_utils::create_test_context(source)
    }

    #[test]
    fn test_bridge_detection() {
        let source = r#"
            contract L1Bridge {
                bytes32 public stateRoot;

                function finalizeWithdrawal(
                    bytes32 merkleRoot,
                    bytes32[] memory proof
                ) external {
                    // Bridge withdrawal logic
                }
            }
        "#;
        let ctx = create_context(source);
        assert!(is_bridge_contract(&ctx));
    }

    #[test]
    fn test_amm_detection() {
        let source = r#"
            contract UniswapPair {
                uint112 private reserve0;
                uint112 private reserve1;

                function swap(uint amount0Out, uint amount1Out, address to) external {
                    // AMM swap logic
                }

                function addLiquidity() external {
                    // Add liquidity
                }
            }
        "#;
        let ctx = create_context(source);
        assert!(is_amm_contract(&ctx));
    }

    #[test]
    fn test_zk_rollup_detection() {
        let source = r#"
            contract ZKVerifier {
                function verifyProof(
                    uint256[2] memory a,
                    uint256[2][2] memory b,
                    uint256[2] memory c
                ) public returns (bool) {
                    // ZK-SNARK verification
                    return pairing(proof);
                }
            }
        "#;
        let ctx = create_context(source);
        assert!(is_zk_rollup_contract(&ctx));
    }

    #[test]
    fn test_vault_detection() {
        let source = r#"
            contract ERC4626Vault {
                function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
                    shares = convertToShares(assets);
                }

                function withdraw(uint256 assets, address receiver, address owner) public {
                    // Withdraw logic
                }

                function totalAssets() public view returns (uint256) {
                    return asset.balanceOf(address(this));
                }
            }
        "#;
        let ctx = create_context(source);
        assert!(is_vault_contract(&ctx));
    }

    #[test]
    fn test_non_bridge_contract() {
        let source = r#"
            contract SimpleVault {
                function withdraw(uint256 amount) public {
                    // Regular withdrawal, not a bridge
                }
            }
        "#;
        let ctx = create_context(source);
        assert!(!is_bridge_contract(&ctx));
    }

    #[test]
    fn test_non_amm_contract() {
        let source = r#"
            contract Token {
                function transfer(address to, uint256 amount) public {
                    // Token transfer, not AMM
                }
            }
        "#;
        let ctx = create_context(source);
        assert!(!is_amm_contract(&ctx));
    }
}
