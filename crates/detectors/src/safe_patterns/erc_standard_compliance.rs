use crate::types::AnalysisContext;

/// Check if a function is part of ERC20 standard interface
pub fn is_erc20_function(function_name: &str, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Standard ERC20 functions that MUST be public
    let erc20_functions = [
        "transfer",
        "transferFrom",
        "approve",
        "allowance",
        "balanceOf",
        "totalSupply",
    ];

    let name_lower = function_name.to_lowercase();

    // Check if function name matches ERC20 standard
    let is_standard_function = erc20_functions
        .iter()
        .any(|&func| name_lower == func.to_lowercase());

    if !is_standard_function {
        return false;
    }

    // Verify this is actually an ERC20 contract (not just a function with same name)
    let is_erc20_contract = source.contains("ERC20")
        || source.contains("IERC20")
        || (source.contains("totalSupply") && source.contains("balanceOf"))
        || source.contains("// ERC-20")
        || source.contains("// ERC20");

    is_erc20_contract && is_standard_function
}

/// Check if a function is part of ERC4626 vault standard interface
pub fn is_erc4626_function(function_name: &str, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Standard ERC4626 functions that MUST be public
    let erc4626_functions = [
        "deposit",
        "mint",
        "withdraw",
        "redeem",
        "asset",
        "totalAssets",
        "convertToShares",
        "convertToAssets",
        "maxDeposit",
        "maxMint",
        "maxWithdraw",
        "maxRedeem",
        "previewDeposit",
        "previewMint",
        "previewWithdraw",
        "previewRedeem",
    ];

    let name_lower = function_name.to_lowercase();

    // Check if function name matches ERC4626 standard
    let is_standard_function = erc4626_functions
        .iter()
        .any(|&func| name_lower == func.to_lowercase());

    if !is_standard_function {
        return false;
    }

    // Verify this is actually an ERC4626 vault contract (not just mentioned in comments)
    let is_erc4626_contract = source.contains("is ERC4626")
        || source.contains("is IERC4626")
        || source.contains("import") && (source.contains("ERC4626") || source.contains("IERC4626"))
        || (source.contains("deposit")
            && source.contains("withdraw")
            && source.contains("totalAssets")
            && source.contains("shares"));

    is_erc4626_contract && is_standard_function
}

/// Check if a function is part of ERC721 NFT standard interface
pub fn is_erc721_function(function_name: &str, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Standard ERC721 functions that MUST be public
    let erc721_functions = [
        "transferFrom",
        "safeTransferFrom",
        "approve",
        "setApprovalForAll",
        "getApproved",
        "isApprovedForAll",
        "balanceOf",
        "ownerOf",
        "tokenURI",
    ];

    let name_lower = function_name.to_lowercase();

    // Check if function name matches ERC721 standard
    let is_standard_function = erc721_functions.iter().any(|&func| name_lower == func);

    if !is_standard_function {
        return false;
    }

    // Verify this is actually an ERC721 contract
    let is_erc721_contract = source.contains("ERC721")
        || source.contains("IERC721")
        || source.contains("tokenURI")
        || source.contains("// ERC-721")
        || source.contains("// ERC721");

    is_erc721_contract && is_standard_function
}

/// Check if a function is part of ERC1155 multi-token standard interface
pub fn is_erc1155_function(function_name: &str, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Standard ERC1155 functions that MUST be public
    let erc1155_functions = [
        "safeTransferFrom",
        "safeBatchTransferFrom",
        "setApprovalForAll",
        "isApprovedForAll",
        "balanceOf",
        "balanceOfBatch",
        "uri",
    ];

    let name_lower = function_name.to_lowercase();

    // Check if function name matches ERC1155 standard
    let is_standard_function = erc1155_functions.iter().any(|&func| name_lower == func);

    if !is_standard_function {
        return false;
    }

    // Verify this is actually an ERC1155 contract
    let is_erc1155_contract = source.contains("ERC1155")
        || source.contains("IERC1155")
        || source.contains("safeBatchTransferFrom")
        || source.contains("balanceOfBatch")
        || source.contains("// ERC-1155")
        || source.contains("// ERC1155");

    is_erc1155_contract && is_standard_function
}

/// Check if a function is part of any ERC standard interface
pub fn is_standard_compliant_function(function_name: &str, ctx: &AnalysisContext) -> bool {
    is_erc20_function(function_name, ctx)
        || is_erc4626_function(function_name, ctx)
        || is_erc721_function(function_name, ctx)
        || is_erc1155_function(function_name, ctx)
}

/// Check if this contract implements multiple ERC standards
pub fn get_implemented_standards(ctx: &AnalysisContext) -> Vec<&'static str> {
    let source = &ctx.source_code;
    let mut standards = Vec::new();

    if source.contains("ERC20") || source.contains("IERC20") {
        standards.push("ERC20");
    }

    if source.contains("ERC4626") || source.contains("IERC4626") {
        standards.push("ERC4626");
    }

    if source.contains("ERC721") || source.contains("IERC721") {
        standards.push("ERC721");
    }

    if source.contains("ERC1155") || source.contains("IERC1155") {
        standards.push("ERC1155");
    }

    standards
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::create_test_context;

    #[test]
    fn test_erc20_function_detection() {
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;

            contract MyToken is ERC20 {
                function transfer(address to, uint256 amount) public returns (bool) {
                    // implementation
                }

                function approve(address spender, uint256 amount) public returns (bool) {
                    // implementation
                }
            }
        "#;

        let ctx = create_mock_context(source);

        // Should recognize ERC20 functions
        assert!(is_erc20_function("transfer", &ctx));
        assert!(is_erc20_function("approve", &ctx));
        assert!(is_erc20_function("balanceOf", &ctx));

        // Should NOT recognize non-ERC20 functions
        assert!(!is_erc20_function("adminWithdraw", &ctx));
        assert!(!is_erc20_function("pause", &ctx));
    }

    #[test]
    fn test_erc4626_function_detection() {
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;

            contract MyVault is ERC4626 {
                function deposit(uint256 assets, address receiver) public returns (uint256) {
                    // implementation
                }

                function withdraw(uint256 assets, address receiver, address owner) public returns (uint256) {
                    // implementation
                }
            }
        "#;

        let ctx = create_mock_context(source);

        // Should recognize ERC4626 functions
        assert!(is_erc4626_function("deposit", &ctx));
        assert!(is_erc4626_function("withdraw", &ctx));
        assert!(is_erc4626_function("mint", &ctx));
        assert!(is_erc4626_function("redeem", &ctx));

        // Should NOT recognize non-ERC4626 functions
        assert!(!is_erc4626_function("adminWithdraw", &ctx));
    }

    #[test]
    fn test_standard_compliant_function() {
        let erc20_source = "contract Token is ERC20 {}";
        let erc20_ctx = create_mock_context(erc20_source);

        assert!(is_standard_compliant_function("transfer", &erc20_ctx));
        assert!(is_standard_compliant_function("approve", &erc20_ctx));

        let erc4626_source = "contract Vault is ERC4626 {}";
        let erc4626_ctx = create_mock_context(erc4626_source);

        assert!(is_standard_compliant_function("deposit", &erc4626_ctx));
        assert!(is_standard_compliant_function("withdraw", &erc4626_ctx));
    }

    #[test]
    fn test_non_standard_function_not_flagged() {
        let source = r#"
            contract MyContract {
                function withdraw() public {
                    // This is NOT an ERC4626 vault, so this withdraw needs access control
                }
            }
        "#;

        let ctx = create_mock_context(source);

        // Should NOT be recognized as ERC4626 function (no ERC4626 markers)
        assert!(!is_erc4626_function("withdraw", &ctx));
        assert!(!is_standard_compliant_function("withdraw", &ctx));
    }

    #[test]
    fn test_get_implemented_standards() {
        let multi_source = r#"
            contract MultiToken is ERC20, ERC721 {
                // Implements both ERC20 and ERC721
            }
        "#;

        let ctx = create_mock_context(multi_source);
        let standards = get_implemented_standards(&ctx);

        assert!(standards.contains(&"ERC20"));
        assert!(standards.contains(&"ERC721"));
        assert!(!standards.contains(&"ERC1155"));
    }

    // Helper function to create mock context for tests
    fn create_mock_context(source: &str) -> AnalysisContext<'static> {
        create_test_context(source)
    }
}
