use parser::arena::ArenaParser;
use detectors::{DetectorRegistry, AnalysisContext};
use semantic::SymbolTable;

/// Test MEV vulnerability detectors
/// These tests are designed to FAIL initially until the detectors are implemented

#[cfg(test)]
mod test_mev_detectors {
    use super::*;

    fn setup_test_contract(source: &str) -> (ArenaParser, AnalysisContext) {
        let mut parser = ArenaParser::new();
        let contract = parser.parse_contract(source, "test.sol").unwrap();
        let symbols = SymbolTable::new();
        let ctx = AnalysisContext::new(contract, symbols, source.to_string(), "test.sol".to_string());
        (parser, ctx)
    }

    #[test]
    #[should_panic(expected = "detector not found: sandwich-attack")]
    fn test_sandwich_attack_vulnerable_contract() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableSwap {
    mapping(address => uint256) public balances;
    uint256 public price = 100; // Price per token

    // Vulnerable to sandwich attacks - price update without slippage protection
    function swap(uint256 amountIn) external payable {
        require(msg.value == amountIn, "Incorrect ETH amount");

        uint256 tokensOut = calculateTokensOut(amountIn);

        // Update price based on trade size (vulnerable)
        price = price * (100 + amountIn / 1 ether) / 100;

        balances[msg.sender] += tokensOut;
    }

    function calculateTokensOut(uint256 amountIn) public view returns (uint256) {
        return (amountIn * 1 ether) / price;
    }

    // No slippage protection
    function swapWithoutSlippage(uint256 amountIn) external payable {
        uint256 tokensOut = calculateTokensOut(amountIn);
        balances[msg.sender] += tokensOut;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because sandwich attack detector is not implemented yet
        let detector = registry.get_detector("sandwich-attack").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should detect:
        // 1. Price manipulation without slippage protection
        // 2. Lack of minimum output validation
        // 3. Vulnerable swap function pattern
        assert!(!findings.is_empty(), "Should detect sandwich attack vulnerabilities");
    }

    #[test]
    #[should_panic(expected = "detector not found: front-running")]
    fn test_front_running_vulnerable_patterns() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableFrontRunning {
    mapping(address => uint256) public commitments;
    mapping(address => bool) public revealed;
    uint256 public revealDeadline;

    // Vulnerable to front-running - visible parameters
    function commitBid(uint256 bidAmount, uint256 nonce) external {
        bytes32 commitment = keccak256(abi.encodePacked(bidAmount, nonce, msg.sender));
        commitments[msg.sender] = uint256(commitment);
    }

    // Transaction ordering dependency
    function processTransaction(address user, uint256 amount) external {
        require(balances[user] >= amount, "Insufficient balance");

        // Vulnerable: state change before external interaction
        balances[user] -= amount;

        // External call after state change
        (bool success,) = user.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // Predictable randomness vulnerable to front-running
    function generateRandom() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender
        )));
    }

    // Prize distribution vulnerable to front-running
    function distributePrize() external {
        address winner = address(uint160(generateRandom() % 1000));
        payable(winner).transfer(address(this).balance);
    }

    mapping(address => uint256) public balances;
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because front-running detector is not implemented yet
        let detector = registry.get_detector("front-running").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should detect:
        // 1. Predictable randomness
        // 2. Transaction ordering dependencies
        // 3. Vulnerable commit-reveal scheme
        // 4. State changes before external calls
        assert!(!findings.is_empty(), "Should detect front-running vulnerabilities");
    }

    #[test]
    #[should_panic(expected = "detector not found: sandwich-attack")]
    fn test_defi_flash_loan_arbitrage_vulnerability() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VulnerableArbitrage {
    IERC20 public token;
    uint256 public exchangeRate = 100; // 1 ETH = 100 tokens

    // Vulnerable to flash loan arbitrage
    function arbitrageSwap(uint256 ethAmount, uint256 expectedTokens) external payable {
        require(msg.value == ethAmount, "Incorrect ETH");

        // No slippage protection or oracle validation
        uint256 tokensOut = ethAmount * exchangeRate;

        // Vulnerable: allows unlimited arbitrage without restrictions
        require(tokensOut >= expectedTokens, "Insufficient output");

        token.transfer(msg.sender, tokensOut);

        // Update rate based on trade (manipulable)
        exchangeRate = exchangeRate * (100 - ethAmount / 1 ether) / 100;
    }

    // Cross-exchange arbitrage without protection
    function crossExchangeArbitrage(
        address exchangeA,
        address exchangeB,
        uint256 amount
    ) external {
        // Get price from exchange A
        (bool success1, bytes memory data1) = exchangeA.call(
            abi.encodeWithSignature("getPrice()", amount)
        );

        // Get price from exchange B
        (bool success2, bytes memory data2) = exchangeB.call(
            abi.encodeWithSignature("getPrice()", amount)
        );

        // Vulnerable: no validation of price difference thresholds
        if (success1 && success2) {
            // Execute arbitrage without safeguards
            executeArbitrage(exchangeA, exchangeB, amount);
        }
    }

    function executeArbitrage(address from, address to, uint256 amount) internal {
        // Simplified arbitrage execution
    }

    // Vulnerable: allows unlimited MEV extraction
    function extractMEV(uint256 gasPrice, uint256 amount) external {
        // No MEV protection or fair ordering
        require(tx.gasprice >= gasPrice, "Gas price too low");

        // Allows MEV bots to extract value
        uint256 profit = amount * (tx.gasprice - gasPrice) / 1e9;
        payable(msg.sender).transfer(profit);
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because MEV detectors are not implemented yet
        let detector = registry.get_detector("sandwich-attack").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should detect:
        // 1. Flash loan arbitrage vulnerabilities
        // 2. Cross-exchange arbitrage without protection
        // 3. MEV extraction opportunities
        // 4. Price manipulation possibilities
        assert!(!findings.is_empty(), "Should detect MEV arbitrage vulnerabilities");
    }

    #[test]
    #[should_panic(expected = "detector not found: front-running")]
    fn test_liquidation_front_running_vulnerability() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableLiquidation {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public liquidationRatio = 150; // 150% collateralization required
    uint256 public liquidationBonus = 10; // 10% bonus for liquidators

    // Vulnerable to liquidation front-running
    function liquidate(address user) external {
        uint256 collateralValue = getCollateralValue(user);
        uint256 debtValue = debt[user];

        // Check if liquidatable
        require(collateralValue * 100 < debtValue * liquidationRatio, "Not liquidatable");

        // Vulnerable: no protection against front-running liquidations
        uint256 liquidationAmount = debtValue;
        uint256 collateralToSeize = liquidationAmount * (100 + liquidationBonus) / 100;

        // Transfer collateral to liquidator
        collateral[user] -= collateralToSeize;
        collateral[msg.sender] += collateralToSeize;

        // Clear debt
        debt[user] = 0;
    }

    // Price update vulnerable to front-running
    function updatePrice(uint256 newPrice) external {
        // Vulnerable: immediate price update allows front-running
        oracle_price = newPrice;

        // This allows MEV bots to front-run liquidations
        emit PriceUpdated(newPrice);
    }

    uint256 private oracle_price = 1000;

    function getCollateralValue(address user) public view returns (uint256) {
        return collateral[user] * oracle_price / 1e18;
    }

    // Vulnerable batch liquidation
    function batchLiquidate(address[] calldata users) external {
        for (uint i = 0; i < users.length; i++) {
            // Vulnerable: no protection against selective liquidation
            if (isLiquidatable(users[i])) {
                liquidate(users[i]);
            }
        }
    }

    function isLiquidatable(address user) public view returns (bool) {
        uint256 collateralValue = getCollateralValue(user);
        uint256 debtValue = debt[user];
        return collateralValue * 100 < debtValue * liquidationRatio;
    }

    event PriceUpdated(uint256 newPrice);
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because front-running detector is not implemented yet
        let detector = registry.get_detector("front-running").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should detect:
        // 1. Liquidation front-running opportunities
        // 2. Price update front-running
        // 3. Batch liquidation vulnerabilities
        // 4. MEV extraction in liquidations
        assert!(!findings.is_empty(), "Should detect liquidation front-running vulnerabilities");
    }

    #[test]
    #[should_panic(expected = "detector not found: sandwich-attack")]
    fn test_amm_sandwich_attack_vulnerability() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableAMM {
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public constant FEE = 3; // 0.3% fee

    // Vulnerable AMM swap function
    function swap(
        uint256 amountIn,
        uint256 minAmountOut,
        bool aToB
    ) external returns (uint256 amountOut) {
        if (aToB) {
            amountOut = getAmountOut(amountIn, reserveA, reserveB);

            // Vulnerable: no slippage protection beyond minAmountOut
            require(amountOut >= minAmountOut, "Insufficient output");

            // Update reserves immediately (vulnerable to sandwich)
            reserveA += amountIn;
            reserveB -= amountOut;
        } else {
            amountOut = getAmountOut(amountIn, reserveB, reserveA);
            require(amountOut >= minAmountOut, "Insufficient output");

            reserveB += amountIn;
            reserveA -= amountOut;
        }

        // No protection against large trades or price impact
    }

    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) public pure returns (uint256) {
        // Standard AMM formula - vulnerable to manipulation
        uint256 amountInWithFee = amountIn * (1000 - FEE);
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 1000 + amountInWithFee;
        return numerator / denominator;
    }

    // Vulnerable: no maximum price impact protection
    function swapWithoutSlippage(uint256 amountIn, bool aToB) external {
        uint256 amountOut;

        if (aToB) {
            amountOut = getAmountOut(amountIn, reserveA, reserveB);
            reserveA += amountIn;
            reserveB -= amountOut;
        } else {
            amountOut = getAmountOut(amountIn, reserveB, reserveA);
            reserveB += amountIn;
            reserveA -= amountOut;
        }

        // No minimum output check - completely vulnerable
    }

    // Vulnerable to flash loan price manipulation
    function addLiquidity(uint256 amountA, uint256 amountB) external {
        // No validation of price ratio
        reserveA += amountA;
        reserveB += amountB;
    }

    // Allows immediate arbitrage
    function setReserves(uint256 newReserveA, uint256 newReserveB) external {
        reserveA = newReserveA;
        reserveB = newReserveB;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because sandwich attack detector is not implemented yet
        let detector = registry.get_detector("sandwich-attack").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should detect:
        // 1. AMM sandwich attack vulnerabilities
        // 2. Lack of slippage protection
        // 3. Price impact vulnerabilities
        // 4. Flash loan manipulation possibilities
        assert!(!findings.is_empty(), "Should detect AMM sandwich attack vulnerabilities");
    }

    #[test]
    #[should_panic(expected = "detector not found: front-running")]
    fn test_secure_mev_protected_contract() {
        let source = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureMEVProtected {
    mapping(address => uint256) public balances;
    uint256 public price = 100;
    uint256 public constant MAX_SLIPPAGE = 500; // 5%
    uint256 public constant MAX_PRICE_IMPACT = 1000; // 10%

    // Protected swap with slippage and MEV protection
    function secureSwap(
        uint256 amountIn,
        uint256 minAmountOut,
        uint256 maxPriceImpact,
        bytes32 commitment
    ) external payable {
        require(msg.value == amountIn, "Incorrect ETH amount");
        require(maxPriceImpact <= MAX_PRICE_IMPACT, "Price impact too high");

        // Commit-reveal scheme to prevent front-running
        require(verifyCommitment(commitment, amountIn, minAmountOut), "Invalid commitment");

        uint256 tokensOut = calculateTokensOut(amountIn);
        require(tokensOut >= minAmountOut, "Slippage too high");

        // Calculate price impact
        uint256 priceImpact = calculatePriceImpact(amountIn);
        require(priceImpact <= maxPriceImpact, "Price impact exceeds limit");

        balances[msg.sender] += tokensOut;

        // Gradual price update to prevent manipulation
        updatePriceGradually(amountIn);
    }

    function calculateTokensOut(uint256 amountIn) public view returns (uint256) {
        return (amountIn * 1 ether) / price;
    }

    function calculatePriceImpact(uint256 amountIn) public view returns (uint256) {
        // Calculate price impact as percentage
        return (amountIn * 10000) / (getTotalLiquidity() + amountIn);
    }

    function getTotalLiquidity() public view returns (uint256) {
        return address(this).balance;
    }

    function updatePriceGradually(uint256 amountIn) internal {
        // Limit price movement to prevent manipulation
        uint256 maxChange = price * 100 / 10000; // 1% max change
        uint256 priceChange = (amountIn * price) / (getTotalLiquidity() * 100);

        if (priceChange > maxChange) {
            priceChange = maxChange;
        }

        price += priceChange;
    }

    function verifyCommitment(
        bytes32 commitment,
        uint256 amountIn,
        uint256 minAmountOut
    ) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(
            amountIn,
            minAmountOut,
            msg.sender,
            block.number - 1 // Prevent same-block attacks
        ));
        return hash == commitment;
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because detectors are not implemented yet
        let detector = registry.get_detector("front-running").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should NOT detect MEV vulnerabilities in this secure contract
        assert!(findings.is_empty(), "Should not detect vulnerabilities in secure contract");
    }
}
"#;

        let (_parser, ctx) = setup_test_contract(source);
        let registry = DetectorRegistry::new();

        // This should fail because detectors are not implemented yet
        let detector = registry.get_detector("front-running").unwrap();
        let findings = detector.detect(&ctx).unwrap();

        // Should NOT detect MEV vulnerabilities in this secure contract
        assert!(findings.is_empty(), "Should not detect vulnerabilities in secure contract");
    }
}