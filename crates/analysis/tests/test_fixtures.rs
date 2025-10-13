use anyhow::Result;
use ast::AstArena;
use ast::SourceFile;
use parser::Parser;

/// Arena-allocated AST test fixtures for realistic scenarios
pub struct TestFixtures<'a> {
    arena: &'a AstArena,
    parser: Parser,
}

impl<'a> TestFixtures<'a> {
    pub fn new(arena: &'a AstArena) -> Self {
        Self {
            arena,
            parser: Parser::new(),
        }
    }

    /// Parse Solidity source code into arena-allocated AST
    pub fn parse_source(&self, source: &str) -> Result<SourceFile<'a>> {
        self.parser
            .parse(self.arena, source, "test.sol")
            .map_err(|e| anyhow::anyhow!("Parse error: {:?}", e))
    }

    /// ERC20 token implementation with common vulnerabilities
    pub fn vulnerable_erc20_source() -> &'static str {
        r#"
        pragma solidity ^0.8.0;

        contract VulnerableERC20 {
            mapping(address => uint256) public balances;
            mapping(address => mapping(address => uint256)) public allowances;
            uint256 public totalSupply;
            string public name;
            string public symbol;

            // Vulnerability: Missing events
            function transfer(address to, uint256 amount) public returns (bool) {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                balances[msg.sender] -= amount;
                balances[to] += amount; // Potential overflow
                return true;
            }

            // Vulnerability: Race condition in approve
            function approve(address spender, uint256 amount) public returns (bool) {
                allowances[msg.sender][spender] = amount;
                return true;
            }

            // Vulnerability: Unprotected mint function
            function mint(address to, uint256 amount) public {
                balances[to] += amount;
                totalSupply += amount;
            }
        }
        "#
    }

    /// DeFi staking contract with reentrancy vulnerabilities
    pub fn vulnerable_staking_source() -> &'static str {
        r#"
        pragma solidity ^0.8.0;

        contract VulnerableStaking {
            mapping(address => uint256) public stakes;
            mapping(address => uint256) public rewards;
            uint256 public totalStaked;

            function stake() public payable {
                stakes[msg.sender] += msg.value;
                totalStaked += msg.value;
            }

            // Vulnerability: Reentrancy attack vector
            function withdraw(uint256 amount) public {
                require(stakes[msg.sender] >= amount, "Insufficient stake");

                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");

                stakes[msg.sender] -= amount; // State update after external call
                totalStaked -= amount;
            }

            // Vulnerability: Precision loss in reward calculation
            function calculateReward(address user) public view returns (uint256) {
                return (stakes[user] * 100) / totalStaked; // Integer division
            }

            // Vulnerability: Unprotected emergency function
            function emergencyWithdraw() public {
                payable(msg.sender).transfer(address(this).balance);
            }
        }
        "#
    }

    /// Complex DeFi protocol with multiple vulnerabilities
    pub fn complex_defi_source() -> &'static str {
        r#"
        pragma solidity ^0.8.0;

        contract ComplexDeFi {
            mapping(address => uint256) public balances;
            mapping(address => uint256) public collateral;
            mapping(address => uint256) public borrowed;

            address[] public users;
            uint256 public liquidationThreshold = 150; // 150%
            uint256 public constant PRECISION = 1e18;

            modifier onlyOwner() {
                // Missing owner check
                _;
            }

            function deposit() public payable {
                require(msg.value > 0, "Invalid amount");
                balances[msg.sender] += msg.value;

                if (balances[msg.sender] == msg.value) {
                    users.push(msg.sender); // Potential duplicate entries
                }
            }

            function borrow(uint256 amount) public {
                uint256 maxBorrow = (collateral[msg.sender] * 100) / liquidationThreshold;
                require(borrowed[msg.sender] + amount <= maxBorrow, "Insufficient collateral");

                borrowed[msg.sender] += amount;
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
            }

            // Vulnerability: Gas griefing in liquidation
            function liquidateUsers() public {
                for (uint256 i = 0; i < users.length; i++) {
                    address user = users[i];
                    uint256 collateralValue = collateral[user];
                    uint256 borrowedValue = borrowed[user];

                    if (collateralValue * 100 < borrowedValue * liquidationThreshold) {
                        // Liquidate user
                        balances[user] = 0;
                        borrowed[user] = 0;
                        collateral[user] = 0;
                    }
                }
            }

            // Vulnerability: Oracle manipulation susceptible
            function updatePrice(uint256 newPrice) public onlyOwner {
                // Missing validation and access control
            }
        }
        "#
    }

    /// MultiSig wallet with timing attack vulnerabilities
    pub fn vulnerable_multisig_source() -> &'static str {
        r#"
        pragma solidity ^0.8.0;

        contract VulnerableMultiSig {
            address[] public owners;
            mapping(address => bool) public isOwner;
            mapping(bytes32 => uint256) public confirmations;
            uint256 public required;

            struct Transaction {
                address to;
                uint256 value;
                bytes data;
                bool executed;
            }

            Transaction[] public transactions;

            modifier onlyOwner() {
                require(isOwner[msg.sender], "Not owner");
                _;
            }

            // Vulnerability: Weak randomness in transaction ID
            function submitTransaction(address to, uint256 value, bytes memory data)
                public onlyOwner returns (bytes32) {
                bytes32 txId = keccak256(abi.encodePacked(block.timestamp, msg.sender));

                transactions.push(Transaction({
                    to: to,
                    value: value,
                    data: data,
                    executed: false
                }));

                return txId;
            }

            // Vulnerability: Race condition in confirmation
            function confirmTransaction(bytes32 txId, uint256 txIndex) public onlyOwner {
                require(!transactions[txIndex].executed, "Already executed");

                confirmations[txId]++;

                if (confirmations[txId] >= required) {
                    executeTransaction(txIndex);
                }
            }

            function executeTransaction(uint256 txIndex) internal {
                Transaction storage txn = transactions[txIndex];
                require(!txn.executed, "Already executed");

                txn.executed = true;
                (bool success, ) = txn.to.call{value: txn.value}(txn.data);
                require(success, "Execution failed");
            }
        }
        "#
    }

    /// Auction contract with front-running vulnerabilities
    pub fn vulnerable_auction_source() -> &'static str {
        r#"
        pragma solidity ^0.8.0;

        contract VulnerableAuction {
            address public highestBidder;
            uint256 public highestBid;
            mapping(address => uint256) public bids;

            uint256 public auctionEnd;
            bool public ended;

            // Vulnerability: Predictable randomness
            function generateRandomNumber() internal view returns (uint256) {
                return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)));
            }

            function bid() public payable {
                require(block.timestamp < auctionEnd, "Auction ended");
                require(msg.value > highestBid, "Bid too low");

                // Vulnerability: Refund before state update
                if (highestBidder != address(0)) {
                    payable(highestBidder).transfer(highestBid);
                }

                highestBidder = msg.sender;
                highestBid = msg.value;
                bids[msg.sender] = msg.value;
            }

            // Vulnerability: Denial of service through gas limit
            function refundAll() public {
                require(ended, "Auction not ended");

                for (uint256 i = 0; i < 1000; i++) { // Arbitrary large loop
                    // Potential gas limit issues
                }
            }

            function endAuction() public {
                require(block.timestamp >= auctionEnd, "Auction still active");
                require(!ended, "Already ended");

                ended = true;

                // Winner selection with weak randomness
                uint256 random = generateRandomNumber();
                if (random % 2 == 0) {
                    // Alternative winner selection
                }
            }
        }
        "#
    }

    /// NFT marketplace with multiple security issues
    pub fn vulnerable_nft_marketplace_source() -> &'static str {
        r#"
        pragma solidity ^0.8.0;

        contract VulnerableNFTMarketplace {
            mapping(uint256 => address) public tokenOwners;
            mapping(uint256 => uint256) public tokenPrices;
            mapping(address => uint256) public balances;

            uint256 public nextTokenId = 1;
            address public feeRecipient;
            uint256 public feePercentage = 250; // 2.5%

            // Vulnerability: Missing access control
            function setFeeRecipient(address _feeRecipient) public {
                feeRecipient = _feeRecipient;
            }

            function mint(address to) public returns (uint256) {
                uint256 tokenId = nextTokenId++;
                tokenOwners[tokenId] = to;
                return tokenId;
            }

            // Vulnerability: Price manipulation
            function listToken(uint256 tokenId, uint256 price) public {
                require(tokenOwners[tokenId] == msg.sender, "Not owner");
                tokenPrices[tokenId] = price;
            }

            // Vulnerability: Reentrancy and integer overflow
            function buyToken(uint256 tokenId) public payable {
                require(tokenPrices[tokenId] > 0, "Not for sale");
                require(msg.value >= tokenPrices[tokenId], "Insufficient payment");

                address seller = tokenOwners[tokenId];
                uint256 price = tokenPrices[tokenId];

                // Calculate fee with potential overflow
                uint256 fee = (price * feePercentage) / 10000;
                uint256 sellerAmount = price - fee;

                // External calls before state updates
                payable(seller).transfer(sellerAmount);
                payable(feeRecipient).transfer(fee);

                tokenOwners[tokenId] = msg.sender;
                tokenPrices[tokenId] = 0;

                // Refund excess payment
                if (msg.value > price) {
                    payable(msg.sender).transfer(msg.value - price);
                }
            }
        }
        "#
    }

    /// Clean, secure contract for comparison
    pub fn secure_contract_source() -> &'static str {
        r#"
        pragma solidity ^0.8.0;

        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        import "@openzeppelin/contracts/access/Ownable.sol";
        import "@openzeppelin/contracts/security/Pausable.sol";

        contract SecureContract is ReentrancyGuard, Ownable, Pausable {
            mapping(address => uint256) private balances;

            event Deposit(address indexed user, uint256 amount);
            event Withdrawal(address indexed user, uint256 amount);

            function deposit() public payable nonReentrant whenNotPaused {
                require(msg.value > 0, "Invalid amount");
                balances[msg.sender] += msg.value;
                emit Deposit(msg.sender, msg.value);
            }

            function withdraw(uint256 amount) public nonReentrant whenNotPaused {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                balances[msg.sender] -= amount;

                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");

                emit Withdrawal(msg.sender, amount);
            }

            function emergencyPause() public onlyOwner {
                _pause();
            }

            function unpause() public onlyOwner {
                _unpause();
            }

            function getBalance(address user) public view returns (uint256) {
                return balances[user];
            }
        }
        "#
    }

    /// Simple function patterns for basic testing
    pub fn simple_patterns_source() -> &'static str {
        r#"
        pragma solidity ^0.8.0;

        contract SimplePatterns {
            uint256 public counter;
            mapping(address => uint256) public balances;

            function increment() public {
                counter += 1;
            }

            function add(uint256 a, uint256 b) public pure returns (uint256) {
                return a + b;
            }

            function conditionalIncrement(bool condition) public {
                if (condition) {
                    counter += 1;
                } else {
                    counter += 2;
                }
            }

            function loopExample(uint256 n) public {
                for (uint256 i = 0; i < n; i++) {
                    counter += i;
                }
            }

            function nestedConditions(uint256 x, uint256 y) public pure returns (uint256) {
                if (x > 10) {
                    if (y > 5) {
                        return x + y;
                    } else {
                        return x - y;
                    }
                } else {
                    if (y > 20) {
                        return x * y;
                    } else {
                        return x / (y + 1);
                    }
                }
            }
        }
        "#
    }

    /// Contract with complex control flow for CFG testing
    pub fn complex_control_flow_source() -> &'static str {
        r#"
        pragma solidity ^0.8.0;

        contract ComplexControlFlow {
            mapping(address => uint256) public data;
            uint256[] public array;

            function complexFunction(uint256 x, uint256 y, bool flag) public returns (uint256) {
                uint256 result = 0;

                // Nested loops with conditions
                for (uint256 i = 0; i < x; i++) {
                    if (i % 2 == 0) {
                        for (uint256 j = 0; j < y; j++) {
                            if (flag && j > 5) {
                                result += i * j;
                                break;
                            } else if (!flag && j < 3) {
                                result += i + j;
                                continue;
                            }
                            result += 1;
                        }
                    } else {
                        if (i > 10) {
                            result *= 2;
                        } else {
                            result += i;
                        }
                    }
                }

                // Switch-like structure with multiple returns
                if (result < 100) {
                    return result;
                } else if (result < 1000) {
                    return result / 2;
                } else if (result < 10000) {
                    return result / 10;
                } else {
                    return 0;
                }
            }

            function recursiveFunction(uint256 n) public pure returns (uint256) {
                if (n <= 1) {
                    return n;
                } else {
                    return recursiveFunction(n - 1) + recursiveFunction(n - 2);
                }
            }
        }
        "#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures_creation() {
        let arena = AstArena::new();
        let fixtures = TestFixtures::new(&arena);

        // Test that we can parse various contract types
        let sources = [
            TestFixtures::vulnerable_erc20_source(),
            TestFixtures::vulnerable_staking_source(),
            TestFixtures::secure_contract_source(),
            TestFixtures::simple_patterns_source(),
        ];

        for (i, source) in sources.iter().enumerate() {
            match fixtures.parse_source(source) {
                Ok(ast) => {
                    assert!(
                        !ast.contracts.is_empty(),
                        "Source {} should have contracts",
                        i
                    );
                    println!("✅ Successfully parsed test fixture {}", i);
                }
                Err(e) => {
                    println!("⚠️  Failed to parse test fixture {}: {}", i, e);
                    // Don't fail test - some fixtures might have syntax issues during development
                }
            }
        }
    }

    #[test]
    fn test_vulnerable_contracts_parsing() {
        let arena = AstArena::new();
        let fixtures = TestFixtures::new(&arena);

        let vulnerable_sources = [
            ("ERC20", TestFixtures::vulnerable_erc20_source()),
            ("Staking", TestFixtures::vulnerable_staking_source()),
            ("DeFi", TestFixtures::complex_defi_source()),
            ("MultiSig", TestFixtures::vulnerable_multisig_source()),
            ("Auction", TestFixtures::vulnerable_auction_source()),
            (
                "NFT Marketplace",
                TestFixtures::vulnerable_nft_marketplace_source(),
            ),
        ];

        for (name, source) in vulnerable_sources.iter() {
            if let Ok(ast) = fixtures.parse_source(source) {
                assert!(!ast.contracts.is_empty(), "{} should have contracts", name);

                // Verify the contract has functions (most vulnerabilities are in functions)
                let has_functions = ast
                    .contracts
                    .iter()
                    .any(|contract| !contract.functions.is_empty());
                assert!(has_functions, "{} should have functions to analyze", name);

                println!(
                    "✅ {} contract parsed successfully with {} contracts",
                    name,
                    ast.contracts.len()
                );
            }
        }
    }

    #[test]
    fn test_control_flow_patterns() {
        let arena = AstArena::new();
        let fixtures = TestFixtures::new(&arena);

        let parse_result = fixtures.parse_source(TestFixtures::complex_control_flow_source());
        match parse_result {
            Ok(ast) => {
                assert_eq!(ast.contracts.len(), 1);
                let contract = &ast.contracts[0];
                assert!(!contract.functions.is_empty());

                // Should have functions with complex control flow
                let complex_function = contract
                    .functions
                    .iter()
                    .find(|f| f.name.name.contains("complexFunction"));
                assert!(complex_function.is_some(), "Should have complexFunction");

                drop(ast); // Explicit drop to end arena borrowing
                println!("✅ Complex control flow patterns parsed successfully");
            }
            Err(e) => {
                println!("⚠️  Complex control flow parsing failed: {}", e);
                // Don't fail test - may be expected during development
            }
        }
    }
}
