// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Simplified Curve 3pool
 * @notice Representative implementation based on Curve Finance stableswap
 * @dev Simplified for FP testing - focuses on core stableswap patterns
 */

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

contract Curve3Pool {
    string public name = "Curve.fi DAI/USDC/USDT";
    string public symbol = "3Crv";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // Pool tokens (DAI, USDC, USDT)
    address[3] public coins;
    uint256[3] public balances;

    uint256 public constant A = 2000;  // Amplification coefficient
    uint256 public constant FEE = 4000000;  // 0.04%
    uint256 public constant ADMIN_FEE = 5000000000;  // 50% of fee

    address public owner;

    event TokenExchange(address indexed buyer, int128 sold_id, uint256 tokens_sold, int128 bought_id, uint256 tokens_bought);
    event AddLiquidity(address indexed provider, uint256[3] token_amounts, uint256[3] fees, uint256 invariant, uint256 token_supply);
    event RemoveLiquidity(address indexed provider, uint256[3] token_amounts, uint256[3] fees, uint256 token_supply);

    constructor(address[3] memory _coins) {
        coins = _coins;
        owner = msg.sender;
    }

    // Core Curve function - should be detected by is_curve_amm()
    function get_virtual_price() external view returns (uint256) {
        uint256 D = _get_D(balances, A);
        return D * 1e18 / totalSupply;
    }

    // StableSwap invariant calculation
    function _get_D(uint256[3] memory _balances, uint256 _A) internal pure returns (uint256) {
        uint256 S = 0;
        for (uint i = 0; i < 3; i++) {
            S += _balances[i];
        }
        if (S == 0) {
            return 0;
        }

        uint256 D = S;
        uint256 Ann = _A * 3;

        for (uint i = 0; i < 255; i++) {
            uint256 D_P = D;
            for (uint j = 0; j < 3; j++) {
                D_P = D_P * D / (_balances[j] * 3);
            }
            uint256 Dprev = D;
            D = (Ann * S + D_P * 3) * D / ((Ann - 1) * D + 4 * D_P);
            if (D > Dprev) {
                if (D - Dprev <= 1) {
                    break;
                }
            } else {
                if (Dprev - D <= 1) {
                    break;
                }
            }
        }
        return D;
    }

    // Add liquidity to pool
    function add_liquidity(uint256[3] calldata amounts, uint256 min_mint_amount) external returns (uint256) {
        uint256[3] memory fees;
        uint256 D0 = 0;
        uint256[3] memory old_balances = balances;

        if (totalSupply > 0) {
            D0 = _get_D(old_balances, A);
        }

        uint256[3] memory new_balances = balances;
        for (uint i = 0; i < 3; i++) {
            if (totalSupply == 0) {
                require(amounts[i] > 0, "Initial deposit requires all coins");
            }
            new_balances[i] = old_balances[i] + amounts[i];
        }

        uint256 D1 = _get_D(new_balances, A);
        require(D1 > D0, "D1 must increase");

        // Calculate mint amount
        uint256 mint_amount;
        if (totalSupply == 0) {
            mint_amount = D1;
        } else {
            mint_amount = totalSupply * (D1 - D0) / D0;
        }

        require(mint_amount >= min_mint_amount, "Slippage");

        // Update state
        for (uint i = 0; i < 3; i++) {
            if (amounts[i] > 0) {
                IERC20(coins[i]).transferFrom(msg.sender, address(this), amounts[i]);
                balances[i] = new_balances[i];
            }
        }

        totalSupply += mint_amount;
        balanceOf[msg.sender] += mint_amount;

        emit AddLiquidity(msg.sender, amounts, fees, D1, totalSupply);

        return mint_amount;
    }

    // Remove liquidity from pool
    function remove_liquidity(uint256 _amount, uint256[3] calldata min_amounts) external returns (uint256[3] memory) {
        uint256[3] memory amounts;

        for (uint i = 0; i < 3; i++) {
            uint256 value = balances[i] * _amount / totalSupply;
            require(value >= min_amounts[i], "Slippage");
            amounts[i] = value;
            balances[i] -= value;
            IERC20(coins[i]).transfer(msg.sender, value);
        }

        totalSupply -= _amount;
        balanceOf[msg.sender] -= _amount;

        emit RemoveLiquidity(msg.sender, amounts, [uint256(0), uint256(0), uint256(0)], totalSupply);

        return amounts;
    }

    // Exchange tokens (swap)
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256) {
        require(i != j, "Same coin");
        require(i >= 0 && i < 3, "Invalid i");
        require(j >= 0 && j < 3, "Invalid j");

        uint256[3] memory old_balances = balances;
        uint256 x = old_balances[uint256(int256(i))] + dx;
        uint256 y = _get_y(i, j, x, old_balances);
        uint256 dy = old_balances[uint256(int256(j))] - y - 1;

        uint256 dy_fee = dy * FEE / 10**10;
        dy = dy - dy_fee;

        require(dy >= min_dy, "Slippage");

        IERC20(coins[uint256(int256(i))]).transferFrom(msg.sender, address(this), dx);
        balances[uint256(int256(i))] += dx;

        balances[uint256(int256(j))] -= dy;
        IERC20(coins[uint256(int256(j))]).transfer(msg.sender, dy);

        emit TokenExchange(msg.sender, i, dx, j, dy);

        return dy;
    }

    // Calculate output amount for exchange
    function _get_y(int128 i, int128 j, uint256 x, uint256[3] memory _balances) internal pure returns (uint256) {
        uint256 D = _get_D(_balances, A);
        uint256 c = D;
        uint256 S_ = 0;
        uint256 Ann = A * 3;

        uint256 _x = 0;
        for (uint _i = 0; _i < 3; _i++) {
            if (_i == uint256(int256(i))) {
                _x = x;
            } else if (_i != uint256(int256(j))) {
                _x = _balances[_i];
            } else {
                continue;
            }
            S_ += _x;
            c = c * D / (_x * 3);
        }
        c = c * D / (Ann * 3);
        uint256 b = S_ + D / Ann;

        uint256 y = D;
        for (uint _i = 0; _i < 255; _i++) {
            uint256 y_prev = y;
            y = (y * y + c) / (2 * y + b - D);
            if (y > y_prev) {
                if (y - y_prev <= 1) {
                    break;
                }
            } else {
                if (y_prev - y <= 1) {
                    break;
                }
            }
        }
        return y;
    }
}
