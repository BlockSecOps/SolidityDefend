/// Shared utility functions for context detection and pattern recognition

use crate::types::AnalysisContext;

/// Detects if the contract is an ERC-4626 compliant vault
///
/// ERC-4626 vaults have specific characteristics:
/// - Mint/burn shares (not tokens) - shares don't need max supply caps
/// - Must have deposit/withdraw/redeem functions
/// - Transfers underlying assets via external calls (normal behavior)
pub fn is_erc4626_vault(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for ERC-4626 interface functions
    let has_deposit = source.contains("function deposit(");
    let has_withdraw = source.contains("function withdraw(");
    let has_redeem = source.contains("function redeem(");
    let has_total_assets = source.contains("function totalAssets(")
        || source.contains("function totalAssets() ");

    // Check for share token characteristics
    let has_shares = source.contains("shares") || source.contains("_shares");
    let has_assets = source.contains("asset") || source.contains("_asset");

    // Must have at least 3 of the 4 core functions + share/asset mentions
    let function_count = [has_deposit, has_withdraw, has_redeem, has_total_assets]
        .iter()
        .filter(|&&x| x)
        .count();

    function_count >= 3 && has_shares && has_assets
}

/// Detects if the contract is an ERC-3156 flash loan provider
///
/// ERC-3156 flash loans have specific characteristics:
/// - flashLoan() function for borrowing
/// - onFlashLoan() callback for repayment validation
/// - Balance-based repayment verification
/// - Flash loan operations manipulate liquidity/state by design
pub fn is_erc3156_flash_loan(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for ERC-3156 flash loan functions
    let has_flash_loan = source.contains("function flashLoan(");
    let has_on_flash_loan = source.contains("onFlashLoan")
        || source.contains("IFlashBorrower")
        || source.contains("IERC3156FlashBorrower");

    // Check for ERC-3156 specific patterns
    let has_erc3156_marker = source.contains("ERC3156")
        || source.contains("ERC-3156")
        || source.contains("flashFee")
        || source.contains("maxFlashLoan");

    // Check for flash loan callback validation pattern
    let has_callback_validation = source.contains("ERC3156FlashBorrower.onFlashLoan")
        || (source.contains("keccak256") && source.contains("onFlashLoan"));

    // Check for balance-based repayment validation (common pattern)
    let has_balance_check = (source.contains("balanceBefore") && source.contains("balanceAfter"))
        || source.contains("repaid")
        || (source.contains("balance") && source.contains("flashLoan"));

    // Must have flashLoan function + at least 2 other indicators
    let indicator_count = [
        has_on_flash_loan,
        has_erc3156_marker,
        has_callback_validation,
        has_balance_check,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_flash_loan && indicator_count >= 2
}

/// Detects if the contract uses OpenZeppelin libraries
///
/// OpenZeppelin contracts are audited and generally safe
pub fn uses_openzeppelin(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    source.contains("@openzeppelin")
        || source.contains("import \"@openzeppelin")
        || source.contains("Ownable")
        || source.contains("AccessControl")
        || source.contains("ReentrancyGuard")
}

/// Detects if the function or contract has reentrancy guards
pub fn has_reentrancy_guard(function_source: &str, contract_source: &str) -> bool {
    function_source.contains("nonReentrant")
        || function_source.contains("ReentrancyGuard")
        || contract_source.contains("ReentrancyGuard")
        || function_source.contains("_reentrancyGuard")
        || function_source.contains("lock()") // Uniswap V2 style lock modifier
        || function_source.contains("modifier lock") // Lock modifier definition
        || (contract_source.contains("unlocked") && contract_source.contains("== 1")) // Uniswap V2 lock pattern
}

/// Detects if the contract uses SafeERC20 for token transfers
pub fn uses_safe_erc20(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    source.contains("SafeERC20")
        || source.contains("safeTransfer")
        || source.contains("safeTransferFrom")
}

/// Detects if an address parameter has zero-address validation
pub fn has_zero_address_check(function_source: &str, param_name: &str) -> bool {
    // Check for explicit zero address validation
    let patterns = [
        format!("require({} != address(0)", param_name),
        format!("require(address(0) != {}", param_name),
        format!("if ({} == address(0))", param_name),
        format!("if (address(0) == {})", param_name),
        format!("assert({} != address(0)", param_name),
    ];

    patterns.iter().any(|pattern| function_source.contains(pattern))
}

/// Detects if the contract implements a pull-over-push pattern
///
/// Pull-over-push is a safe pattern where users must claim funds
/// rather than having funds pushed to them
pub fn has_pull_pattern(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    (source.contains("claim") || source.contains("Claim"))
        && (source.contains("pending") || source.contains("claimable") || source.contains("owed"))
}

/// Detects if the function has actual delay mechanisms (not just asset transfers)
pub fn has_actual_delay_mechanism(function_source: &str) -> bool {
    // True delay indicators (time-based locks, not just external calls)
    let delay_indicators = [
        "delay",
        "lock",
        "lockTime",
        "unlockTime",
        "cooldown",
        "vestingPeriod",
        "block.timestamp +",
        "block.number +",
    ];

    delay_indicators.iter().any(|indicator| function_source.contains(indicator))
}

/// Detects if the contract is an ERC-4337 Account Abstraction contract
///
/// ERC-4337 contracts (Paymasters, Smart Accounts) have specific characteristics:
/// - validatePaymasterUserOp() or validateUserOp() for validation
/// - Session key management (temporary permissions)
/// - Nonce management for replay protection
/// - Social recovery patterns with guardians
/// - Functions use msg.sender checks instead of access modifiers (pattern is intentional)
pub fn is_erc4337_paymaster(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for ERC-4337 validation functions
    let has_paymaster_validation = source.contains("function validatePaymasterUserOp(")
        || source.contains("function validateUserOp(");

    // Check for UserOperation type usage
    let has_user_op = source.contains("UserOp")
        || source.contains("userOp")
        || source.contains("UserOperation");

    // Check for ERC-4337 specific markers
    let has_erc4337_marker = source.contains("ERC4337")
        || source.contains("ERC-4337")
        || source.contains("IPaymaster")
        || source.contains("EntryPoint");

    // Check for session key patterns
    let has_session_keys = (source.contains("sessionKey") || source.contains("SessionKey"))
        && (source.contains("addSessionKey") || source.contains("revokeSessionKey"));

    // Check for nonce management (ERC-4337 specific patterns)
    let has_nonce_management = (source.contains("function getNonce(")
        || source.contains("function incrementNonce("))
        && (source.contains("nonces") || source.contains("nonceSequenceNumber"));

    // Check for social recovery patterns
    let has_social_recovery = source.contains("guardian")
        && (source.contains("initiateRecovery")
            || source.contains("approveRecovery")
            || source.contains("completeRecovery"));

    // Must have validation function + at least 2 other indicators
    let indicator_count = [
        has_user_op,
        has_erc4337_marker,
        has_session_keys,
        has_nonce_management,
        has_social_recovery,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_paymaster_validation && indicator_count >= 2
}

/// Detects if the contract is a Uniswap V2 style AMM pair
///
/// Uniswap V2 pairs have specific characteristics:
/// - getReserves() function returning reserve amounts
/// - swap() function for token exchanges
/// - mint() and burn() for liquidity management
/// - token0 and token1 address variables
/// - TWAP price accumulator variables (price0CumulativeLast, price1CumulativeLast)
/// - Reentrancy lock pattern
/// - These contracts ARE the oracle source and should not be flagged for using spot prices
pub fn is_uniswap_v2_pair(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for core V2 pair functions
    let has_get_reserves = source.contains("function getReserves()")
        && (source.contains("reserve0") || source.contains("_reserve0"));
    let has_swap = source.contains("function swap(");
    let has_mint = source.contains("function mint(");
    let has_burn = source.contains("function burn(");

    // Check for token pair variables
    let has_token_pair = source.contains("token0") && source.contains("token1");

    // Check for TWAP price accumulators (key indicator of V2)
    let has_price_cumulative = source.contains("price0CumulativeLast")
        || source.contains("price1CumulativeLast")
        || source.contains("priceCumulative");

    // Check for reentrancy lock pattern (common in V2)
    let has_lock_pattern = source.contains("modifier lock()")
        || (source.contains("unlocked") && source.contains("== 1"));

    // Check for MINIMUM_LIQUIDITY constant (V2 specific)
    let has_minimum_liquidity = source.contains("MINIMUM_LIQUIDITY");

    // Must have core functions + token pair + at least 2 other indicators
    let core_functions = has_get_reserves && has_swap && has_mint && has_burn;
    let indicator_count = [
        has_price_cumulative,
        has_lock_pattern,
        has_minimum_liquidity,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    core_functions && has_token_pair && indicator_count >= 2
}

/// Detects if the contract is a Uniswap V3 style AMM pool
///
/// Uniswap V3 pools have specific characteristics:
/// - slot0() function with tick and price info
/// - observe() function for TWAP oracle
/// - Tick-based liquidity management
/// - Advanced fee tiers and concentrated liquidity
/// - These contracts provide TWAP oracle functionality
pub fn is_uniswap_v3_pool(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for V3 core functions
    let has_slot0 = source.contains("function slot0()") || source.contains("slot0() ");
    let has_observe = source.contains("function observe(") || source.contains("observe(uint32[] ");

    // Check for V3 swap function signature
    let has_v3_swap = source.contains("function swap(")
        && (source.contains("sqrtPriceLimitX96") || source.contains("zeroForOne"));

    // Check for tick-based liquidity
    let has_ticks = source.contains("tick") || source.contains("Tick");
    let has_liquidity = source.contains("liquidity");

    // Check for V3 position management
    let has_positions = source.contains("position") || source.contains("Position");

    // Check for fee tiers (V3 specific)
    let has_fee_tier = source.contains("fee") && (source.contains("500") || source.contains("3000") || source.contains("10000"));

    // Must have slot0 + observe (TWAP oracle) + at least 2 other V3 indicators
    let has_v3_oracle = has_slot0 && has_observe;
    let indicator_count = [has_v3_swap, has_ticks, has_positions, has_fee_tier]
        .iter()
        .filter(|&&x| x)
        .count();

    has_v3_oracle && has_liquidity && indicator_count >= 2
}

/// Detects if the contract is a Uniswap V4 style AMM with hooks
///
/// Uniswap V4 characteristics:
/// - Hook system (beforeSwap, afterSwap, beforeAddLiquidity, afterAddLiquidity, etc.)
/// - PoolManager singleton pattern
/// - Delta accounting system (BalanceDelta)
/// - EIP-1153 transient storage usage
/// - Dynamic fee structure based on hooks
pub fn is_uniswap_v4_pool(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for V4 hook functions
    let has_before_swap = source.contains("function beforeSwap(")
        || source.contains("beforeSwap(address,PoolKey");
    let has_after_swap =
        source.contains("function afterSwap(") || source.contains("afterSwap(address,PoolKey");

    // Check for V4 hook system
    let has_hooks = (source.contains("beforeSwap")
        || source.contains("afterSwap")
        || source.contains("beforeAddLiquidity")
        || source.contains("afterAddLiquidity"))
        && (source.contains("IHooks") || source.contains("BaseHook"));

    // Check for PoolManager pattern
    let has_pool_manager = source.contains("PoolManager")
        || source.contains("IPoolManager")
        || source.contains("poolManager");

    // Check for BalanceDelta type (V4 specific)
    let has_balance_delta = source.contains("BalanceDelta") || source.contains("toBalanceDelta");

    // Check for transient storage (EIP-1153, V4 uses this heavily)
    let has_transient_storage = source.contains("tstore") || source.contains("tload");

    // Check for V4 PoolKey structure
    let has_pool_key = source.contains("PoolKey") || source.contains("poolKey");

    // Must have hooks + at least 2 other V4 indicators
    let indicator_count = [
        has_pool_manager,
        has_balance_delta,
        has_transient_storage,
        has_pool_key,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_hooks && indicator_count >= 2
}

/// Detects if the contract is a Curve Finance style AMM
///
/// Curve Finance characteristics:
/// - StableSwap algorithm for low-slippage stablecoin swaps
/// - exchange() function with int128 token indices
/// - get_virtual_price() for share price calculation
/// - A (amplification coefficient) parameter
/// - coins() and balances() arrays for pool tokens
/// - Meta pools and factory pools
pub fn is_curve_amm(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for Curve-specific exchange function
    let has_exchange = source.contains("function exchange(int128")
        || (source.contains("function exchange(") && source.contains("int128"));

    // Check for virtual price (key Curve concept)
    let has_virtual_price = source.contains("function get_virtual_price(")
        || source.contains("get_virtual_price()");

    // Check for amplification coefficient (StableSwap algorithm)
    let has_amplification = source.contains("function A()")
        || source.contains("function get_A()")
        || source.contains("amplification");

    // Check for Curve token arrays (coins, balances)
    let has_coins_array = source.contains("function coins(")
        || source.contains("coins[") || source.contains("coins(uint256");
    let has_balances_array = source.contains("function balances(")
        || source.contains("balances[") || source.contains("balances(uint256");

    // Check for Curve-specific patterns
    let has_curve_marker =
        source.contains("StableSwap") || source.contains("Curve") || source.contains("CurveFi");

    // Check for dy calculation (Curve naming convention)
    let has_dy_calculation =
        source.contains("get_dy") || source.contains("calc_token_amount") || source.contains("dy");

    // Must have exchange function + at least 3 other indicators
    let indicator_count = [
        has_virtual_price,
        has_amplification,
        has_coins_array && has_balances_array,
        has_curve_marker,
        has_dy_calculation,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_exchange && indicator_count >= 3
}

/// Detects if the contract is a Balancer style AMM
///
/// Balancer characteristics:
/// - Weighted pools with customizable token weights
/// - Stable pools with amplification parameter
/// - onSwap() hook function for pool logic
/// - getPoolId() returning bytes32 pool identifier
/// - Vault-based architecture (pool tokens held by Vault)
/// - getNormalizedWeights() for weighted pools
/// - getAmplificationParameter() for stable pools
pub fn is_balancer_amm(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for Balancer Vault architecture
    let has_pool_id = source.contains("function getPoolId()")
        || source.contains("getPoolId() ")
        || source.contains("poolId");

    // Check for onSwap hook (Balancer pool interface)
    let has_on_swap = source.contains("function onSwap(") && source.contains("SwapRequest");

    // Check for Balancer weighted pool functions
    let has_normalized_weights = source.contains("function getNormalizedWeights(")
        || source.contains("getNormalizedWeights()");

    // Check for Balancer stable pool functions
    let has_amplification_param = source.contains("function getAmplificationParameter(")
        || source.contains("getAmplificationParameter()");

    // Check for Balancer marker interfaces
    let has_balancer_marker = source.contains("IBalancer")
        || source.contains("BasePool")
        || source.contains("IVault")
        || source.contains("Balancer");

    // Check for Balancer pool token management
    let has_pool_tokens = source.contains("function getPoolTokens(")
        || source.contains("getPoolTokens()")
        || source.contains("IERC20[] ");

    // Check for Balancer-specific patterns
    let has_balancer_math =
        source.contains("WeightedMath") || source.contains("StableMath") || source.contains("_calcOutGivenIn");

    // Must have pool ID + at least 2 other Balancer indicators
    let indicator_count = [
        has_on_swap,
        has_normalized_weights || has_amplification_param,
        has_balancer_marker,
        has_pool_tokens,
        has_balancer_math,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_pool_id && indicator_count >= 2
}

/// Detects if the contract is any type of AMM/DEX pool
///
/// This is a generic AMM detection that covers various AMM implementations
/// including Uniswap V2/V3/V4, Curve, Balancer, etc.
pub fn is_amm_pool(ctx: &AnalysisContext) -> bool {
    // Check for specific AMM types first
    if is_uniswap_v2_pair(ctx)
        || is_uniswap_v3_pool(ctx)
        || is_uniswap_v4_pool(ctx)
        || is_curve_amm(ctx)
        || is_balancer_amm(ctx)
    {
        return true;
    }

    let source = ctx.source_code.as_str();

    // Generic AMM indicators
    let has_swap = source.contains("function swap(") || source.contains("function exchange(");
    let has_liquidity_ops = (source.contains("function addLiquidity")
        || source.contains("function removeLiquidity"))
        && (source.contains("function mint(") || source.contains("function burn("));

    // Check for reserve or balance management
    let has_reserves = source.contains("reserve") || source.contains("Reserve");
    let has_pool_tokens = (source.contains("token0") && source.contains("token1"))
        || source.contains("poolTokens")
        || source.contains("coins");

    // Check for AMM-specific patterns
    let has_k_invariant = source.contains("* balance") || source.contains("balance0 * balance1");
    let has_price_calculation = source.contains("getAmountOut")
        || source.contains("getAmountIn")
        || source.contains("get_dy");

    // Must have swap + liquidity operations + at least 2 other indicators
    let indicator_count = [
        has_reserves,
        has_pool_tokens,
        has_k_invariant,
        has_price_calculation,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_swap && has_liquidity_ops && indicator_count >= 2
}

/// Detects if the contract is a Compound-style cToken
///
/// Compound cTokens are interest-bearing tokens that represent deposits:
/// - mint() to deposit underlying assets
/// - redeem() to withdraw underlying assets
/// - borrow() to borrow against collateral
/// - repayBorrow() to repay borrowed assets
/// - liquidateBorrow() for undercollateralized positions
/// - Exchange rate and interest rate calculations
pub fn is_compound_ctoken(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for cToken core functions (mint/redeem/borrow/repay)
    let has_mint = source.contains("function mint(") && source.contains("mintAmount");
    let has_redeem = source.contains("function redeem(") && source.contains("redeemTokens");
    let has_borrow = source.contains("function borrow(") && source.contains("borrowAmount");
    let has_repay_borrow = source.contains("function repayBorrow(")
        || source.contains("function repayBorrowBehalf(");

    // Check for liquidation function (Compound-specific signature)
    let has_liquidate_borrow = source.contains("function liquidateBorrow(")
        && source.contains("cTokenCollateral");

    // Check for exchange rate (cToken to underlying conversion)
    let has_exchange_rate = source.contains("function exchangeRateCurrent(")
        || source.contains("function exchangeRateStored(")
        || source.contains("exchangeRate");

    // Check for interest rate functions
    let has_interest_rates = (source.contains("function borrowRatePerBlock(")
        || source.contains("function supplyRatePerBlock("))
        || (source.contains("borrowRate") && source.contains("supplyRate"));

    // Check for comptroller reference
    let has_comptroller = source.contains("comptroller")
        || source.contains("Comptroller")
        || source.contains("IComptroller");

    // Check for underlying asset
    let has_underlying =
        source.contains("underlying") || source.contains("UNDERLYING_ASSET_ADDRESS");

    // Check for Compound-specific markers
    let has_compound_marker = source.contains("CToken")
        || source.contains("cToken")
        || source.contains("CErc20")
        || source.contains("CEther");

    // Must have core lending operations + at least 3 other indicators
    let core_operations = has_mint && has_redeem && has_borrow && has_repay_borrow;
    let indicator_count = [
        has_liquidate_borrow,
        has_exchange_rate,
        has_interest_rates,
        has_comptroller,
        has_underlying,
        has_compound_marker,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    core_operations && indicator_count >= 3
}

/// Detects if the contract is a Compound Comptroller (risk management)
///
/// Comptroller manages risk parameters across all cToken markets:
/// - enterMarkets() to enable collateral
/// - exitMarket() to disable collateral
/// - getAccountLiquidity() to check account health
/// - liquidateBorrowAllowed() for liquidation validation
/// - Market parameters and collateral factors
pub fn is_compound_comptroller(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for market entry/exit functions
    let has_enter_markets = source.contains("function enterMarkets(")
        && source.contains("cTokens")
        && source.contains("[]");
    let has_exit_market =
        source.contains("function exitMarket(") && source.contains("cToken");

    // Check for account liquidity calculation
    let has_account_liquidity = source.contains("function getAccountLiquidity(")
        || source.contains("function getHypotheticalAccountLiquidity(");

    // Check for liquidation allowed validation
    let has_liquidate_allowed = source.contains("function liquidateBorrowAllowed(")
        || source.contains("function liquidateCalculateSeizeTokens(");

    // Check for markets mapping
    let has_markets_mapping = (source.contains("mapping") && source.contains("markets"))
        || source.contains("function markets(");

    // Check for collateral factor
    let has_collateral_factor = source.contains("collateralFactor")
        || source.contains("collateralFactorMantissa")
        || source.contains("CollateralFactor");

    // Check for Comptroller markers
    let has_comptroller_marker = source.contains("Comptroller")
        || source.contains("comptroller")
        || source.contains("IComptroller");

    // Check for price oracle
    let has_oracle = source.contains("oracle") && source.contains("PriceOracle");

    // Must have market management + at least 3 other indicators
    let has_market_management = has_enter_markets && has_exit_market;
    let indicator_count = [
        has_account_liquidity,
        has_liquidate_allowed,
        has_markets_mapping,
        has_collateral_factor,
        has_comptroller_marker,
        has_oracle,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_market_management && indicator_count >= 3
}

/// Detects if the contract is an Aave LendingPool
///
/// Aave LendingPool is the core lending protocol contract:
/// - deposit() to supply assets
/// - withdraw() to retrieve supplied assets
/// - borrow() to borrow assets
/// - repay() to repay borrowed assets
/// - liquidationCall() for liquidating undercollateralized positions
/// - flashLoan() for flash loan functionality
pub fn is_aave_lending_pool(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for Aave V2/V3 core functions
    let has_deposit = source.contains("function deposit(")
        && source.contains("onBehalfOf")
        && source.contains("referralCode");
    let has_withdraw =
        source.contains("function withdraw(") && source.contains("asset");
    let has_borrow = source.contains("function borrow(")
        && source.contains("interestRateMode")
        && source.contains("asset");
    let has_repay = source.contains("function repay(") && source.contains("rateMode");

    // Check for liquidation call (Aave-specific signature)
    let has_liquidation_call = source.contains("function liquidationCall(")
        && (source.contains("debtToCover") || source.contains("collateralAsset"));

    // Check for flash loan function
    let has_flash_loan = source.contains("function flashLoan(")
        && source.contains("receiverAddress")
        && source.contains("assets")
        && source.contains("[]");

    // Check for reserve data
    let has_reserve_data = source.contains("function getReserveData(")
        || source.contains("ReserveData")
        || source.contains("getReserveNormalizedIncome");

    // Check for user account data
    let has_user_account_data = source.contains("function getUserAccountData(")
        || source.contains("healthFactor")
        || source.contains("totalDebtETH");

    // Check for Aave markers
    let has_aave_marker = source.contains("LendingPool")
        || source.contains("ILendingPool")
        || source.contains("ADDRESSES_PROVIDER")
        || source.contains("POOL");

    // Check for aToken integration
    let has_atoken = source.contains("aToken") || source.contains("IAToken");

    // Must have core operations + at least 3 other indicators
    let core_operations = has_deposit && has_withdraw && has_borrow && has_repay;
    let indicator_count = [
        has_liquidation_call,
        has_flash_loan,
        has_reserve_data,
        has_user_account_data,
        has_aave_marker,
        has_atoken,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    core_operations && indicator_count >= 3
}

/// Detects if the contract is an Aave aToken (interest-bearing token)
///
/// Aave aTokens are rebasing tokens that represent deposits in Aave:
/// - POOL() reference to LendingPool
/// - UNDERLYING_ASSET_ADDRESS() for the underlying asset
/// - scaledBalanceOf() for balance calculations
/// - mint() and burn() only callable by LendingPool
pub fn is_aave_atoken(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for POOL reference (Aave V3) or getLendingPool (V2)
    let has_pool = source.contains("function POOL()")
        || source.contains("function pool()")
        || source.contains("function getLendingPool()");

    // Check for underlying asset address
    let has_underlying = source.contains("function UNDERLYING_ASSET_ADDRESS()")
        || source.contains("_underlyingAsset");

    // Check for scaled balance (rebasing token pattern)
    let has_scaled_balance = source.contains("function scaledBalanceOf(")
        || source.contains("scaledTotalSupply")
        || source.contains("_userState");

    // Check for mint function (only callable by LendingPool)
    let has_mint = source.contains("function mint(")
        && (source.contains("onlyPool") || source.contains("onlyLendingPool"));

    // Check for burn function (only callable by LendingPool)
    let has_burn = source.contains("function burn(")
        && (source.contains("onlyPool") || source.contains("receiverOfUnderlying"));

    // Check for Aave aToken markers
    let has_atoken_marker = source.contains("AToken")
        || source.contains("aToken")
        || source.contains("IAToken")
        || source.contains("IncentivizedERC20");

    // Check for interest accrual
    let has_interest = source.contains("liquidityIndex")
        || source.contains("getIncentivesController")
        || source.contains("_accrueToTreasury");

    // Must have pool reference + scaled balance + at least 2 other indicators
    let indicator_count = [
        has_underlying,
        has_mint,
        has_burn,
        has_atoken_marker,
        has_interest,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_pool && has_scaled_balance && indicator_count >= 2
}

/// Detects if the contract is a MakerDAO Vat (vault system)
///
/// MakerDAO Vat is the core CDP (Collateralized Debt Position) engine:
/// - frob() to adjust vault collateral and debt
/// - fork() to split vaults
/// - grab() for liquidations
/// - urns mapping for vault data
/// - ilks mapping for collateral type data
pub fn is_makerdao_vault(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for frob function (adjust collateral/debt)
    let has_frob = source.contains("function frob(")
        && source.contains("ilk")
        && source.contains("dink")
        && source.contains("dart");

    // Check for fork function (split vault)
    let has_fork = source.contains("function fork(") && source.contains("ilk");

    // Check for grab function (liquidation)
    let has_grab = source.contains("function grab(") && source.contains("ilk");

    // Check for urns mapping (vault data)
    let has_urns = (source.contains("mapping") && source.contains("urns"))
        || source.contains("function urns(");

    // Check for ilks mapping (collateral type data)
    let has_ilks = (source.contains("mapping") && source.contains("ilks"))
        || source.contains("function ilks(");

    // Check for gem mapping (collateral balances)
    let has_gem =
        (source.contains("mapping") && source.contains("gem")) || source.contains("function gem(");

    // Check for MakerDAO Vat markers
    let has_vat_marker = source.contains("Vat")
        || source.contains("vat")
        || source.contains("ilk")
        || source.contains("bytes32");

    // Check for debt and collateral terms
    let has_debt_terms = source.contains("art") // normalized debt
        || source.contains("ink") // locked collateral
        || source.contains("rate") // debt multiplier
        || source.contains("spot"); // price with safety margin

    // Must have frob + at least 3 other indicators
    let indicator_count = [
        has_fork || has_grab,
        has_urns,
        has_ilks,
        has_gem,
        has_vat_marker,
        has_debt_terms,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_frob && indicator_count >= 3
}

/// Detects if the contract is any type of lending protocol
///
/// This is a generic lending protocol detection that covers various implementations
/// including Compound, Aave, MakerDAO, and custom lending protocols
pub fn is_lending_protocol(ctx: &AnalysisContext) -> bool {
    // Check for specific lending protocol types first
    if is_compound_ctoken(ctx)
        || is_compound_comptroller(ctx)
        || is_aave_lending_pool(ctx)
        || is_aave_atoken(ctx)
        || is_makerdao_vault(ctx)
    {
        return true;
    }

    let source = ctx.source_code.as_str();

    // Generic lending protocol indicators
    let has_deposit_withdraw = (source.contains("function deposit(")
        || source.contains("function supply("))
        && (source.contains("function withdraw(") || source.contains("function redeem("));

    let has_borrow_repay = source.contains("function borrow(")
        && (source.contains("function repay(") || source.contains("function repayBorrow("));

    // Check for collateral management
    let has_collateral = source.contains("collateral")
        || source.contains("Collateral")
        || source.contains("collateralFactor")
        || source.contains("LTV");

    // Check for liquidation
    let has_liquidation = source.contains("liquidat") || source.contains("Liquidat");

    // Check for health factor / account liquidity
    let has_health_check = source.contains("healthFactor")
        || source.contains("accountLiquidity")
        || source.contains("getAccountLiquidity");

    // Check for interest rate calculations
    let has_interest_rates = source.contains("interestRate")
        || source.contains("borrowRate")
        || source.contains("supplyRate")
        || source.contains("utilizationRate");

    // Must have deposit/withdraw + borrow/repay + at least 2 other indicators
    let indicator_count = [
        has_collateral,
        has_liquidation,
        has_health_check,
        has_interest_rates,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_deposit_withdraw && has_borrow_repay && indicator_count >= 2
}

/// Detects if the contract is a flash loan provider
///
/// Flash loan providers include:
/// - ERC-3156 compliant contracts
/// - Aave LendingPool (provides flash loans)
/// - Compound-style flash loans
/// - Custom flash loan implementations
pub fn is_flash_loan_provider(ctx: &AnalysisContext) -> bool {
    // Check for ERC-3156 compliance first
    if is_erc3156_flash_loan(ctx) {
        return true;
    }

    // Check if it's Aave LendingPool (provides flash loans)
    if is_aave_lending_pool(ctx) {
        return true;
    }

    let source = ctx.source_code.as_str();

    // Check for flash loan function signatures
    let has_flash_loan_function = source.contains("function flashLoan(")
        && (source.contains("receiverAddress") || source.contains("receiver"));

    // Check for flash loan callback interface
    let has_callback = source.contains("executeOperation")
        || source.contains("onFlashLoan")
        || source.contains("receiveFlashLoan");

    // Check for flash loan fee calculation
    let has_fee = (source.contains("flashLoanFee") || source.contains("FLASHLOAN_PREMIUM"))
        && (source.contains("function") || source.contains("uint"));

    // Check for balance validation (flash loan must return borrowed amount + fee)
    let has_balance_check =
        source.contains("balanceAfter") || source.contains("require(balance");

    // Must have flash loan function + at least 2 other indicators
    let indicator_count = [has_callback, has_fee, has_balance_check]
        .iter()
        .filter(|&&x| x)
        .count();

    has_flash_loan_function && indicator_count >= 2
}

/// Detects governance protocols (Governor Bravo, OpenZeppelin Governor, etc.)
///
/// Governance protocols manage protocol upgrades and parameter changes through
/// decentralized voting. Examples: Compound Governor Bravo, Uniswap Governor,
/// OpenZeppelin Governor.
///
/// Detection requires:
/// - Core governance functions (propose, vote, execute)
/// - At least 3 additional indicators (proposal state, delegation, timelock, quorum)
///
/// This helps avoid FPs on contracts with governance-like patterns but aren't
/// actual governance systems (e.g., lending protocols with delegate for proxies).
pub fn is_governance_protocol(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // Core governance functions - REQUIRED
    let has_propose = lower.contains("function propose(")
        || (lower.contains("propose(") && lower.contains("targets"))
        || lower.contains("function propose");

    let has_vote = lower.contains("function castvote")
        || lower.contains("function vote(")
        || lower.contains("function cast");

    let has_execute = (lower.contains("function execute(") || lower.contains("function executeproposal"))
        && (lower.contains("proposal") || lower.contains("targets"));

    // Must have core governance functions
    if !has_propose || !has_vote || !has_execute {
        return false;
    }

    // Additional governance indicators
    let has_proposal_state = lower.contains("proposalstate")
        || (lower.contains("enum") && (lower.contains("pending") && lower.contains("succeeded")))
        || lower.contains("state(uint256");

    let has_delegation = lower.contains("delegate(address")
        || lower.contains("delegatebyvote")
        || lower.contains("delegatebysig");

    let has_timelock = lower.contains("timelock")
        || lower.contains("eta")
        || lower.contains("queuedtransactions");

    let has_quorum = lower.contains("quorum")
        || lower.contains("quorumvotes")
        || lower.contains("votingdelay")
        || lower.contains("votingperiod");

    let has_voting_power = lower.contains("getvotes")
        || lower.contains("getpriorvotes")
        || lower.contains("votingpower");

    let has_proposal_struct = source.contains("struct Proposal")
        || (source.contains("struct") && lower.contains("proposer"));

    // Count additional indicators (need at least 3 for high confidence)
    let indicator_count = [
        has_proposal_state,
        has_delegation,
        has_timelock,
        has_quorum,
        has_voting_power,
        has_proposal_struct,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    indicator_count >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erc4626_detection() {
        // This would need a proper AnalysisContext mock
        // Placeholder for future tests
    }
}
