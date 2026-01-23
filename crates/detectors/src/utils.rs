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
    let has_total_assets =
        source.contains("function totalAssets(") || source.contains("function totalAssets() ");

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

    patterns
        .iter()
        .any(|pattern| function_source.contains(pattern))
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

    delay_indicators
        .iter()
        .any(|indicator| function_source.contains(indicator))
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
    let has_user_op =
        source.contains("UserOp") || source.contains("userOp") || source.contains("UserOperation");

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
    let has_fee_tier = source.contains("fee")
        && (source.contains("500") || source.contains("3000") || source.contains("10000"));

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
    let _has_before_swap =
        source.contains("function beforeSwap(") || source.contains("beforeSwap(address,PoolKey");
    let _has_after_swap =
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
    let has_virtual_price =
        source.contains("function get_virtual_price(") || source.contains("get_virtual_price()");

    // Check for amplification coefficient (StableSwap algorithm)
    let has_amplification = source.contains("function A()")
        || source.contains("function get_A()")
        || source.contains("amplification");

    // Check for Curve token arrays (coins, balances)
    let has_coins_array = source.contains("function coins(")
        || source.contains("coins[")
        || source.contains("coins(uint256");
    let has_balances_array = source.contains("function balances(")
        || source.contains("balances[")
        || source.contains("balances(uint256");

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
    let has_balancer_math = source.contains("WeightedMath")
        || source.contains("StableMath")
        || source.contains("_calcOutGivenIn");

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
    let has_repay_borrow =
        source.contains("function repayBorrow(") || source.contains("function repayBorrowBehalf(");

    // Check for liquidation function (Compound-specific signature)
    let has_liquidate_borrow =
        source.contains("function liquidateBorrow(") && source.contains("cTokenCollateral");

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
    let has_exit_market = source.contains("function exitMarket(") && source.contains("cToken");

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
    let has_withdraw = source.contains("function withdraw(") && source.contains("asset");
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
    let has_balance_check = source.contains("balanceAfter") || source.contains("require(balance");

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

    let has_execute = (lower.contains("function execute(")
        || lower.contains("function executeproposal"))
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

    let has_timelock =
        lower.contains("timelock") || lower.contains("eta") || lower.contains("queuedtransactions");

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

// ===========================================================================
// PHASE 9 FP REDUCTION: TEST CONTRACT AND ERC INTERFACE DETECTION
// ===========================================================================

/// Detects if the contract is a test, mock, or example contract
///
/// Test contracts should generally be skipped by detectors as they:
/// - Often intentionally contain vulnerable patterns for testing
/// - Are not deployed to production
/// - Clutter results with non-actionable findings
///
/// Detection based on:
/// - Contract name patterns (Test, Mock, Vulnerable, Example, Demo)
/// - File path patterns (/test/, /tests/, .t.sol)
/// - Common test framework indicators
pub fn is_test_contract(ctx: &AnalysisContext) -> bool {
    let name = ctx.contract.name.name.to_lowercase();
    let file = ctx.file_path.to_lowercase();

    // Contract name patterns indicating test/mock
    let is_test_name = name.contains("test")
        || name.contains("mock")
        || name.contains("vulnerable")
        || name.contains("example")
        || name.contains("demo")
        || name.contains("stub")
        || name.contains("fake")
        || name.contains("helper")
        || name.starts_with("t_")
        || name.ends_with("_test");

    // File path patterns indicating test directory
    let is_test_file = file.contains("/test/")
        || file.contains("/tests/")
        || file.contains("/testing/")
        || file.contains(".t.sol")
        || file.contains("_test.sol")
        || file.contains("/mocks/")
        || file.contains("/mock/");

    is_test_name || is_test_file
}

/// Detects if the file is a "secure" example demonstrating safe patterns
///
/// These files are documentation/examples showing correct implementations
/// and should generally have fewer findings than vulnerable examples.
/// Phase 10: Added to reduce FPs in demonstration files
pub fn is_secure_example_file(ctx: &AnalysisContext) -> bool {
    let file = ctx.file_path.to_lowercase();
    let name = ctx.contract.name.name.to_lowercase();

    // File path patterns indicating secure examples
    let is_secure_file = file.contains("secure")
        || file.contains("safe")
        || file.contains("/secure/")
        || file.contains("/safe/");

    // Contract name patterns indicating secure implementation
    let is_secure_name = name.contains("secure")
        || name.contains("safe")
        || name.ends_with("fixed")
        || name.ends_with("patched");

    is_secure_file || is_secure_name
}

/// Detects if the contract is a flash loan provider or borrower
///
/// Flash loans have specific patterns that should not be flagged
/// as unprotected withdrawals. Phase 10: FP reduction
pub fn is_flash_loan_context(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for flash loan function names
    let has_flash_loan_func = source.contains("function flashLoan(")
        || source.contains("function flash(")
        || source.contains("function executeFlash(");

    // Check for flash loan interfaces
    let has_flash_interface = source.contains("IFlashLoan")
        || source.contains("IERC3156")
        || source.contains("IFlashBorrower")
        || source.contains("FlashLoan");

    // Check for flash loan callback
    let has_callback = source.contains("onFlashLoan")
        || source.contains("flashLoanCallback")
        || source.contains("executeOperation"); // Aave pattern

    has_flash_loan_func || has_flash_interface || has_callback
}

/// Detects if the function is a batch execution pattern
///
/// Batch functions like executeBatch, multicall are common patterns
/// that involve callbacks but are not circular dependencies.
/// Phase 10: FP reduction
pub fn is_batch_execution_pattern(function_name: &str, func_source: &str) -> bool {
    let name_lower = function_name.to_lowercase();

    // Common batch function names
    let is_batch_name = name_lower.contains("batch")
        || name_lower.contains("multicall")
        || name_lower.contains("aggregate")
        || name_lower == "execute"
        || name_lower == "executecall"
        || name_lower == "executecalls";

    // Batch execution patterns in source
    let has_batch_pattern = func_source.contains("for (")
        && (func_source.contains("calls[i]")
            || func_source.contains("targets[i]")
            || func_source.contains("data[i]"));

    is_batch_name || has_batch_pattern
}

/// Detects if the contract is an ERC-20 compliant token
///
/// ERC-20 tokens follow a standardized interface:
/// - transfer(address, uint256)
/// - transferFrom(address, address, uint256)
/// - approve(address, uint256)
/// - balanceOf(address)
/// - totalSupply()
/// - allowance(address, address)
pub fn is_erc20_token(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // Check for ERC20 interface indicator or explicit marker
    if lower.contains("ierc20") || lower.contains("erc20") || lower.contains("erc-20") {
        return true;
    }

    // Check for core ERC20 function signatures
    let has_transfer = lower.contains("function transfer(address")
        && lower.contains("uint256")
        && lower.contains("returns (bool");
    let has_transfer_from = lower.contains("function transferfrom(address");
    let has_approve = lower.contains("function approve(address");
    let has_balance_of = lower.contains("function balanceof(address");
    let has_total_supply = lower.contains("function totalsupply(");
    let has_allowance = lower.contains("function allowance(address");

    // Must have at least 4 of the 6 core functions
    let function_count = [
        has_transfer,
        has_transfer_from,
        has_approve,
        has_balance_of,
        has_total_supply,
        has_allowance,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    function_count >= 4
}

/// Detects if the contract is an ERC-721 compliant NFT
///
/// ERC-721 NFTs follow a standardized interface:
/// - ownerOf(uint256)
/// - balanceOf(address)
/// - transferFrom(address, address, uint256)
/// - safeTransferFrom(address, address, uint256)
/// - approve(address, uint256)
/// - setApprovalForAll(address, bool)
pub fn is_erc721_token(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // Check for ERC721 interface indicator
    if lower.contains("ierc721") || lower.contains("erc721") || lower.contains("erc-721") {
        return true;
    }

    // Check for core ERC721 function signatures
    let has_owner_of = lower.contains("function ownerof(uint256");
    let has_balance_of = lower.contains("function balanceof(address");
    let has_safe_transfer = lower.contains("function safetransferfrom(");
    let has_approval_for_all = lower.contains("function setapprovalforall(");
    let has_get_approved = lower.contains("function getapproved(uint256");

    // Check for NFT-specific patterns
    let has_token_uri = lower.contains("function tokenuri(") || lower.contains("function tokenof(");

    // Must have at least 3 core functions + token-specific patterns
    let function_count = [
        has_owner_of,
        has_balance_of,
        has_safe_transfer,
        has_approval_for_all,
        has_get_approved,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    function_count >= 3 || (function_count >= 2 && has_token_uri)
}

/// Detects if the contract is an ERC-1155 multi-token
///
/// ERC-1155 multi-tokens support batch operations:
/// - balanceOf(address, uint256)
/// - balanceOfBatch(address[], uint256[])
/// - safeTransferFrom(address, address, uint256, uint256, bytes)
/// - safeBatchTransferFrom(...)
/// - setApprovalForAll(address, bool)
pub fn is_erc1155_token(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // Check for ERC1155 interface indicator
    if lower.contains("ierc1155") || lower.contains("erc1155") || lower.contains("erc-1155") {
        return true;
    }

    // Check for ERC1155-specific batch operations
    let has_balance_of_batch = lower.contains("function balanceofbatch(");
    let has_safe_batch_transfer = lower.contains("function safebatchtransferfrom(");

    // Must have batch operations (these are unique to ERC1155)
    has_balance_of_batch || has_safe_batch_transfer
}

/// Detects if the contract implements any standard ERC token interface
pub fn is_standard_token(ctx: &AnalysisContext) -> bool {
    is_erc20_token(ctx) || is_erc721_token(ctx) || is_erc1155_token(ctx) || is_erc4626_vault(ctx)
}

/// Detects if the contract is a factory pattern
///
/// Factory contracts create other contracts:
/// - Name contains "Factory", "Deployer", "Registry"
/// - Has create/deploy functions
/// - Uses CREATE or CREATE2 opcode patterns
pub fn is_factory_contract(ctx: &AnalysisContext) -> bool {
    let name = ctx.contract.name.name.to_lowercase();
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // Factory naming patterns
    let has_factory_name = name.contains("factory")
        || name.contains("deployer")
        || name.contains("creator")
        || name.contains("registry");

    // Factory function patterns
    let has_create_function = lower.contains("function create(")
        || lower.contains("function deploy(")
        || lower.contains("function createpair(")
        || lower.contains("function createpool(")
        || lower.contains("function createtoken(");

    // CREATE2 usage (deployment with deterministic address)
    let has_create2 = lower.contains("create2(") || lower.contains("new ") && lower.contains("salt");

    has_factory_name || (has_create_function && has_create2)
}

/// Detects if the contract is a bridge or cross-chain contract
///
/// Bridge contracts handle cross-chain communication:
/// - Name contains "Bridge", "Relay", "CrossChain", "Gateway"
/// - Has message relay functions
/// - Has merkle proof verification
pub fn is_bridge_contract(ctx: &AnalysisContext) -> bool {
    let name = ctx.contract.name.name.to_lowercase();
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // Bridge naming patterns
    let has_bridge_name = name.contains("bridge")
        || name.contains("relay")
        || name.contains("crosschain")
        || name.contains("cross_chain")
        || name.contains("gateway")
        || name.contains("messenger");

    // Bridge function patterns
    let has_bridge_functions = (lower.contains("function relay")
        || lower.contains("function finalize")
        || lower.contains("function receivemessage")
        || lower.contains("function sendmessage"))
        && (lower.contains("proof") || lower.contains("merkle") || lower.contains("message"));

    // L2/rollup specific patterns
    let has_l2_patterns = lower.contains("l1") && lower.contains("l2")
        || lower.contains("rollup")
        || lower.contains("optimism")
        || lower.contains("arbitrum");

    has_bridge_name || has_bridge_functions || has_l2_patterns
}

/// Detects if the contract is an EIP-7702 delegation context
///
/// EIP-7702 contracts handle account delegation:
/// - AUTH/AUTHCALL opcodes
/// - setCode patterns
/// - Delegation-related naming
pub fn is_eip7702_context(ctx: &AnalysisContext) -> bool {
    let name = ctx.contract.name.name.to_lowercase();
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // EIP-7702 specific patterns (require 2+ indicators)
    let has_auth = lower.contains("auth") && !lower.contains("authorize"); // AUTH opcode, not authorization
    let has_authcall = lower.contains("authcall");
    let has_setcode = lower.contains("setcode") || lower.contains("set_code");
    let has_7702_marker = lower.contains("7702") || lower.contains("eip7702") || lower.contains("eip-7702");

    // Account abstraction patterns
    let has_aa_patterns = lower.contains("validateuserop")
        || lower.contains("entrypoint")
        || lower.contains("eip4337")
        || lower.contains("useroperaction");

    // Delegation naming
    let has_delegation_name = name.contains("delegate")
        || name.contains("delegation")
        || name.contains("account")
        || name.contains("wallet")
        || name.contains("proxy");

    // Count indicators
    let indicator_count = [
        has_auth,
        has_authcall,
        has_setcode,
        has_7702_marker,
        has_aa_patterns,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    // Require 2+ EIP-7702 specific indicators OR delegation context with AA patterns
    indicator_count >= 2 || (has_delegation_name && has_aa_patterns)
}

/// Detects if the contract is an oracle implementation
///
/// Oracle contracts provide price/data feeds:
/// - Chainlink AggregatorV3Interface patterns
/// - TWAP oracle patterns
/// - Custom price feed implementations
pub fn is_oracle_implementation(ctx: &AnalysisContext) -> bool {
    let name = ctx.contract.name.name.to_lowercase();
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // Oracle naming patterns
    let has_oracle_name = name.contains("oracle")
        || name.contains("pricefeed")
        || name.contains("price_feed")
        || name.contains("aggregator");

    // Chainlink oracle patterns
    let has_chainlink = lower.contains("aggregatorv3interface")
        || lower.contains("latestrounddata")
        || lower.contains("getlatestprice")
        || lower.contains("pricefeed");

    // TWAP oracle patterns
    let has_twap = lower.contains("twap")
        || lower.contains("pricecumulativelast")
        || lower.contains("observe(")
        || lower.contains("consult(");

    // Must have oracle name AND implementation patterns
    has_oracle_name && (has_chainlink || has_twap)
}

// ===========================================================================
// TEXT PROCESSING UTILITIES FOR FALSE POSITIVE REDUCTION
// ===========================================================================

/// Remove single-line and multi-line comments from Solidity source code.
/// This prevents pattern matching from triggering on comments or documentation.
///
/// Handles:
/// - // single-line comments
/// - /* multi-line comments */
/// - /** NatSpec documentation */
///
/// Returns the source with all comments replaced by whitespace (preserving line numbers).
pub fn remove_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let chars: Vec<char> = source.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_string = false;
    let mut string_char = '"';

    while i < len {
        // Track string literals to avoid removing "comment-like" content inside strings
        if !in_string && (chars[i] == '"' || chars[i] == '\'') {
            in_string = true;
            string_char = chars[i];
            result.push(chars[i]);
            i += 1;
            continue;
        }

        if in_string {
            // Check for escape sequence
            if chars[i] == '\\' && i + 1 < len {
                result.push(chars[i]);
                result.push(chars[i + 1]);
                i += 2;
                continue;
            }
            // Check for end of string
            if chars[i] == string_char {
                in_string = false;
            }
            result.push(chars[i]);
            i += 1;
            continue;
        }

        // Check for single-line comment
        if i + 1 < len && chars[i] == '/' && chars[i + 1] == '/' {
            // Skip until end of line, preserving the newline
            while i < len && chars[i] != '\n' {
                result.push(' '); // Replace with space to preserve positions
                i += 1;
            }
            continue;
        }

        // Check for multi-line comment
        if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
            // Skip until closing */
            result.push(' ');
            result.push(' ');
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                if chars[i] == '\n' {
                    result.push('\n'); // Preserve line breaks
                } else {
                    result.push(' ');
                }
                i += 1;
            }
            if i + 1 < len {
                result.push(' ');
                result.push(' ');
                i += 2; // Skip the closing */
            }
            continue;
        }

        result.push(chars[i]);
        i += 1;
    }

    result
}

/// Remove string literals from Solidity source code.
/// This prevents pattern matching from triggering on strings like "send(" or "delegatecall".
///
/// Handles:
/// - "double-quoted strings"
/// - 'single-quoted strings'
/// - hex"..." and hex'...' strings
/// - Escape sequences within strings
///
/// Returns the source with all string literals replaced by empty quotes.
pub fn remove_string_literals(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let chars: Vec<char> = source.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Check for hex string: hex"..." or hex'...'
        if i + 4 < len
            && chars[i] == 'h'
            && chars[i + 1] == 'e'
            && chars[i + 2] == 'x'
            && (chars[i + 3] == '"' || chars[i + 3] == '\'')
        {
            let quote_char = chars[i + 3];
            result.push_str("hex");
            result.push(quote_char);
            i += 4;
            // Skip until closing quote
            while i < len && chars[i] != quote_char {
                if chars[i] == '\\' && i + 1 < len {
                    i += 2; // Skip escape sequence
                } else {
                    i += 1;
                }
            }
            if i < len {
                result.push(quote_char);
                i += 1;
            }
            continue;
        }

        // Check for regular string
        if chars[i] == '"' || chars[i] == '\'' {
            let quote_char = chars[i];
            result.push(quote_char);
            i += 1;
            // Skip until closing quote
            while i < len && chars[i] != quote_char {
                if chars[i] == '\\' && i + 1 < len {
                    i += 2; // Skip escape sequence
                } else if chars[i] == '\n' {
                    // Preserve newlines for line number accuracy
                    result.push('\n');
                    i += 1;
                } else {
                    i += 1;
                }
            }
            if i < len {
                result.push(quote_char);
                i += 1;
            }
            continue;
        }

        result.push(chars[i]);
        i += 1;
    }

    result
}

/// Clean source code by removing both comments and string literals.
/// This is the primary function to call before keyword searching.
///
/// Use this before any `contains()` or regex matching to ensure
/// patterns are found only in actual code, not comments or strings.
pub fn clean_source_for_search(source: &str) -> String {
    remove_string_literals(&remove_comments(source))
}

/// Find the actual line number(s) where a pattern appears in the source.
/// Returns a vector of (line_number, line_content) tuples.
///
/// This should be used after detecting a pattern to report the correct
/// line number instead of always reporting line 1.
pub fn find_pattern_lines(source: &str, pattern: &str) -> Vec<(u32, String)> {
    let mut results = Vec::new();
    let cleaned = clean_source_for_search(source);

    for (line_num, line) in cleaned.lines().enumerate() {
        if line.contains(pattern) {
            // Return the original line content (with comments/strings intact) for display
            if let Some(original_line) = source.lines().nth(line_num) {
                results.push(((line_num + 1) as u32, original_line.to_string()));
            }
        }
    }

    results
}

/// Find the first occurrence of a pattern and return its line number.
/// Returns None if the pattern is not found in actual code.
pub fn find_pattern_line(source: &str, pattern: &str) -> Option<u32> {
    find_pattern_lines(source, pattern)
        .first()
        .map(|(line, _)| *line)
}

/// Check if a pattern exists in actual code (not in comments or strings).
/// This is a safer replacement for `source.contains(pattern)`.
pub fn contains_in_code(source: &str, pattern: &str) -> bool {
    clean_source_for_search(source).contains(pattern)
}

/// Find function blocks that contain a specific pattern.
/// Returns a vector of (start_line, end_line, function_source) tuples.
///
/// This allows for function-scoped analysis when checking patterns.
pub fn find_function_blocks_with_pattern(
    source: &str,
    pattern: &str,
) -> Vec<(u32, u32, String)> {
    let mut results = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        // Look for function definitions
        if line.contains("function ")
            || line.starts_with("constructor")
            || line.starts_with("fallback")
            || line.starts_with("receive")
        {
            let func_start = i;
            let mut brace_count = 0;
            let mut found_open_brace = false;
            let mut func_end = i;

            // Find the function body bounds
            for j in i..lines.len() {
                for ch in lines[j].chars() {
                    if ch == '{' {
                        brace_count += 1;
                        found_open_brace = true;
                    } else if ch == '}' {
                        brace_count -= 1;
                    }
                }

                if found_open_brace && brace_count == 0 {
                    func_end = j;
                    break;
                }
            }

            // Extract the function source
            let func_source = lines[func_start..=func_end].join("\n");

            // Check if the pattern exists in this function (in actual code)
            if contains_in_code(&func_source, pattern) {
                results.push((
                    (func_start + 1) as u32,
                    (func_end + 1) as u32,
                    func_source,
                ));
            }

            i = func_end + 1;
        } else {
            i += 1;
        }
    }

    results
}

/// Extract the function source code containing a specific line number.
/// Returns (function_name, start_line, end_line, function_source) or None.
pub fn get_containing_function(source: &str, target_line: u32) -> Option<(String, u32, u32, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let target_idx = (target_line - 1) as usize;

    if target_idx >= lines.len() {
        return None;
    }

    // Walk backwards to find function start
    let mut func_start: Option<usize> = None;
    let mut func_name = String::new();

    for i in (0..=target_idx).rev() {
        let line = lines[i].trim();
        if line.contains("function ") {
            func_start = Some(i);
            // Extract function name
            if let Some(start) = line.find("function ") {
                let after_func = &line[start + 9..];
                if let Some(end) = after_func.find('(') {
                    func_name = after_func[..end].trim().to_string();
                }
            }
            break;
        } else if line.starts_with("constructor") {
            func_start = Some(i);
            func_name = "constructor".to_string();
            break;
        } else if line.starts_with("fallback") {
            func_start = Some(i);
            func_name = "fallback".to_string();
            break;
        } else if line.starts_with("receive") {
            func_start = Some(i);
            func_name = "receive".to_string();
            break;
        }
    }

    // Return None if no function definition was found
    let func_start = func_start?;

    // Walk forward from function start to find function end
    let mut brace_count = 0;
    let mut found_open_brace = false;
    let mut func_end = func_start;

    for j in func_start..lines.len() {
        for ch in lines[j].chars() {
            if ch == '{' {
                brace_count += 1;
                found_open_brace = true;
            } else if ch == '}' {
                brace_count -= 1;
            }
        }

        if found_open_brace && brace_count == 0 {
            func_end = j;
            break;
        }
    }

    // Verify target line is within function bounds
    if target_idx < func_start || target_idx > func_end {
        return None;
    }

    let func_source = lines[func_start..=func_end].join("\n");
    Some((
        func_name,
        (func_start + 1) as u32,
        (func_end + 1) as u32,
        func_source,
    ))
}

/// Check if a line is inside a function body (not at contract level).
/// Useful for distinguishing state variables from local variables.
pub fn is_in_function_scope(source: &str, target_line: u32) -> bool {
    get_containing_function(source, target_line).is_some()
}

/// Parse function signature and extract parameters.
/// Returns a vector of (param_type, param_name) tuples.
pub fn parse_function_params(func_signature: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();

    // Find the parameter list
    if let Some(start) = func_signature.find('(') {
        if let Some(end) = func_signature.find(')') {
            let param_str = &func_signature[start + 1..end];

            for param in param_str.split(',') {
                let param = param.trim();
                if param.is_empty() {
                    continue;
                }

                // Split by whitespace to get type and name
                let parts: Vec<&str> = param.split_whitespace().collect();
                if parts.len() >= 2 {
                    // Last part is the name, first part(s) are the type
                    let name = parts.last().unwrap().to_string();
                    let type_name = parts[..parts.len() - 1].join(" ");
                    params.push((type_name, name));
                } else if parts.len() == 1 {
                    // Type only (interface definition)
                    params.push((parts[0].to_string(), String::new()));
                }
            }
        }
    }

    params
}

/// Check if a function has a specific modifier by name.
pub fn has_modifier(func_source: &str, modifier_name: &str) -> bool {
    // Look for the modifier in the function signature (before the opening brace)
    if let Some(brace_pos) = func_source.find('{') {
        let signature = &func_source[..brace_pos];
        signature.contains(modifier_name)
    } else {
        false
    }
}

/// Check if a function has any access control modifier.
/// Looks for common patterns like onlyOwner, onlyAdmin, etc.
pub fn has_access_control_modifier(func_source: &str) -> bool {
    let access_modifiers = [
        "onlyOwner",
        "onlyAdmin",
        "onlyAuthorized",
        "onlyRole",
        "onlyGovernance",
        "onlyMinter",
        "onlyBurner",
        "restricted",
        "authorized",
        "whenNotPaused",
    ];

    access_modifiers
        .iter()
        .any(|&modifier| has_modifier(func_source, modifier))
}

/// Check if source code has explicit reentrancy protection.
/// Looks for nonReentrant modifier, lock patterns, or ReentrancyGuard.
pub fn has_reentrancy_protection(func_source: &str, contract_source: &str) -> bool {
    // Check function-level protection
    if has_modifier(func_source, "nonReentrant")
        || has_modifier(func_source, "lock")
        || func_source.contains("_reentrancyGuard")
    {
        return true;
    }

    // Check contract-level ReentrancyGuard inheritance
    if contract_source.contains("ReentrancyGuard")
        || contract_source.contains("reentrancy guard")
    {
        return true;
    }

    // Check for Uniswap V2 style lock pattern
    if contract_source.contains("uint private unlocked")
        && contract_source.contains("unlocked == 1")
    {
        return true;
    }

    // Check for transient storage reentrancy guard (EIP-1153)
    if contract_source.contains("tstore") && contract_source.contains("tload") {
        return true;
    }

    false
}

// ===========================================================================
// PHASE 10 FP REDUCTION: CONTRACT TYPE DETECTION FOR DOMAIN-SPECIFIC DETECTORS
// ===========================================================================

/// Detects if the contract is an L2 or cross-chain contract
///
/// L2/cross-chain contracts have specific characteristics:
/// - Bridge interfaces (IL1Bridge, IL2Bridge, ICrossChainMessenger)
/// - Cross-domain messaging functions
/// - L1/L2 specific terminology
/// - Rollup-specific patterns (sequencer, batch, proof)
///
/// Used to prevent L2-specific detectors from flagging simple L1 contracts.
pub fn is_l2_contract(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // Check for L2/bridge imports and interfaces
    let has_bridge_imports = source.contains("IL1Bridge")
        || source.contains("IL2Bridge")
        || source.contains("ICrossChainMessenger")
        || source.contains("ICrossDomainMessenger")
        || source.contains("IMailbox")
        || source.contains("IOutbox")
        || source.contains("IInbox")
        || source.contains("IArbSys")
        || source.contains("IScrollMessenger")
        || source.contains("IZkSync");

    // Check for L2-specific terminology
    let has_l2_terminology = lower.contains("l1bridge")
        || lower.contains("l2bridge")
        || lower.contains("l1messenger")
        || lower.contains("l2messenger")
        || lower.contains("crossdomainmessenger")
        || lower.contains("arbitrum")
        || lower.contains("optimism")
        || lower.contains("zksync")
        || lower.contains("scroll")
        || lower.contains("starknet")
        || lower.contains("polygon")
        || lower.contains("rollup");

    // Check for cross-chain messaging functions
    let has_messaging_functions = lower.contains("sendmessage")
        || lower.contains("relaymessage")
        || lower.contains("onmessage")
        || lower.contains("receivemessage")
        || lower.contains("sendcrossdomainmessage")
        || lower.contains("xdomainmessagesender")
        || lower.contains("deposittransaction")
        || lower.contains("createretryableticket");

    // Check for sequencer/batch patterns (rollup-specific)
    let has_rollup_patterns = lower.contains("sequencer")
        || lower.contains("batchposter")
        || lower.contains("forceinclusion")
        || lower.contains("finalizationperiod")
        || lower.contains("withdrawalproof")
        || lower.contains("stateroot");

    // Check for L1/L2 block references
    let has_l1_l2_refs = (lower.contains("l1blocknumber") || lower.contains("l1block"))
        && !lower.contains("// l1");  // Exclude comments

    // Must have at least 2 strong indicators
    let indicator_count = [
        has_bridge_imports,
        has_l2_terminology,
        has_messaging_functions,
        has_rollup_patterns,
        has_l1_l2_refs,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    indicator_count >= 2
}

/// Detects if the contract is a simple token (ERC20/ERC721/ERC1155)
/// without DeFi protocol complexity.
///
/// Simple tokens have:
/// - Standard token transfer functions
/// - Balance tracking
/// - Optional minting/burning
/// - NO: swap, liquidity, lending, staking, or other DeFi patterns
///
/// Used to prevent DeFi-specific detectors from flagging standard tokens.
pub fn is_simple_token(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();
    let lower = source.to_lowercase();

    // Check for ERC20/ERC721/ERC1155 patterns
    let has_token_interface = source.contains("IERC20")
        || source.contains("ERC20")
        || source.contains("IERC721")
        || source.contains("ERC721")
        || source.contains("IERC1155")
        || source.contains("ERC1155");

    // Check for standard token functions
    let has_transfer = lower.contains("function transfer(")
        || lower.contains("function transferfrom(")
        || lower.contains("function safetransfer(")
        || lower.contains("function safetransferfrom(");

    let has_balance_tracking = lower.contains("balanceof")
        || lower.contains("_balances")
        || lower.contains("ownerof");

    // Check for token standards
    let is_token_standard = (has_token_interface || has_transfer) && has_balance_tracking;

    if !is_token_standard {
        return false;
    }

    // Exclude DeFi protocols - these are NOT simple tokens
    let has_defi_patterns = lower.contains("addliquidity")
        || lower.contains("removeliquidity")
        || lower.contains("function swap(")
        || lower.contains("getreserves")
        || lower.contains("function borrow(")
        || lower.contains("function repay(")
        || lower.contains("collateral")
        || lower.contains("liquidat")
        || lower.contains("function stake(")
        || lower.contains("function unstake(")
        || lower.contains("flashloan")
        || lower.contains("oracle")
        || lower.contains("reserve0")
        || lower.contains("converttoassets")
        || lower.contains("converttoshares");

    // Is a token standard but NOT a DeFi protocol
    is_token_standard && !has_defi_patterns
}

/// Detects if function has OpenZeppelin's initializer protection
///
/// OpenZeppelin's Initializable contract provides:
/// - `initializer` modifier - prevents re-initialization
/// - `reinitializer(uint64)` modifier - for versioned re-initialization
/// - `onlyInitializing` modifier - for initialization-only code
/// - `_disableInitializers()` - disables initialization on implementation
///
/// This prevents FPs on properly protected upgradeable contracts.
pub fn has_openzeppelin_initializer_guard(func_source: &str, contract_source: &str) -> bool {
    // Check for initializer modifier on function
    if has_modifier(func_source, "initializer") {
        return true;
    }

    // Check for reinitializer modifier
    if func_source.contains("reinitializer(") {
        return true;
    }

    // Check for onlyInitializing modifier
    if has_modifier(func_source, "onlyInitializing") {
        return true;
    }

    // Check if contract inherits from Initializable and has protection
    let inherits_initializable = contract_source.contains("Initializable")
        || contract_source.contains("@openzeppelin/contracts-upgradeable");

    // Check if contract disables initializers in constructor
    let disables_in_constructor = contract_source.contains("_disableInitializers()");

    // If it inherits Initializable and disables in constructor, initialization is protected
    inherits_initializable && disables_in_constructor
}

/// Detects if function/contract has OpenZeppelin security patterns
///
/// Recognizes these OpenZeppelin security patterns:
/// - ReentrancyGuard with nonReentrant modifier
/// - Ownable with onlyOwner modifier
/// - AccessControl with onlyRole modifier
/// - Pausable with whenNotPaused/whenPaused modifiers
/// - Initializable with initializer modifier
///
/// Returns true if the function has proper OZ security protection.
pub fn has_openzeppelin_security(func_source: &str, contract_source: &str) -> bool {
    // Check for nonReentrant (ReentrancyGuard)
    if has_modifier(func_source, "nonReentrant") && contract_source.contains("ReentrancyGuard") {
        return true;
    }

    // Check for onlyOwner (Ownable/Ownable2Step)
    if has_modifier(func_source, "onlyOwner")
        && (contract_source.contains("Ownable") || contract_source.contains("Ownable2Step"))
    {
        return true;
    }

    // Check for onlyRole (AccessControl)
    if func_source.contains("onlyRole(") && contract_source.contains("AccessControl") {
        return true;
    }

    // Check for whenNotPaused/whenPaused (Pausable)
    if (has_modifier(func_source, "whenNotPaused") || has_modifier(func_source, "whenPaused"))
        && contract_source.contains("Pausable")
    {
        return true;
    }

    // Check for initializer (Initializable)
    if has_openzeppelin_initializer_guard(func_source, contract_source) {
        return true;
    }

    false
}

/// Detects if the contract is a liquidity pool that should be analyzed by
/// AMM/liquidity-specific detectors.
///
/// A liquidity pool has:
/// - Liquidity add/remove functions
/// - Reserve tracking
/// - Swap functionality or LP token mechanics
///
/// Simple token contracts and L2 bridges are NOT liquidity pools.
pub fn is_liquidity_pool(ctx: &AnalysisContext) -> bool {
    // Skip if it's a simple token
    if is_simple_token(ctx) {
        return false;
    }

    // Skip if it's an L2 contract
    if is_l2_contract(ctx) {
        return false;
    }

    let lower = ctx.source_code.to_lowercase();
    let contract_name = ctx.contract.name.name.to_lowercase();

    // Must have explicit liquidity functions (not just withdraw)
    let has_liquidity_ops = lower.contains("addliquidity")
        || lower.contains("removeliquidity")
        || lower.contains("providerliquidity")
        || lower.contains("withdrawliquidity");

    // Must have reserve tracking
    let has_reserves = (lower.contains("reserve0") && lower.contains("reserve1"))
        || lower.contains("getreserves")
        || lower.contains("totalreserves");

    // Must have swap or LP token mechanics
    let has_swap_or_lp = lower.contains("function swap(")
        || lower.contains("swaptokens")
        || lower.contains("lptoken")
        || lower.contains("pooltoken")
        || lower.contains("liquiditytoken");

    // Contract name indicates pool
    let is_pool_named = contract_name.contains("pool")
        || contract_name.contains("pair")
        || contract_name.contains("amm")
        || contract_name.contains("liquidity");

    // Need liquidity operations + at least one other strong indicator
    has_liquidity_ops && (has_reserves || has_swap_or_lp || is_pool_named)
}

/// Check if contract has escape hatch patterns specific to L2 contracts.
///
/// L2 escape hatches have:
/// - References to L1 mechanisms
/// - Sequencer/bridge dependencies
/// - Forced withdrawal patterns
///
/// Simple emergency withdraw functions on L1 contracts are NOT escape hatches.
pub fn has_l2_escape_hatch_patterns(ctx: &AnalysisContext) -> bool {
    let lower = ctx.source_code.to_lowercase();

    // Must be in an L2 context
    if !is_l2_contract(ctx) {
        return false;
    }

    // Check for escape hatch function names
    let has_escape_functions = lower.contains("escapehatch")
        || lower.contains("l1withdraw")
        || lower.contains("forceinclude")
        || lower.contains("forcedwithdrawal");

    // Check for L1 dependency in escape logic
    let has_l1_dependency = lower.contains("l1message")
        || lower.contains("l1proof")
        || lower.contains("withdrawalproof")
        || lower.contains("sequencerdown");

    has_escape_functions || has_l1_dependency
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erc4626_detection() {
        // This would need a proper AnalysisContext mock
        // Placeholder for future tests
    }

    #[test]
    fn test_remove_comments_single_line() {
        let source = r#"
contract Test {
    // This is a comment with send( and delegatecall
    uint public x;
    function foo() public {
        x = 1; // inline comment
    }
}
"#;
        let cleaned = remove_comments(source);
        assert!(!cleaned.contains("This is a comment"));
        assert!(!cleaned.contains("inline comment"));
        assert!(cleaned.contains("uint public x"));
        assert!(cleaned.contains("function foo()"));
    }

    #[test]
    fn test_remove_comments_multiline() {
        let source = r#"
contract Test {
    /* Multi-line comment
       with send( and delegatecall
       patterns */
    uint public x;
    /** NatSpec
     * @notice Also removed
     */
    function foo() public {}
}
"#;
        let cleaned = remove_comments(source);
        assert!(!cleaned.contains("Multi-line"));
        assert!(!cleaned.contains("NatSpec"));
        assert!(cleaned.contains("uint public x"));
    }

    #[test]
    fn test_remove_string_literals() {
        let source = r#"
contract Test {
    string public name = "This has send( in it";
    function foo() public {
        require(true, "Error with delegatecall");
    }
}
"#;
        let cleaned = remove_string_literals(source);
        assert!(!cleaned.contains("This has send"));
        assert!(!cleaned.contains("Error with delegatecall"));
        assert!(cleaned.contains("string public name"));
    }

    #[test]
    fn test_contains_in_code() {
        let source = r#"
contract Test {
    // send( in comment - should NOT match
    /* delegatecall in block comment - should NOT match */
    string s = "send( in string - should NOT match";

    function foo() public {
        address(this).send(100); // actual send - SHOULD match
    }
}
"#;
        assert!(contains_in_code(source, ".send("));
        // The pattern "send(" appears multiple times, but only one is in actual code
        let pattern_lines = find_pattern_lines(source, ".send(");
        assert_eq!(pattern_lines.len(), 1);
    }

    #[test]
    fn test_find_pattern_line() {
        let source = r#"line1
line2
function test() {
    send(value); // line 4
}
line6
"#;
        let line = find_pattern_line(source, "send(");
        assert_eq!(line, Some(4));
    }

    #[test]
    fn test_get_containing_function() {
        let source = r#"
contract Test {
    uint public x;

    function foo() public {
        x = 1;
        bar();
    }

    function bar() internal {
        x = 2;
    }
}
"#;
        // Line 7 is inside foo()
        let result = get_containing_function(source, 7);
        assert!(result.is_some());
        let (name, _, _, _) = result.unwrap();
        assert_eq!(name, "foo");

        // Line 3 (uint public x) is at contract level, not in a function
        let result = get_containing_function(source, 3);
        assert!(result.is_none());
    }

    #[test]
    fn test_has_access_control_modifier() {
        let func_with_modifier = "function withdraw() external onlyOwner { }";
        let func_without = "function withdraw() external { }";

        assert!(has_access_control_modifier(func_with_modifier));
        assert!(!has_access_control_modifier(func_without));
    }
}
