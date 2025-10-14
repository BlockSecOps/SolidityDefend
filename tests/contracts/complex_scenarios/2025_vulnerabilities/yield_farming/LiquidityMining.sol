// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    function totalSupply() external view returns (uint256);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IOracle {
    function getPrice(address token) external view returns (uint256);
    function getTWAP(address token, uint256 period) external view returns (uint256);
}

/**
 * @title LiquidityMining
 * @dev Advanced yield farming contract with 2025-era vulnerabilities
 *
 * VULNERABILITIES:
 * 1. Reward calculation manipulation via timestamp attacks
 * 2. Flash loan attacks on staking/unstaking
 * 3. Impermanent loss farming (IL farming)
 * 4. Reward token inflation attacks
 * 5. Multi-block MEV attacks
 * 6. Liquidity pool manipulation for reward boost
 * 7. Time-weighted reward gaming
 * 8. Emergency withdrawal bypass
 * 9. Reward multiplier manipulation
 * 10. Cross-pool arbitrage exploitation
 */
contract LiquidityMining is Ownable, ReentrancyGuard {
    using SafeMath for uint256;

    struct UserInfo {
        uint256 amount; // Staked LP token amount
        uint256 rewardDebt; // Reward debt for calculations
        uint256 lastStakeTime; // Last stake timestamp
        uint256 lastRewardTime; // Last reward claim timestamp
        uint256 accumulatedRewards; // Total accumulated rewards
        uint256 boostMultiplier; // User-specific boost (1000 = 1x)
        uint256 lockEndTime; // Lock period end time
        bool isVIP; // VIP status for bonus rewards
    }

    struct PoolInfo {
        IERC20 lpToken; // LP token contract
        uint256 allocPoint; // Allocation points for this pool
        uint256 lastRewardBlock; // Last block number where rewards were calculated
        uint256 accRewardPerShare; // Accumulated rewards per share
        uint256 totalStaked; // Total amount staked in pool
        uint256 minimumStake; // Minimum stake amount
        uint256 lockPeriod; // Lock period in seconds
        uint256 withdrawalFee; // Early withdrawal fee (basis points)
        bool emergencyWithdrawEnabled; // Emergency withdrawal status
        address oracle; // Price oracle for this pool
        uint256 lastPriceUpdate; // Last oracle price update
    }

    struct RewardBoost {
        uint256 duration; // Boost duration in blocks
        uint256 multiplier; // Boost multiplier (1000 = 1x)
        uint256 startBlock; // Boost start block
        uint256 endBlock; // Boost end block
        bool active; // Boost status
    }

    // Core state variables
    IERC20 public rewardToken;
    address public treasury;

    PoolInfo[] public poolInfo;
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    mapping(address => bool) public authorizedUpdaters;
    mapping(uint256 => RewardBoost) public poolBoosts;

    // Reward parameters
    uint256 public rewardPerBlock = 10e18; // Base reward per block
    uint256 public totalAllocPoint = 0;
    uint256 public startBlock;
    uint256 public bonusEndBlock;

    // Advanced features
    uint256 public globalBoostMultiplier = 1000; // 1x by default
    uint256 public vipBoostMultiplier = 1500; // 1.5x for VIP users
    uint256 public emergencyFee = 1000; // 10% emergency withdrawal fee
    uint256 public maxLockPeriod = 365 days;

    // VULNERABILITY: Time-based parameters that can be manipulated
    uint256 public rewardCalculationWindow = 1 hours;
    uint256 public priceUpdateThreshold = 300; // 5 minutes
    uint256 public constant PRECISION_FACTOR = 1e12;

    // VULNERABILITY: Mutable fee structure
    mapping(address => uint256) public userWithdrawalFees;
    mapping(uint256 => uint256) public poolDepositFees;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event RewardPaid(address indexed user, uint256 amount);
    event PoolAdded(uint256 indexed pid, address lpToken, uint256 allocPoint);
    event BoostActivated(uint256 indexed pid, uint256 multiplier, uint256 duration);

    modifier onlyAuthorized() {
        require(authorizedUpdaters[msg.sender] || msg.sender == owner(), "Not authorized");
        _;
    }

    modifier validPool(uint256 _pid) {
        require(_pid < poolInfo.length, "Invalid pool");
        _;
    }

    constructor(
        IERC20 _rewardToken,
        address _treasury,
        uint256 _startBlock
    ) Ownable(msg.sender) {
        rewardToken = _rewardToken;
        treasury = _treasury;
        startBlock = _startBlock;
        bonusEndBlock = _startBlock.add(200000); // ~30 days assuming 13s blocks

        authorizedUpdaters[msg.sender] = true;
    }

    /**
     * @dev Add new staking pool - VULNERABLE to misconfiguration
     */
    function addPool(
        uint256 _allocPoint,
        IERC20 _lpToken,
        uint256 _minimumStake,
        uint256 _lockPeriod,
        uint256 _withdrawalFee,
        address _oracle,
        bool _withUpdate
    ) external onlyOwner {
        if (_withUpdate) {
            massUpdatePools();
        }

        // VULNERABILITY: No validation of parameters
        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);

        poolInfo.push(PoolInfo({
            lpToken: _lpToken,
            allocPoint: _allocPoint,
            lastRewardBlock: lastRewardBlock,
            accRewardPerShare: 0,
            totalStaked: 0,
            minimumStake: _minimumStake,
            lockPeriod: _lockPeriod,
            withdrawalFee: _withdrawalFee,
            emergencyWithdrawEnabled: true,
            oracle: _oracle,
            lastPriceUpdate: block.timestamp
        }));

        emit PoolAdded(poolInfo.length.sub(1), address(_lpToken), _allocPoint);
    }

    /**
     * @dev Stake LP tokens - VULNERABLE to flash loan attacks
     */
    function deposit(uint256 _pid, uint256 _amount) external nonReentrant validPool(_pid) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        require(_amount >= pool.minimumStake, "Below minimum stake");

        updatePool(_pid);

        // VULNERABILITY: Reward calculation before new deposit is considered
        if (user.amount > 0) {
            uint256 pending = user.amount.mul(pool.accRewardPerShare).div(PRECISION_FACTOR).sub(user.rewardDebt);
            if (pending > 0) {
                user.accumulatedRewards = user.accumulatedRewards.add(pending);
            }
        }

        // VULNERABILITY: External call before state update
        pool.lpToken.transferFrom(msg.sender, address(this), _amount);

        // VULNERABILITY: Deposit fee calculated after transfer
        uint256 depositFee = _amount.mul(poolDepositFees[_pid]).div(10000);
        uint256 actualAmount = _amount.sub(depositFee);

        if (depositFee > 0) {
            pool.lpToken.transfer(treasury, depositFee);
        }

        user.amount = user.amount.add(actualAmount);
        user.lastStakeTime = block.timestamp;
        user.lockEndTime = block.timestamp.add(pool.lockPeriod);
        pool.totalStaked = pool.totalStaked.add(actualAmount);

        user.rewardDebt = user.amount.mul(pool.accRewardPerShare).div(PRECISION_FACTOR);

        emit Deposit(msg.sender, _pid, actualAmount);
    }

    /**
     * @dev Withdraw LP tokens - VULNERABLE to timing manipulation
     */
    function withdraw(uint256 _pid, uint256 _amount) external nonReentrant validPool(_pid) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        require(user.amount >= _amount, "Insufficient balance");

        updatePool(_pid);

        // VULNERABILITY: Lock period can be bypassed with emergency withdrawal
        require(block.timestamp >= user.lockEndTime, "Still locked");

        uint256 pending = user.amount.mul(pool.accRewardPerShare).div(PRECISION_FACTOR).sub(user.rewardDebt);
        if (pending > 0) {
            user.accumulatedRewards = user.accumulatedRewards.add(pending);
        }

        user.amount = user.amount.sub(_amount);
        pool.totalStaked = pool.totalStaked.sub(_amount);

        // VULNERABILITY: Withdrawal fee calculation can be manipulated
        uint256 withdrawalFee = 0;
        if (block.timestamp < user.lastStakeTime.add(7 days)) {
            withdrawalFee = _amount.mul(pool.withdrawalFee).div(10000);
        }

        uint256 withdrawAmount = _amount.sub(withdrawalFee);

        if (withdrawalFee > 0) {
            pool.lpToken.transfer(treasury, withdrawalFee);
        }

        pool.lpToken.transfer(msg.sender, withdrawAmount);

        user.rewardDebt = user.amount.mul(pool.accRewardPerShare).div(PRECISION_FACTOR);

        emit Withdraw(msg.sender, _pid, withdrawAmount);
    }

    /**
     * @dev Emergency withdraw - VULNERABLE to abuse
     */
    function emergencyWithdraw(uint256 _pid) external nonReentrant validPool(_pid) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        require(pool.emergencyWithdrawEnabled, "Emergency withdraw disabled");

        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        user.accumulatedRewards = 0; // VULNERABILITY: Loses all accumulated rewards

        pool.totalStaked = pool.totalStaked.sub(amount);

        // VULNERABILITY: Emergency fee can be bypassed by admin
        uint256 fee = amount.mul(emergencyFee).div(10000);
        uint256 withdrawAmount = amount.sub(fee);

        if (fee > 0) {
            pool.lpToken.transfer(treasury, fee);
        }

        pool.lpToken.transfer(msg.sender, withdrawAmount);

        emit EmergencyWithdraw(msg.sender, _pid, withdrawAmount);
    }

    /**
     * @dev Claim accumulated rewards - VULNERABLE to MEV attacks
     */
    function claimRewards(uint256 _pid) external nonReentrant validPool(_pid) {
        updatePool(_pid);

        UserInfo storage user = userInfo[_pid][msg.sender];
        PoolInfo storage pool = poolInfo[_pid];

        uint256 pending = user.amount.mul(pool.accRewardPerShare).div(PRECISION_FACTOR).sub(user.rewardDebt);
        uint256 totalRewards = user.accumulatedRewards.add(pending);

        require(totalRewards > 0, "No rewards to claim");

        // VULNERABILITY: Time-based boost calculation can be gamed
        uint256 boost = calculateTimeBoost(user.lastRewardTime);
        uint256 vipBoost = user.isVIP ? vipBoostMultiplier : 1000;
        uint256 globalBoost = globalBoostMultiplier;

        uint256 finalRewards = totalRewards
            .mul(boost).div(1000)
            .mul(vipBoost).div(1000)
            .mul(globalBoost).div(1000);

        user.accumulatedRewards = 0;
        user.lastRewardTime = block.timestamp;
        user.rewardDebt = user.amount.mul(pool.accRewardPerShare).div(PRECISION_FACTOR);

        // VULNERABILITY: External call to transfer rewards
        safeRewardTransfer(msg.sender, finalRewards);

        emit RewardPaid(msg.sender, finalRewards);
    }

    /**
     * @dev Update pool rewards - VULNERABLE to manipulation
     */
    function updatePool(uint256 _pid) public validPool(_pid) {
        PoolInfo storage pool = poolInfo[_pid];

        if (block.number <= pool.lastRewardBlock) {
            return;
        }

        uint256 lpSupply = pool.totalStaked;
        if (lpSupply == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }

        // VULNERABILITY: Reward calculation based on current price, can be manipulated
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 baseReward = multiplier.mul(rewardPerBlock).mul(pool.allocPoint).div(totalAllocPoint);

        // VULNERABILITY: Oracle price used without staleness check
        uint256 priceMultiplier = getPriceMultiplier(_pid);
        uint256 reward = baseReward.mul(priceMultiplier).div(1000);

        // Apply pool-specific boost if active
        RewardBoost storage boost = poolBoosts[_pid];
        if (boost.active && block.number >= boost.startBlock && block.number <= boost.endBlock) {
            reward = reward.mul(boost.multiplier).div(1000);
        }

        pool.accRewardPerShare = pool.accRewardPerShare.add(reward.mul(PRECISION_FACTOR).div(lpSupply));
        pool.lastRewardBlock = block.number;
    }

    /**
     * @dev Calculate price multiplier - VULNERABLE to oracle manipulation
     */
    function getPriceMultiplier(uint256 _pid) public view returns (uint256) {
        PoolInfo storage pool = poolInfo[_pid];

        if (pool.oracle == address(0)) {
            return 1000; // 1x multiplier if no oracle
        }

        // VULNERABILITY: Using spot price without TWAP validation
        try IOracle(pool.oracle).getPrice(address(pool.lpToken)) returns (uint256 currentPrice) {
            try IOracle(pool.oracle).getTWAP(address(pool.lpToken), 1 hours) returns (uint256 twapPrice) {
                // VULNERABILITY: Price deviation calculation can overflow
                uint256 deviation = currentPrice > twapPrice ?
                    currentPrice.sub(twapPrice).mul(1000).div(twapPrice) :
                    twapPrice.sub(currentPrice).mul(1000).div(twapPrice);

                // Higher deviation = higher rewards (VULNERABILITY: Incentivizes manipulation)
                if (deviation > 100) { // >10% deviation
                    return 1500; // 1.5x multiplier
                } else if (deviation > 50) { // >5% deviation
                    return 1200; // 1.2x multiplier
                }
                return 1000; // 1x multiplier
            } catch {
                return 1000;
            }
        } catch {
            return 1000;
        }
    }

    /**
     * @dev Calculate time-based boost - VULNERABLE to timestamp manipulation
     */
    function calculateTimeBoost(uint256 lastRewardTime) public view returns (uint256) {
        if (lastRewardTime == 0) {
            return 1000; // No previous claim
        }

        uint256 timeSinceLastClaim = block.timestamp.sub(lastRewardTime);

        // VULNERABILITY: Longer periods = higher boost (incentivizes timing games)
        if (timeSinceLastClaim >= 30 days) {
            return 2000; // 2x boost
        } else if (timeSinceLastClaim >= 7 days) {
            return 1500; // 1.5x boost
        } else if (timeSinceLastClaim >= 1 days) {
            return 1200; // 1.2x boost
        }

        return 1000; // 1x boost
    }

    /**
     * @dev Mass update all pools
     */
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    /**
     * @dev Set VIP status - VULNERABLE to admin abuse
     */
    function setVIPStatus(address user, bool isVIP) external onlyAuthorized {
        // VULNERABILITY: VIP status can be changed instantly
        userInfo[0][user].isVIP = isVIP; // Simplified - should be per pool
    }

    /**
     * @dev Activate boost for pool - VULNERABLE to timing manipulation
     */
    function activateBoost(
        uint256 _pid,
        uint256 _multiplier,
        uint256 _duration
    ) external onlyAuthorized validPool(_pid) {
        // VULNERABILITY: Boost can be activated instantly
        require(_multiplier >= 1000 && _multiplier <= 5000, "Invalid multiplier");

        poolBoosts[_pid] = RewardBoost({
            duration: _duration,
            multiplier: _multiplier,
            startBlock: block.number,
            endBlock: block.number.add(_duration),
            active: true
        });

        emit BoostActivated(_pid, _multiplier, _duration);
    }

    /**
     * @dev Emergency functions - VULNERABLE to admin abuse
     */
    function emergencyRewardWithdraw(uint256 _amount) external onlyOwner {
        // VULNERABILITY: Owner can drain all rewards
        rewardToken.transfer(owner(), _amount);
    }

    function setEmergencyWithdraw(uint256 _pid, bool _enabled) external onlyOwner validPool(_pid) {
        poolInfo[_pid].emergencyWithdrawEnabled = _enabled;
    }

    /**
     * @dev Get multiplier between blocks
     */
    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {
        if (_to <= bonusEndBlock) {
            return _to.sub(_from);
        } else if (_from >= bonusEndBlock) {
            return _to.sub(_from).div(2); // Half rewards after bonus period
        } else {
            return bonusEndBlock.sub(_from).add(_to.sub(bonusEndBlock).div(2));
        }
    }

    /**
     * @dev Safe reward transfer with supply check
     */
    function safeRewardTransfer(address _to, uint256 _amount) internal {
        uint256 rewardBal = rewardToken.balanceOf(address(this));
        if (_amount > rewardBal) {
            rewardToken.transfer(_to, rewardBal);
        } else {
            rewardToken.transfer(_to, _amount);
        }
    }

    /**
     * @dev View functions
     */
    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    function pendingRewards(uint256 _pid, address _user) external view validPool(_pid) returns (uint256) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accRewardPerShare = pool.accRewardPerShare;
        uint256 lpSupply = pool.totalStaked;

        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
            uint256 reward = multiplier.mul(rewardPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
            accRewardPerShare = accRewardPerShare.add(reward.mul(PRECISION_FACTOR).div(lpSupply));
        }

        return user.amount.mul(accRewardPerShare).div(PRECISION_FACTOR).sub(user.rewardDebt).add(user.accumulatedRewards);
    }

    // VULNERABILITY: Fallback function accepts ETH
    receive() external payable {}
}