# Restaking Security Detectors

**Total:** 6 detectors

---

## AVS Validation Bypass

**ID:** `avs-validation-bypass`  
**Severity:** High  
**Categories:** DeFi  

### Description

Detects AVS registration without proper security validation, allowing malicious services to slash stakes

### Remediation

- Require AVS collateral as deterrent: \
     \
     uint256 public constant MIN_AVS_COLLATERAL = 100 ether; \
     \
     struct AVSMetadata { \
      string name; \
      address owner; \
      uint256 collateral; \
      bool approved; \
     } \
     \
     mapping(address => AVSMetadata) public avsMetadata; \
     \
     function registerAVS( \
      string calldata name \
     ) external payable { \
      require( \
       msg.value >= MIN_AVS_COLLATERAL, \
       \

### Source

`restaking/avs_validation.rs`

---

## LRT Share Inflation Attack

**ID:** `lrt-share-inflation`  
**Severity:** Critical  
**Categories:** DeFi  

### Description

Detects ERC-4626-style first depositor attacks in liquid restaking tokens where attackers can steal deposits

### Remediation

- Implement initial share lock (OpenZeppelin ERC-4626 pattern): \
     \
     uint256 private constant INITIAL_SHARE_LOCK = 1000; \
     bool private initialized; \
     \
     function deposit(uint256 assets) external returns (uint256 shares) { \
      // ... balance checks \
      \
      if (!initialized) { \
       // First deposit: lock initial shares to prevent inflation \
       shares = assets; \
       _mint(address(0), INITIAL_SHARE_LOCK); // Lock to 0x0 \
       _mint(msg.sender, shares - INITIAL_SHARE_LOCK); \
       initialized = true; \
      } else { \
       shares = (assets * totalSupply()) / _totalTrackedAssets; \
       require(shares > 0, \
- Validate minimum shares minted: \
     \
     function deposit(uint256 assets) external returns (uint256 shares) { \
      shares = convertToShares(assets); \
      \
      // Prevent zero shares (rounding attack) \
      require(shares > 0, \

### Source

`restaking/lrt_share_inflation.rs`

---

## Restaking Delegation Manipulation

**ID:** `restaking-delegation-manipulation`  
**Severity:** Critical  
**Categories:** DeFi  

### Description

Detects improper delegation validation in restaking protocols allowing unauthorized operator changes

### Remediation

- Implement operator whitelist: \
     \
     mapping(address => bool) public approvedOperators; \
     mapping(address => uint256) public operatorMaxDelegation; \
     \
     function approveOperator(address operator, uint256 maxDelegation) external onlyOwner { \
      approvedOperators[operator] = true; \
      operatorMaxDelegation[operator] = maxDelegation; \
     } \
     \
     function delegateTo(address operator, uint256 amount) external { \
      require(approvedOperators[operator], \
- Enforce delegation caps to prevent centralization: \
      \
      mapping(address => uint256) public operatorMaxDelegation; \
      mapping(address => uint256) public currentDelegation; \
      \
      function delegateTo(address operator, uint256 amount) external { \
       require( \
        currentDelegation[operator] + amount <= operatorMaxDelegation[operator], \
        \

### Source

`restaking/delegation_manipulation.rs`

---

## Restaking Rewards Manipulation

**ID:** `restaking-rewards-manipulation`  
**Severity:** Medium  
**Categories:** DeFi  

### Description

Detects reward calculation exploits, point system gaming, and unfair reward distribution

### Remediation

- Implement pro-rata reward distribution (Synthetix StakingRewards pattern): \
     \
     uint256 public rewardPerTokenStored; \
     mapping(address => uint256) public userRewardPerTokenPaid; \
     mapping(address => uint256) public rewards; \
     \
     function rewardPerToken() public view returns (uint256) { \
      if (totalStaked == 0) { \
       return rewardPerTokenStored; \
      } \
      return rewardPerTokenStored + \
       ((totalRewardsTracked * 1e18) / totalStaked); \
     } \
     \
     function earned(address user) public view returns (uint256) { \
      return (stakes[user] * \
       (rewardPerToken() - userRewardPerTokenPaid[user])) / 1e18 \
       + rewards[user]; \
     } \
     \
     function claimRewards() external { \
      updateReward(msg.sender); \
      uint256 reward = rewards[msg.sender]; \
      require(reward > 0, \

### Source

`restaking/rewards_manipulation.rs`

---

## Restaking Slashing Conditions Bypass

**ID:** `restaking-slashing-conditions`  
**Severity:** Critical  
**Categories:** DeFi  

### Description

Detects missing slashing protection, improper penalty calculation, and compound slashing risks

### Remediation

- Add evidence parameter to slashing function: \
     \
     function requestSlashing( \
      address operator, \
      uint256 amount, \
      bytes calldata evidence // Add evidence \
     ) external onlyAVS returns (bytes32 requestId) { \
      require(evidence.length > 0, \
- Validate evidence before accepting slashing request: \
     \
     function requestSlashing( \
      address operator, \
      uint256 amount, \
      bytes calldata evidence \
     ) external onlyAVS { \
      // Validate evidence exists \
      require(evidence.length > 0, \

### Source

`restaking/slashing_conditions.rs`

---

## Restaking Withdrawal Delays Not Enforced

**ID:** `restaking-withdrawal-delays`  
**Severity:** High  
**Categories:** DeFi  

### Description

Detects missing withdrawal delay enforcement, queue manipulation, and liquidity lock vulnerabilities

### Remediation

- Implement 7-day withdrawal delay (EigenLayer requirement): \
     \
     uint256 public constant WITHDRAWAL_DELAY = 7 days; \
     \
     struct WithdrawalRequest { \
      uint256 shares; \
      uint256 assets; \
      uint256 requestTime; \
      bool completed; \
     } \
     \
     mapping(address => WithdrawalRequest) public withdrawalRequests; \
     \
     function requestWithdrawal(uint256 shares) external { \
      require(shares > 0, \

### Source

`restaking/withdrawal_delays.rs`

---

