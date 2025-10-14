// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IVotingToken {
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function delegate(address delegatee) external;
    function delegates(address account) external view returns (address);
    function getPastVotes(address account, uint256 blockNumber) external view returns (uint256);
}

/**
 * @title DAOGovernance
 * @dev DAO governance contract with modern 2025 vulnerabilities
 *
 * VULNERABILITIES:
 * 1. Flash loan governance attacks
 * 2. Voting power manipulation through delegation loops
 * 3. Proposal execution time manipulation
 * 4. Cross-chain governance inconsistencies
 * 5. MEV extraction during proposal execution
 * 6. Voting period manipulation
 * 7. Quorum manipulation attacks
 * 8. Delegation front-running
 * 9. Emergency governance bypass
 * 10. Time-weighted voting manipulation
 */
contract DAOGovernance is Ownable, ReentrancyGuard {

    enum ProposalState {
        Pending,
        Active,
        Succeeded,
        Defeated,
        Queued,
        Executed,
        Canceled,
        Expired
    }

    struct Proposal {
        uint256 id;
        address proposer;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        uint256 startBlock;
        uint256 endBlock;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        bool canceled;
        bool executed;
        uint256 eta; // execution time
        string description;
        mapping(address => Receipt) receipts;
    }

    struct Receipt {
        bool hasVoted;
        uint8 support; // 0=against, 1=for, 2=abstain
        uint256 votes;
        uint256 blockNumber;
    }

    struct DelegationInfo {
        address delegatee;
        uint256 delegatedVotes;
        uint256 lastDelegationBlock;
        bool isDelegating;
    }

    // Core governance parameters
    IVotingToken public votingToken;
    mapping(uint256 => Proposal) public proposals;
    mapping(address => DelegationInfo) public delegationInfo;
    mapping(address => mapping(uint256 => bool)) public hasVotedOnProposal;

    uint256 public proposalCount;
    uint256 public votingDelay = 1 days; // VULNERABILITY: Can be manipulated
    uint256 public votingPeriod = 3 days; // VULNERABILITY: Too short
    uint256 public proposalThreshold = 100000e18; // VULNERABILITY: Centralized threshold
    uint256 public quorum = 4; // 4% VULNERABILITY: Low quorum
    uint256 public timelock = 2 days; // VULNERABILITY: Can be bypassed

    // VULNERABILITY: Admin controls for emergency situations
    address public guardian;
    bool public emergencyPaused;
    uint256 public emergencyDelay = 1 hours;

    // VULNERABILITY: Voting power multipliers for different proposal types
    mapping(string => uint256) public proposalTypeMultipliers;

    // VULNERABILITY: Cross-chain governance state
    mapping(uint256 => mapping(uint256 => bool)) public crossChainExecuted;
    mapping(uint256 => address) public chainGovernors;

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        string description
    );

    event VoteCast(
        address indexed voter,
        uint256 indexed proposalId,
        uint8 support,
        uint256 votes
    );

    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCanceled(uint256 indexed proposalId);
    event DelegationChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);

    modifier onlyGuardian() {
        require(msg.sender == guardian || msg.sender == owner(), "Not guardian");
        _;
    }

    modifier notEmergencyPaused() {
        require(!emergencyPaused, "Emergency paused");
        _;
    }

    constructor(
        address _votingToken,
        address _guardian
    ) Ownable(msg.sender) {
        votingToken = IVotingToken(_votingToken);
        guardian = _guardian;

        // Initialize proposal type multipliers
        proposalTypeMultipliers["treasury"] = 150; // 1.5x voting power needed
        proposalTypeMultipliers["parameter"] = 100; // 1x voting power
        proposalTypeMultipliers["emergency"] = 200; // 2x voting power needed
    }

    /**
     * @dev Create proposal - VULNERABLE to manipulation
     */
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) external notEmergencyPaused returns (uint256) {
        require(targets.length == values.length && targets.length == calldatas.length, "Proposal function information arity mismatch");
        require(targets.length != 0, "Empty proposal");

        // VULNERABILITY: Proposal threshold check can be bypassed with flash loans
        require(votingToken.balanceOf(msg.sender) >= proposalThreshold, "Proposer votes below proposal threshold");

        // VULNERABILITY: No cooldown period between proposals from same address
        proposalCount++;
        uint256 proposalId = proposalCount;

        uint256 startBlock = block.number + votingDelay;
        uint256 endBlock = startBlock + votingPeriod;

        Proposal storage newProposal = proposals[proposalId];
        newProposal.id = proposalId;
        newProposal.proposer = msg.sender;
        newProposal.targets = targets;
        newProposal.values = values;
        newProposal.calldatas = calldatas;
        newProposal.startBlock = startBlock;
        newProposal.endBlock = endBlock;
        newProposal.description = description;

        emit ProposalCreated(proposalId, msg.sender, description);
        return proposalId;
    }

    /**
     * @dev Cast vote - VULNERABLE to various attacks
     */
    function castVote(
        uint256 proposalId,
        uint8 support
    ) external notEmergencyPaused returns (uint256) {
        return _castVote(msg.sender, proposalId, support, "");
    }

    /**
     * @dev Cast vote with signature - VULNERABLE to replay attacks
     */
    function castVoteBySig(
        uint256 proposalId,
        uint8 support,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external notEmergencyPaused returns (uint256) {
        // VULNERABILITY: No nonce system for signature replay protection
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("DAOGovernance")),
            block.chainid,
            address(this)
        ));

        bytes32 structHash = keccak256(abi.encode(
            keccak256("Ballot(uint256 proposalId,uint8 support)"),
            proposalId,
            support
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "Invalid signature");

        return _castVote(signer, proposalId, support, "");
    }

    /**
     * @dev Internal vote casting - VULNERABLE implementation
     */
    function _castVote(
        address voter,
        uint256 proposalId,
        uint8 support,
        string memory reason
    ) internal returns (uint256) {
        require(getProposalState(proposalId) == ProposalState.Active, "Voting is closed");
        require(support <= 2, "Invalid vote type");

        Proposal storage proposal = proposals[proposalId];
        Receipt storage receipt = proposal.receipts[voter];

        require(!receipt.hasVoted, "Voter already voted");

        // VULNERABILITY: Voting power calculated at current block, not proposal snapshot
        uint256 votes = getVotingPower(voter, block.number);
        require(votes > 0, "No voting power");

        // VULNERABILITY: Vote delegation can be manipulated during voting
        if (delegationInfo[voter].isDelegating) {
            address delegatee = delegationInfo[voter].delegatee;
            votes = getVotingPower(delegatee, block.number);
        }

        receipt.hasVoted = true;
        receipt.support = support;
        receipt.votes = votes;
        receipt.blockNumber = block.number;

        if (support == 0) {
            proposal.againstVotes += votes;
        } else if (support == 1) {
            proposal.forVotes += votes;
        } else {
            proposal.abstainVotes += votes;
        }

        emit VoteCast(voter, proposalId, support, votes);
        return votes;
    }

    /**
     * @dev Queue proposal for execution - VULNERABLE to timing manipulation
     */
    function queue(uint256 proposalId) external notEmergencyPaused {
        require(getProposalState(proposalId) == ProposalState.Succeeded, "Proposal not succeeded");

        Proposal storage proposal = proposals[proposalId];

        // VULNERABILITY: ETA can be manipulated by admin
        uint256 eta = block.timestamp + timelock;
        proposal.eta = eta;
    }

    /**
     * @dev Execute proposal - VULNERABLE to MEV and reentrancy
     */
    function execute(uint256 proposalId) external payable nonReentrant notEmergencyPaused {
        require(getProposalState(proposalId) == ProposalState.Queued, "Proposal not queued");

        Proposal storage proposal = proposals[proposalId];
        require(block.timestamp >= proposal.eta, "Proposal not ready");
        require(block.timestamp <= proposal.eta + 14 days, "Proposal expired");

        proposal.executed = true;

        // VULNERABILITY: External calls in loop without proper error handling
        for (uint256 i = 0; i < proposal.targets.length; i++) {
            (bool success, bytes memory returndata) = proposal.targets[i].call{value: proposal.values[i]}(
                proposal.calldatas[i]
            );

            // VULNERABILITY: Continues execution even if one call fails
            if (!success) {
                if (returndata.length > 0) {
                    assembly {
                        let returndata_size := mload(returndata)
                        revert(add(32, returndata), returndata_size)
                    }
                } else {
                    revert("Execution failed");
                }
            }
        }

        emit ProposalExecuted(proposalId);
    }

    /**
     * @dev Cancel proposal - VULNERABLE to admin abuse
     */
    function cancel(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        // VULNERABILITY: Guardian can cancel any proposal
        require(
            msg.sender == proposal.proposer ||
            msg.sender == guardian ||
            votingToken.balanceOf(proposal.proposer) < proposalThreshold,
            "Cannot cancel"
        );

        require(getProposalState(proposalId) != ProposalState.Executed, "Cannot cancel executed proposal");

        proposal.canceled = true;
        emit ProposalCanceled(proposalId);
    }

    /**
     * @dev Delegate voting power - VULNERABLE to front-running
     */
    function delegate(address delegatee) external notEmergencyPaused {
        require(delegatee != msg.sender, "Cannot delegate to self");

        // VULNERABILITY: No protection against delegation loops
        // VULNERABILITY: No time lock for delegation changes

        address currentDelegate = delegationInfo[msg.sender].delegatee;

        if (currentDelegate != address(0)) {
            delegationInfo[currentDelegate].delegatedVotes -= votingToken.balanceOf(msg.sender);
        }

        delegationInfo[msg.sender].delegatee = delegatee;
        delegationInfo[msg.sender].isDelegating = true;
        delegationInfo[msg.sender].lastDelegationBlock = block.number;

        if (delegatee != address(0)) {
            delegationInfo[delegatee].delegatedVotes += votingToken.balanceOf(msg.sender);
        }

        emit DelegationChanged(msg.sender, currentDelegate, delegatee);
    }

    /**
     * @dev Get voting power - VULNERABLE calculation
     */
    function getVotingPower(address account, uint256 blockNumber) public view returns (uint256) {
        // VULNERABILITY: Uses current balance instead of historical snapshot
        uint256 tokenBalance = votingToken.balanceOf(account);
        uint256 delegatedBalance = delegationInfo[account].delegatedVotes;

        // VULNERABILITY: No protection against flash loan voting
        return tokenBalance + delegatedBalance;
    }

    /**
     * @dev Get proposal state
     */
    function getProposalState(uint256 proposalId) public view returns (ProposalState) {
        require(proposalId > 0 && proposalId <= proposalCount, "Invalid proposal id");

        Proposal storage proposal = proposals[proposalId];

        if (proposal.canceled) {
            return ProposalState.Canceled;
        } else if (proposal.executed) {
            return ProposalState.Executed;
        } else if (block.number <= proposal.startBlock) {
            return ProposalState.Pending;
        } else if (block.number <= proposal.endBlock) {
            return ProposalState.Active;
        } else if (proposal.forVotes <= proposal.againstVotes || proposal.forVotes < getQuorumVotes()) {
            return ProposalState.Defeated;
        } else if (proposal.eta == 0) {
            return ProposalState.Succeeded;
        } else if (block.timestamp >= proposal.eta + 14 days) {
            return ProposalState.Expired;
        } else {
            return ProposalState.Queued;
        }
    }

    /**
     * @dev Get required quorum votes
     */
    function getQuorumVotes() public view returns (uint256) {
        // VULNERABILITY: Quorum based on current supply, can be manipulated
        return (votingToken.totalSupply() * quorum) / 100;
    }

    /**
     * @dev Emergency pause - VULNERABLE to admin abuse
     */
    function emergencyPause() external onlyGuardian {
        // VULNERABILITY: No time lock or multi-sig for emergency pause
        emergencyPaused = true;
    }

    /**
     * @dev Emergency unpause
     */
    function emergencyUnpause() external onlyGuardian {
        emergencyPaused = false;
    }

    /**
     * @dev Update governance parameters - VULNERABLE to immediate changes
     */
    function updateParameters(
        uint256 _votingDelay,
        uint256 _votingPeriod,
        uint256 _proposalThreshold,
        uint256 _quorum
    ) external onlyOwner {
        // VULNERABILITY: Parameters can be changed immediately without proposal
        votingDelay = _votingDelay;
        votingPeriod = _votingPeriod;
        proposalThreshold = _proposalThreshold;
        quorum = _quorum;
    }

    /**
     * @dev Cross-chain execution - VULNERABLE to inconsistencies
     */
    function executeCrossChain(
        uint256 proposalId,
        uint256 targetChain,
        bytes calldata data
    ) external onlyOwner {
        // VULNERABILITY: No validation of cross-chain state
        require(!crossChainExecuted[proposalId][targetChain], "Already executed on target chain");

        crossChainExecuted[proposalId][targetChain] = true;

        // VULNERABILITY: No verification of cross-chain message authenticity
        address targetGovernor = chainGovernors[targetChain];
        require(targetGovernor != address(0), "No governor for target chain");

        // This would call cross-chain bridge - simplified for testing
    }

    /**
     * @dev Set guardian - VULNERABLE to centralization
     */
    function setGuardian(address newGuardian) external onlyOwner {
        guardian = newGuardian;
    }

    // VULNERABILITY: Fallback accepts ETH without validation
    receive() external payable {}
}