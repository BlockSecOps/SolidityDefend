// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Simplified Compound Governor Bravo
 * @notice Representative implementation based on Compound governance
 * @dev Simplified for FP testing - focuses on core governance patterns
 */

interface IERC20 {
    function getPriorVotes(address account, uint blockNumber) external view returns (uint96);
}

interface ITimelock {
    function queueTransaction(address target, uint value, string memory signature, bytes memory data, uint eta) external returns (bytes32);
    function executeTransaction(address target, uint value, string memory signature, bytes memory data, uint eta) external payable returns (bytes memory);
}

contract GovernorBravo {
    string public constant name = "Compound Governor Bravo";

    IERC20 public immutable comp;
    ITimelock public immutable timelock;

    uint public constant votingDelay = 1;
    uint public constant votingPeriod = 17280;  // ~3 days in blocks
    uint public constant proposalThreshold = 100000e18;
    uint public constant quorumVotes = 400000e18;

    uint public proposalCount;

    struct Proposal {
        uint id;
        address proposer;
        uint eta;
        address[] targets;
        uint[] values;
        string[] signatures;
        bytes[] calldatas;
        uint startBlock;
        uint endBlock;
        uint forVotes;
        uint againstVotes;
        uint abstainVotes;
        bool canceled;
        bool executed;
        mapping(address => Receipt) receipts;
    }

    struct Receipt {
        bool hasVoted;
        uint8 support;  // 0=against, 1=for, 2=abstain
        uint96 votes;
    }

    enum ProposalState {
        Pending,
        Active,
        Canceled,
        Defeated,
        Succeeded,
        Queued,
        Expired,
        Executed
    }

    mapping(uint => Proposal) public proposals;

    event ProposalCreated(uint id, address proposer, address[] targets, uint[] values, string[] signatures, bytes[] calldatas, uint startBlock, uint endBlock, string description);
    event VoteCast(address indexed voter, uint proposalId, uint8 support, uint votes, string reason);
    event ProposalCanceled(uint id);
    event ProposalQueued(uint id, uint eta);
    event ProposalExecuted(uint id);

    constructor(address _timelock, address _comp) {
        timelock = ITimelock(_timelock);
        comp = IERC20(_comp);
    }

    // Core governance functions - should be detected by is_governance_protocol()

    function propose(
        address[] memory targets,
        uint[] memory values,
        string[] memory signatures,
        bytes[] memory calldatas,
        string memory description
    ) public returns (uint) {
        require(comp.getPriorVotes(msg.sender, block.number - 1) > proposalThreshold, "Below proposal threshold");
        require(targets.length == values.length && targets.length == signatures.length && targets.length == calldatas.length, "Arity mismatch");
        require(targets.length != 0, "Must provide actions");
        require(targets.length <= 10, "Too many actions");

        uint proposalId = ++proposalCount;
        Proposal storage newProposal = proposals[proposalId];

        newProposal.id = proposalId;
        newProposal.proposer = msg.sender;
        newProposal.targets = targets;
        newProposal.values = values;
        newProposal.signatures = signatures;
        newProposal.calldatas = calldatas;
        newProposal.startBlock = block.number + votingDelay;
        newProposal.endBlock = newProposal.startBlock + votingPeriod;

        emit ProposalCreated(proposalId, msg.sender, targets, values, signatures, calldatas, newProposal.startBlock, newProposal.endBlock, description);

        return proposalId;
    }

    function queue(uint proposalId) external {
        require(state(proposalId) == ProposalState.Succeeded, "Proposal can only be queued if it is succeeded");
        Proposal storage proposal = proposals[proposalId];
        uint eta = block.timestamp + 2 days;

        for (uint i = 0; i < proposal.targets.length; i++) {
            timelock.queueTransaction(
                proposal.targets[i],
                proposal.values[i],
                proposal.signatures[i],
                proposal.calldatas[i],
                eta
            );
        }

        proposal.eta = eta;
        emit ProposalQueued(proposalId, eta);
    }

    function execute(uint proposalId) external payable {
        require(state(proposalId) == ProposalState.Queued, "Proposal can only be executed if it is queued");
        Proposal storage proposal = proposals[proposalId];
        proposal.executed = true;

        for (uint i = 0; i < proposal.targets.length; i++) {
            timelock.executeTransaction(
                proposal.targets[i],
                proposal.values[i],
                proposal.signatures[i],
                proposal.calldatas[i],
                proposal.eta
            );
        }

        emit ProposalExecuted(proposalId);
    }

    function cancel(uint proposalId) external {
        require(state(proposalId) != ProposalState.Executed, "Cannot cancel executed proposal");
        Proposal storage proposal = proposals[proposalId];

        require(msg.sender == proposal.proposer || comp.getPriorVotes(proposal.proposer, block.number - 1) < proposalThreshold, "Only proposer or if below threshold");

        proposal.canceled = true;
        emit ProposalCanceled(proposalId);
    }

    function castVote(uint proposalId, uint8 support) external {
        emit VoteCast(msg.sender, proposalId, support, _castVoteInternal(msg.sender, proposalId, support), "");
    }

    function castVoteWithReason(uint proposalId, uint8 support, string calldata reason) external {
        emit VoteCast(msg.sender, proposalId, support, _castVoteInternal(msg.sender, proposalId, support), reason);
    }

    function _castVoteInternal(address voter, uint proposalId, uint8 support) internal returns (uint96) {
        require(state(proposalId) == ProposalState.Active, "Voting is closed");
        require(support <= 2, "Invalid vote type");

        Proposal storage proposal = proposals[proposalId];
        Receipt storage receipt = proposal.receipts[voter];

        require(receipt.hasVoted == false, "Already voted");

        uint96 votes = comp.getPriorVotes(voter, proposal.startBlock);

        if (support == 0) {
            proposal.againstVotes += votes;
        } else if (support == 1) {
            proposal.forVotes += votes;
        } else if (support == 2) {
            proposal.abstainVotes += votes;
        }

        receipt.hasVoted = true;
        receipt.support = support;
        receipt.votes = votes;

        return votes;
    }

    function state(uint proposalId) public view returns (ProposalState) {
        require(proposalId > 0 && proposalId <= proposalCount, "Invalid proposal id");
        Proposal storage proposal = proposals[proposalId];

        if (proposal.canceled) {
            return ProposalState.Canceled;
        } else if (block.number <= proposal.startBlock) {
            return ProposalState.Pending;
        } else if (block.number <= proposal.endBlock) {
            return ProposalState.Active;
        } else if (proposal.forVotes <= proposal.againstVotes || proposal.forVotes < quorumVotes) {
            return ProposalState.Defeated;
        } else if (proposal.eta == 0) {
            return ProposalState.Succeeded;
        } else if (proposal.executed) {
            return ProposalState.Executed;
        } else if (block.timestamp >= proposal.eta + 14 days) {
            return ProposalState.Expired;
        } else {
            return ProposalState.Queued;
        }
    }

    function getActions(uint proposalId) external view returns (
        address[] memory targets,
        uint[] memory values,
        string[] memory signatures,
        bytes[] memory calldatas
    ) {
        Proposal storage p = proposals[proposalId];
        return (p.targets, p.values, p.signatures, p.calldatas);
    }

    function getReceipt(uint proposalId, address voter) external view returns (Receipt memory) {
        return proposals[proposalId].receipts[voter];
    }
}
