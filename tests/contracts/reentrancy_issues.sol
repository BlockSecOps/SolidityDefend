// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Test contract with reentrancy vulnerabilities
contract ReentrancyIssues {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerability: Classic reentrancy - state updated after external call
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // External call before state update (vulnerable)
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= _amount; // State update after external call
    }

    // Vulnerability: Read-only reentrancy
    function getBalance(address _user) public view returns (uint256) {
        return balances[_user];
    }

    function withdrawBasedOnBalance(address _user) public {
        uint256 userBalance = this.getBalance(_user); // External view call
        require(userBalance > 0, "No balance");

        balances[_user] = 0;
        payable(_user).transfer(userBalance);
    }
}