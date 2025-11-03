// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Simple ERC721 NFT
 * @notice Representative implementation based on OpenZeppelin ERC721
 * @dev Simplified for FP testing - standard ERC721 with minting
 */

contract SimpleERC721 {
    string public name = "Simple NFT";
    string public symbol = "SNFT";

    uint256 public totalSupply;
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    address public owner;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // Core ERC721 functions
    function transferFrom(address from, address to, uint256 tokenId) public {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Not approved");
        require(ownerOf[tokenId] == from, "Not token owner");

        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public {
        safeTransferFrom(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Not approved");
        require(ownerOf[tokenId] == from, "Not token owner");

        _transfer(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, data);
    }

    function approve(address approved, uint256 tokenId) public {
        address tokenOwner = ownerOf[tokenId];
        require(msg.sender == tokenOwner || isApprovedForAll[tokenOwner][msg.sender], "Not authorized");

        getApproved[tokenId] = approved;
        emit Approval(tokenOwner, approved, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) public {
        require(operator != msg.sender, "Cannot approve self");
        isApprovedForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    // Minting function
    function mint(address to, uint256 tokenId) external onlyOwner {
        require(to != address(0), "Mint to zero address");
        require(ownerOf[tokenId] == address(0), "Token already minted");

        balanceOf[to] += 1;
        ownerOf[tokenId] = to;
        totalSupply += 1;

        emit Transfer(address(0), to, tokenId);
    }

    // Burning function
    function burn(uint256 tokenId) external {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Not approved");

        address tokenOwner = ownerOf[tokenId];

        // Clear approvals
        delete getApproved[tokenId];

        balanceOf[tokenOwner] -= 1;
        delete ownerOf[tokenId];
        totalSupply -= 1;

        emit Transfer(tokenOwner, address(0), tokenId);
    }

    // View functions
    function tokenURI(uint256 tokenId) public view returns (string memory) {
        require(ownerOf[tokenId] != address(0), "Token does not exist");
        return string(abi.encodePacked("https://example.com/nft/", _toString(tokenId)));
    }

    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return interfaceId == 0x80ac58cd || // ERC721
               interfaceId == 0x5b5e139f || // ERC721Metadata
               interfaceId == 0x01ffc9a7;   // ERC165
    }

    // Internal functions
    function _transfer(address from, address to, uint256 tokenId) internal {
        require(to != address(0), "Transfer to zero address");

        // Clear approvals
        delete getApproved[tokenId];

        balanceOf[from] -= 1;
        balanceOf[to] += 1;
        ownerOf[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {
        address tokenOwner = ownerOf[tokenId];
        require(tokenOwner != address(0), "Token does not exist");

        return (spender == tokenOwner ||
                getApproved[tokenId] == spender ||
                isApprovedForAll[tokenOwner][spender]);
    }

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data) private {
        // Simplified - in production would check if receiver is a contract and call onERC721Received
        // For testing purposes, we skip the actual call
    }

    function _toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}
