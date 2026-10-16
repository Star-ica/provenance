// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title CreatorCollection
 * @notice A per-creator ERC-721 collection deployed by NFTFactory.
 *         Only the AuditedAuction marketplace can mint.
 *         Tokens are minted directly into the marketplace escrow.
 */
contract CreatorCollection is ERC721URIStorage, Ownable {
    uint256 public nextTokenId;
    address public immutable marketplace;
    address public immutable creator;

    event Minted(address indexed creator, uint256 indexed tokenId, string tokenURI);

    modifier onlyMarketplace() {
        require(msg.sender == marketplace, "Only marketplace");
        _;
    }

    /**
     * @param name_       e.g. "Jeremiah's Works"
     * @param symbol_     e.g. "JRW"
     * @param marketplace_ The AuditedAuction contract — sole minting authority.
     * @param creator_    The artist who owns this collection conceptually.
     *                    Stored for UI indexing; does not affect access control.
     */
    constructor(
        string memory name_,
        string memory symbol_,
        address marketplace_,
        address creator_
    ) ERC721(name_, symbol_) Ownable(marketplace_) {
        require(marketplace_ != address(0), "Zero marketplace");
        require(creator_    != address(0), "Zero creator");
        marketplace = marketplace_;
        creator     = creator_;
    }

    /**
     * @notice Mint a new token into the marketplace escrow.
     *         Called exclusively by AuditedAuction during listForAudit().
     * @return tokenId  The freshly minted token ID within this collection.
     */
    function mint(string calldata tokenURI_)
        external
        onlyMarketplace
        returns (uint256 tokenId)
    {
        tokenId = nextTokenId++;
        _safeMint(marketplace, tokenId);  // lands in escrow immediately
        _setTokenURI(tokenId, tokenURI_);
        emit Minted(creator, tokenId, tokenURI_);
    }
}
