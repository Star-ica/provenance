// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CreatorCollection.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title NFTFactory
 * @notice Deploys one CreatorCollection per creator address and remembers it.
 *         Only the registered AuditedAuction marketplace may call
 *         getOrCreateCollection() and mintForListing().
 *
 * Deploy order:
 *   1. Deploy AuditedAuction (pass this factory's address as _nftContract)
 *      — OR —
 *      Deploy NFTFactory first, then AuditedAuction, then call
 *      NFTFactory.setMarketplace(auctionAddr).
 *
 *   2. Call NFTFactory.setMarketplace(auctionAddress)  (owner-only, once).
 */
contract NFTFactory is Ownable {
    address public marketplace;

    /// creator address => their deployed CreatorCollection
    mapping(address => address) public collectionOf;

    /// all deployed collections for enumeration / UI
    address[] public allCollections;

    event MarketplaceSet(address indexed marketplace);
    event CollectionCreated(
        address indexed creator,
        address indexed collection,
        string  name,
        string  symbol
    );

    modifier onlyMarketplace() {
        require(msg.sender == marketplace, "Only marketplace");
        _;
    }

    constructor() Ownable(msg.sender) {}

    // ------------------------------------------------------------------ //
    // Admin                                                               //
    // ------------------------------------------------------------------ //

    /// @notice Set (or update) the marketplace address. Owner-only, callable
    ///         once after both contracts are deployed.
    function setMarketplace(address _marketplace) external onlyOwner {
        require(_marketplace != address(0), "Zero address");
        marketplace = _marketplace;
        emit MarketplaceSet(_marketplace);
    }

    // ------------------------------------------------------------------ //
    // Core — called by AuditedAuction                                    //
    // ------------------------------------------------------------------ //

    /**
     * @notice Returns the existing collection for `creator`, or deploys a new
     *         one with the supplied name/symbol if this is their first listing.
     *         Can only be called by the marketplace.
     *
     * @param creator   Artist's wallet address.
     * @param name      ERC-721 collection name  (e.g. "Alice's Works").
     * @param symbol    ERC-721 collection symbol (e.g. "ALCE").
     * @return collection  Address of the creator's ERC-721 contract.
     */
    function getOrCreateCollection(
        address creator,
        string calldata name,
        string calldata symbol
    ) external onlyMarketplace returns (address collection) {
        if (collectionOf[creator] != address(0)) {
            return collectionOf[creator];
        }

        require(bytes(name).length   > 0, "Empty name");
        require(bytes(symbol).length > 0, "Empty symbol");

        CreatorCollection c = new CreatorCollection(
            name,
            symbol,
            marketplace,  // sole minting authority
            creator
        );

        collectionOf[creator] = address(c);
        allCollections.push(address(c));

        emit CollectionCreated(creator, address(c), name, symbol);
        return address(c);
    }

    /**
     * @notice Convenience wrapper: get-or-create the collection, then mint.
     *         AuditedAuction calls this in a single hop so it only needs the
     *         factory address — no two-step lookup.
     *
     * @param creator   Artist wallet.
     * @param name      Collection name (ignored if collection already exists).
     * @param symbol    Collection symbol (ignored if collection already exists).
     * @param tokenURI_ IPFS metadata URI.
     * @return collection  Address of the ERC-721 collection.
     * @return tokenId     Freshly minted token ID within that collection.
     */
    function mintForListing(
        address creator,
        string calldata name,
        string calldata symbol,
        string calldata tokenURI_
    )
        external
        onlyMarketplace
        returns (address collection, uint256 tokenId)
    {
        collection = this.getOrCreateCollection(creator, name, symbol);
        tokenId    = CreatorCollection(collection).mint(tokenURI_);
    }

    // ------------------------------------------------------------------ //
    // Views                                                               //
    // ------------------------------------------------------------------ //

    function totalCollections() external view returns (uint256) {
        return allCollections.length;
    }

    function hasCollection(address creator) external view returns (bool) {
        return collectionOf[creator] != address(0);
    }
}
