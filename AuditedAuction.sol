// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface INFTFactory {
    function mintForListing(
        address creator,
        string calldata collectionName,
        string calldata collectionSymbol,
        string calldata tokenURI_
    ) external returns (address collection, uint256 tokenId);

    function collectionOf(address creator) external view returns (address);
}

interface ICreatorCollection {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

/**
 * @title AuditedAuction  (v3 — per-creator NFT collections via NFTFactory)
 *
 * Stack-depth fix: Listing is split into two structs.
 *   ListingMeta  — immutable fields set on submission, never written again.
 *   AuctionState — mutable auction/bid fields updated throughout the lifecycle.
 *
 * Flow:
 *   listForAudit()  → PendingAudit
 *   beginAudit()    → InAudit          (auditor)
 *   decideAudit()   → Verified | Rejected
 *   startAuction()  → Live             (creator)
 *   settle()        → Ended            (anyone, after endTime)
 *   withdraw()      — losing bidders pull their ETH at any time
 */
contract AuditedAuction is Ownable, ReentrancyGuard, ERC721Holder {

    // ------------------------------------------------------------------ //
    // Types                                                               //
    // ------------------------------------------------------------------ //

    enum Status {
        PendingAudit,   // 0
        InAudit,        // 1
        Verified,       // 2
        Rejected,       // 3
        Live,           // 4
        Ended,          // 5
        Cancelled       // 6
    }

    /// Fields set once at submission time — never written again.
    struct ListingMeta {
        address  collection;         // creator's ERC-721 contract (from factory)
        uint256  tokenId;            // token ID within that collection
        address payable creator;
        uint256  reservePrice;       // wei
        uint256  minBidIncrementBps; // e.g. 500 = 5 %
        uint256  auctionDuration;    // seconds
        string   tokenURI;           // ipfs://CID — stored for the UI
    }

    /// Fields that change as the listing moves through its lifecycle.
    struct AuctionState {
        Status   status;
        address  auditor;
        string   auditNote;
        uint256  startTime;
        uint256  endTime;
        address  highestBidder;
        uint256  highestBid;
        bool     settled;
    }

    // ------------------------------------------------------------------ //
    // State                                                               //
    // ------------------------------------------------------------------ //

    INFTFactory public immutable factory;

    uint256 public nextListingId;
    mapping(uint256 => ListingMeta)  public meta;
    mapping(uint256 => AuctionState) public state;

    /// pull-payment escrow: listingId => bidder => amount
    mapping(uint256 => mapping(address => uint256)) public pendingReturns;

    mapping(address => bool) public auditors;

    uint256 public platformFeeBps = 250;  // 2.5 %
    address payable public feeRecipient;

    uint256 public constant MIN_AUCTION_DURATION      = 1 hours;
    uint256 public constant MAX_AUCTION_DURATION      = 30 days;
    uint256 public constant DEFAULT_MIN_INCREMENT_BPS = 500; // 5 %

    // ------------------------------------------------------------------ //
    // Events                                                              //
    // ------------------------------------------------------------------ //

    event Listed(
        uint256 indexed listingId,
        address indexed creator,
        address indexed collection,
        uint256 tokenId,
        uint256 reservePrice,
        string  tokenURI
    );
    event AuditDecided(uint256 indexed listingId, address indexed auditor, bool approved, string note);
    event AuctionStarted(uint256 indexed listingId, uint256 startTime, uint256 endTime);
    event BidPlaced(uint256 indexed listingId, address indexed bidder, uint256 amount);
    event AuctionSettled(uint256 indexed listingId, address indexed winner, uint256 amount);
    event AuctionCancelled(uint256 indexed listingId);
    event Withdrawn(uint256 indexed listingId, address indexed bidder, uint256 amount);
    event AuditorUpdated(address indexed auditor, bool allowed);

    // ------------------------------------------------------------------ //
    // Modifiers                                                           //
    // ------------------------------------------------------------------ //

    modifier onlyAuditor() {
        require(auditors[msg.sender], "Not an auditor");
        _;
    }

    modifier exists(uint256 id) {
        require(id < nextListingId, "No such listing");
        _;
    }

    // ------------------------------------------------------------------ //
    // Constructor                                                         //
    // ------------------------------------------------------------------ //

    constructor(address payable _feeRecipient, address _factory)
        Ownable(msg.sender)
    {
        require(_feeRecipient != address(0) && _factory != address(0), "Zero address");
        feeRecipient         = _feeRecipient;
        factory              = INFTFactory(_factory);
        auditors[msg.sender] = true;
    }

    // ------------------------------------------------------------------ //
    // Admin                                                               //
    // ------------------------------------------------------------------ //

    function setAuditor(address account, bool allowed) external onlyOwner {
        auditors[account] = allowed;
        emit AuditorUpdated(account, allowed);
    }

    function setPlatformFee(uint256 bps) external onlyOwner {
        require(bps <= 1000, "Fee cap 10%");
        platformFeeBps = bps;
    }

    function setFeeRecipient(address payable recipient) external onlyOwner {
        require(recipient != address(0), "Zero address");
        feeRecipient = recipient;
    }

    // ------------------------------------------------------------------ //
    // Listing                                                             //
    // ------------------------------------------------------------------ //

    /**
     * @notice Submit a work for audit.
     *         The factory mints a fresh token into this contract's escrow
     *         under the creator's own ERC-721 collection (created on first use).
     *
     * @param tokenURI_           IPFS URI for the ERC-721 metadata JSON.
     * @param reservePrice        Minimum acceptable bid (wei).
     * @param auctionDurationSecs Auction window length once the piece is verified.
     * @param collectionName      ERC-721 name  — used only when creating a new collection.
     * @param collectionSymbol    ERC-721 symbol — used only when creating a new collection.
     */
    function listForAudit(
        string  calldata tokenURI_,
        uint256 reservePrice,
        uint256 auctionDurationSecs,
        string  calldata collectionName,
        string  calldata collectionSymbol
    ) external nonReentrant returns (uint256 listingId) {
        require(reservePrice > 0,            "Reserve must be > 0");
        require(bytes(tokenURI_).length > 0, "No token URI");
        require(
            auctionDurationSecs >= MIN_AUCTION_DURATION &&
            auctionDurationSecs <= MAX_AUCTION_DURATION,
            "Bad duration"
        );

        // Mint into escrow — kept in its own scope to free stack slots.
        address collection;
        uint256 tokenId;
        {
            (collection, tokenId) = factory.mintForListing(
                msg.sender,
                collectionName,
                collectionSymbol,
                tokenURI_
            );
        }

        listingId = nextListingId++;

        // Write meta — one storage pointer, minimal stack usage.
        ListingMeta storage m = meta[listingId];
        m.collection          = collection;
        m.tokenId             = tokenId;
        m.creator             = payable(msg.sender);
        m.reservePrice        = reservePrice;
        m.minBidIncrementBps  = DEFAULT_MIN_INCREMENT_BPS;
        m.auctionDuration     = auctionDurationSecs;
        m.tokenURI            = tokenURI_;

        // Write state — default Status(0) == PendingAudit, everything else zeroed.
        // Nothing to set explicitly; the mapping default is correct.

        emit Listed(listingId, msg.sender, collection, tokenId, reservePrice, tokenURI_);
    }

    // ------------------------------------------------------------------ //
    // Audit lifecycle                                                     //
    // ------------------------------------------------------------------ //

    function beginAudit(uint256 listingId)
        external onlyAuditor exists(listingId)
    {
        AuctionState storage s = state[listingId];
        require(s.status == Status.PendingAudit, "Not pending");
        s.status = Status.InAudit;
    }

    function decideAudit(uint256 listingId, bool approve, string calldata note)
        external onlyAuditor exists(listingId) nonReentrant
    {
        AuctionState storage s = state[listingId];
        require(
            s.status == Status.PendingAudit || s.status == Status.InAudit,
            "Not awaiting audit"
        );
        s.auditor   = msg.sender;
        s.auditNote = note;

        if (approve) {
            s.status = Status.Verified;
        } else {
            s.status = Status.Rejected;
            ListingMeta storage m = meta[listingId];
            ICreatorCollection(m.collection).safeTransferFrom(
                address(this), m.creator, m.tokenId
            );
        }

        emit AuditDecided(listingId, msg.sender, approve, note);
    }

    function startAuction(uint256 listingId) external exists(listingId) {
        ListingMeta  storage m = meta[listingId];
        AuctionState storage s = state[listingId];
        require(msg.sender == m.creator,     "Not creator");
        require(s.status == Status.Verified, "Not verified");

        s.status    = Status.Live;
        s.startTime = block.timestamp;
        s.endTime   = block.timestamp + m.auctionDuration;

        emit AuctionStarted(listingId, s.startTime, s.endTime);
    }

    function cancelBeforeAuction(uint256 listingId)
        external exists(listingId) nonReentrant
    {
        ListingMeta  storage m = meta[listingId];
        AuctionState storage s = state[listingId];
        require(msg.sender == m.creator, "Not creator");
        require(
            s.status == Status.PendingAudit ||
            s.status == Status.InAudit      ||
            s.status == Status.Verified,
            "Too late to cancel"
        );
        s.status = Status.Cancelled;
        ICreatorCollection(m.collection).safeTransferFrom(
            address(this), m.creator, m.tokenId
        );
        emit AuctionCancelled(listingId);
    }

    // ------------------------------------------------------------------ //
    // Bidding                                                             //
    // ------------------------------------------------------------------ //

    function minNextBid(uint256 listingId) public view returns (uint256) {
        ListingMeta  storage m = meta[listingId];
        AuctionState storage s = state[listingId];
        if (s.highestBid == 0) return m.reservePrice;
        return s.highestBid + (s.highestBid * m.minBidIncrementBps) / 10_000;
    }

    function placeBid(uint256 listingId)
        external payable exists(listingId) nonReentrant
    {
        ListingMeta  storage m = meta[listingId];
        AuctionState storage s = state[listingId];
        require(s.status == Status.Live,           "Auction not live");
        require(block.timestamp < s.endTime,        "Auction ended");
        require(msg.sender != m.creator,            "Creator cannot bid");
        require(msg.value >= minNextBid(listingId), "Bid too low");

        if (s.highestBidder != address(0)) {
            pendingReturns[listingId][s.highestBidder] += s.highestBid;
        }
        s.highestBidder = msg.sender;
        s.highestBid    = msg.value;

        emit BidPlaced(listingId, msg.sender, msg.value);
    }

    function withdraw(uint256 listingId)
        external exists(listingId) nonReentrant
    {
        uint256 amount = pendingReturns[listingId][msg.sender];
        require(amount > 0, "Nothing to withdraw");
        pendingReturns[listingId][msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "Withdraw failed");
        emit Withdrawn(listingId, msg.sender, amount);
    }

    // ------------------------------------------------------------------ //
    // Settlement                                                          //
    // ------------------------------------------------------------------ //

    function settle(uint256 listingId)
        external exists(listingId) nonReentrant
    {
        ListingMeta  storage m = meta[listingId];
        AuctionState storage s = state[listingId];
        require(s.status == Status.Live,      "Not live");
        require(block.timestamp >= s.endTime, "Still running");
        require(!s.settled,                   "Already settled");

        s.settled = true;
        s.status  = Status.Ended;

        if (s.highestBidder == address(0)) {
            ICreatorCollection(m.collection).safeTransferFrom(
                address(this), m.creator, m.tokenId
            );
            emit AuctionSettled(listingId, address(0), 0);
            return;
        }

        ICreatorCollection(m.collection).safeTransferFrom(
            address(this), s.highestBidder, m.tokenId
        );

        uint256 fee      = (s.highestBid * platformFeeBps) / 10_000;
        uint256 proceeds = s.highestBid - fee;

        (bool feeOk,)     = feeRecipient.call{value: fee}("");
        require(feeOk,    "Fee transfer failed");
        (bool creatorOk,) = m.creator.call{value: proceeds}("");
        require(creatorOk,"Payout failed");

        emit AuctionSettled(listingId, s.highestBidder, s.highestBid);
    }

    // ------------------------------------------------------------------ //
    // Views                                                               //
    // ------------------------------------------------------------------ //

    /// @notice Convenience composite view — returns both structs together.
    ///         The frontend ABI calls this as getListing(id).
    function getListing(uint256 listingId)
        external view
        returns (ListingMeta memory m, AuctionState memory s)
    {
        m = meta[listingId];
        s = state[listingId];
    }

    function timeRemaining(uint256 listingId)
        external view returns (uint256)
    {
        AuctionState storage s = state[listingId];
        if (s.status != Status.Live || block.timestamp >= s.endTime) return 0;
        return s.endTime - block.timestamp;
    }

    function collectionOf(address creator)
        external view returns (address)
    {
        return factory.collectionOf(creator);
    }
}
