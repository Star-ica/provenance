// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title AuditedAuction
 * @notice Marketplace for NFTs that must clear an independent audit before
 *         they can be auctioned. Flow per listing:
 *
 *         PendingAudit -> (auditor) -> Verified | Rejected
 *         Verified -> (creator calls startAuction) -> Live
 *         Live -> (anyone, after endTime) -> Ended  -> settle() transfers
 *         NFT to highest bidder and funds to creator (minus fee).
 *
 *         Losing bidders use a pull-payment pattern (withdraw()) so a
 *         malicious bidder can never block the auction by reverting on
 *         receive.
 *
 *         The NFT itself is a standard external ERC721 (already minted by
 *         the creator). The creator must approve() this contract for the
 *         tokenId before calling listForAudit, and the token is pulled into
 *         escrow at that point so it cannot be sold or moved elsewhere
 *         while under audit or up for bid.
 */
contract AuditedAuction is Ownable, ReentrancyGuard, ERC721Holder {
    enum Status {
        PendingAudit,
        InAudit,
        Verified,
        Rejected,
        Live,
        Ended,
        Cancelled
    }

    struct Listing {
        address nftContract;
        uint256 tokenId;
        address payable creator;
        uint256 reservePrice;      // wei
        uint256 minBidIncrementBps; // basis points, e.g. 500 = 5%
        uint256 auctionDuration;   // seconds, applied once startAuction is called
        Status status;
        address auditor;           // who reviewed it
        string auditNote;          // short note, e.g. rejection reason
        uint256 startTime;
        uint256 endTime;
        address highestBidder;
        uint256 highestBid;
        bool settled;
    }

    uint256 public nextListingId;
    mapping(uint256 => Listing) public listings;

    // bidder => listingId => refundable balance (outbid or auction cancelled)
    mapping(uint256 => mapping(address => uint256)) public pendingReturns;

    mapping(address => bool) public auditors;

    uint256 public platformFeeBps = 250; // 2.5%
    address payable public feeRecipient;

    uint256 public constant MIN_AUCTION_DURATION = 1 hours;
    uint256 public constant MAX_AUCTION_DURATION = 30 days;
    uint256 public constant DEFAULT_MIN_INCREMENT_BPS = 500; // 5%

    event Listed(uint256 indexed listingId, address indexed creator, address nftContract, uint256 tokenId, uint256 reservePrice);
    event AuditDecided(uint256 indexed listingId, address indexed auditor, bool approved, string note);
    event AuctionStarted(uint256 indexed listingId, uint256 startTime, uint256 endTime);
    event BidPlaced(uint256 indexed listingId, address indexed bidder, uint256 amount);
    event AuctionSettled(uint256 indexed listingId, address indexed winner, uint256 amount);
    event AuctionCancelled(uint256 indexed listingId);
    event Withdrawn(uint256 indexed listingId, address indexed bidder, uint256 amount);
    event AuditorUpdated(address indexed auditor, bool allowed);

    modifier onlyAuditor() {
        require(auditors[msg.sender], "Not an auditor");
        _;
    }

    modifier listingExists(uint256 listingId) {
        require(listingId < nextListingId, "No such listing");
        _;
    }

    constructor(address payable _feeRecipient) Ownable(msg.sender) {
        require(_feeRecipient != address(0), "Bad fee recipient");
        feeRecipient = _feeRecipient;
        auditors[msg.sender] = true;
    }

    /* ------------------------------------------------------------------ */
    /* Admin                                                              */
    /* ------------------------------------------------------------------ */

    function setAuditor(address account, bool allowed) external onlyOwner {
        auditors[account] = allowed;
        emit AuditorUpdated(account, allowed);
    }

    function setPlatformFee(uint256 bps) external onlyOwner {
        require(bps <= 1000, "Fee too high"); // hard cap 10%
        platformFeeBps = bps;
    }

    function setFeeRecipient(address payable recipient) external onlyOwner {
        require(recipient != address(0), "Bad address");
        feeRecipient = recipient;
    }

    /* ------------------------------------------------------------------ */
    /* Listing + audit lifecycle                                         */
    /* ------------------------------------------------------------------ */

    /// @notice Creator lists an already-minted NFT for audit. Requires prior
    ///         approve()/setApprovalForAll() on the NFT contract for this
    ///         contract's address. The token is escrowed immediately.
    function listForAudit(
        address nftContract,
        uint256 tokenId,
        uint256 reservePrice,
        uint256 auctionDurationSeconds
    ) external nonReentrant returns (uint256 listingId) {
        require(reservePrice > 0, "Reserve must be > 0");
        require(
            auctionDurationSeconds >= MIN_AUCTION_DURATION &&
            auctionDurationSeconds <= MAX_AUCTION_DURATION,
            "Bad duration"
        );
        require(IERC721(nftContract).ownerOf(tokenId) == msg.sender, "Not token owner");

        IERC721(nftContract).safeTransferFrom(msg.sender, address(this), tokenId);

        listingId = nextListingId++;
        Listing storage l = listings[listingId];
        l.nftContract = nftContract;
        l.tokenId = tokenId;
        l.creator = payable(msg.sender);
        l.reservePrice = reservePrice;
        l.minBidIncrementBps = DEFAULT_MIN_INCREMENT_BPS;
        l.auctionDuration = auctionDurationSeconds;
        l.status = Status.PendingAudit;

        emit Listed(listingId, msg.sender, nftContract, tokenId, reservePrice);
    }

    /// @notice Auditor marks a submission as under active review (optional
    ///         intermediate state so the UI can distinguish "queued" from
    ///         "being looked at").
    function beginAudit(uint256 listingId) external onlyAuditor listingExists(listingId) {
        Listing storage l = listings[listingId];
        require(l.status == Status.PendingAudit, "Not pending");
        l.status = Status.InAudit;
    }

    /// @notice Auditor approves or rejects a listing. Rejected NFTs are
    ///         returned to the creator immediately.
    function decideAudit(uint256 listingId, bool approve, string calldata note)
        external
        onlyAuditor
        listingExists(listingId)
        nonReentrant
    {
        Listing storage l = listings[listingId];
        require(
            l.status == Status.PendingAudit || l.status == Status.InAudit,
            "Not awaiting audit"
        );

        l.auditor = msg.sender;
        l.auditNote = note;

        if (approve) {
            l.status = Status.Verified;
        } else {
            l.status = Status.Rejected;
            IERC721(l.nftContract).safeTransferFrom(address(this), l.creator, l.tokenId);
        }

        emit AuditDecided(listingId, msg.sender, approve, note);
    }

    /// @notice Creator opens bidding on a verified work. Uses the duration
    ///         set at listing time.
    function startAuction(uint256 listingId) external listingExists(listingId) {
        Listing storage l = listings[listingId];
        require(msg.sender == l.creator, "Not creator");
        require(l.status == Status.Verified, "Not verified");

        l.status = Status.Live;
        l.startTime = block.timestamp;
        l.endTime = block.timestamp + l.auctionDuration;

        emit AuctionStarted(listingId, l.startTime, l.endTime);
    }

    /// @notice Creator can pull a verified-but-not-yet-live listing back,
    ///         reclaiming the NFT. Cannot cancel once bidding has started.
    function cancelBeforeAuction(uint256 listingId) external listingExists(listingId) nonReentrant {
        Listing storage l = listings[listingId];
        require(msg.sender == l.creator, "Not creator");
        require(
            l.status == Status.PendingAudit ||
            l.status == Status.InAudit ||
            l.status == Status.Verified,
            "Too late to cancel"
        );
        l.status = Status.Cancelled;
        IERC721(l.nftContract).safeTransferFrom(address(this), l.creator, l.tokenId);
        emit AuctionCancelled(listingId);
    }

    /* ------------------------------------------------------------------ */
    /* Bidding                                                            */
    /* ------------------------------------------------------------------ */

    function minNextBid(uint256 listingId) public view returns (uint256) {
        Listing storage l = listings[listingId];
        if (l.highestBid == 0) return l.reservePrice;
        return l.highestBid + (l.highestBid * l.minBidIncrementBps) / 10000;
    }

    /// @notice Highest bidder wins. Every new bid must clear the previous
    ///         highest bid by at least minBidIncrementBps. The previous
    ///         high bidder's funds become withdrawable, they are never
    ///         force-sent (pull-payment pattern).
    function placeBid(uint256 listingId) external payable listingExists(listingId) nonReentrant {
        Listing storage l = listings[listingId];
        require(l.status == Status.Live, "Auction not live");
        require(block.timestamp < l.endTime, "Auction ended");
        require(msg.sender != l.creator, "Creator cannot bid");
        require(msg.value >= minNextBid(listingId), "Bid too low");

        if (l.highestBidder != address(0)) {
            pendingReturns[listingId][l.highestBidder] += l.highestBid;
        }

        l.highestBidder = msg.sender;
        l.highestBid = msg.value;

        emit BidPlaced(listingId, msg.sender, msg.value);
    }

    /// @notice Outbid bidders (or everyone, if the auction is cancelled)
    ///         withdraw their escrowed ETH here.
    function withdraw(uint256 listingId) external listingExists(listingId) nonReentrant {
        uint256 amount = pendingReturns[listingId][msg.sender];
        require(amount > 0, "Nothing to withdraw");
        pendingReturns[listingId][msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "Withdraw failed");
        emit Withdrawn(listingId, msg.sender, amount);
    }

    /* ------------------------------------------------------------------ */
    /* Settlement                                                         */
    /* ------------------------------------------------------------------ */

    /// @notice Anyone can trigger settlement once the auction window has
    ///         closed. If reserve was met, NFT -> highest bidder, funds
    ///         (minus platform fee) -> creator. If no qualifying bid was
    ///         placed, the NFT returns to the creator.
    function settle(uint256 listingId) external listingExists(listingId) nonReentrant {
        Listing storage l = listings[listingId];
        require(l.status == Status.Live, "Not live");
        require(block.timestamp >= l.endTime, "Auction still running");
        require(!l.settled, "Already settled");

        l.settled = true;
        l.status = Status.Ended;

        if (l.highestBidder == address(0)) {
            // No bids at all — return the NFT.
            IERC721(l.nftContract).safeTransferFrom(address(this), l.creator, l.tokenId);
            emit AuctionSettled(listingId, address(0), 0);
            return;
        }

        IERC721(l.nftContract).safeTransferFrom(address(this), l.highestBidder, l.tokenId);

        uint256 fee = (l.highestBid * platformFeeBps) / 10000;
        uint256 proceeds = l.highestBid - fee;

        (bool feeOk, ) = feeRecipient.call{value: fee}("");
        require(feeOk, "Fee transfer failed");

        (bool creatorOk, ) = l.creator.call{value: proceeds}("");
        require(creatorOk, "Payout failed");

        emit AuctionSettled(listingId, l.highestBidder, l.highestBid);
    }

    /* ------------------------------------------------------------------ */
    /* Views                                                              */
    /* ------------------------------------------------------------------ */

    function getListing(uint256 listingId) external view returns (Listing memory) {
        return listings[listingId];
    }

    function timeRemaining(uint256 listingId) external view returns (uint256) {
        Listing storage l = listings[listingId];
        if (l.status != Status.Live || block.timestamp >= l.endTime) return 0;
        return l.endTime - block.timestamp;
    }
}
