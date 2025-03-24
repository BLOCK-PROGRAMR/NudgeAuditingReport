// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { INudgePointsCampaign } from "./interfaces/INudgePointsCampaign.sol";
import "./interfaces/INudgeCampaignFactory.sol";

/// @title NudgePointsCampaigns
/// @notice Manages points-based campaigns where users can reallocate their tokens and earn points as rewards
contract NudgePointsCampaigns is INudgePointsCampaign, AccessControl {
  using SafeERC20 for IERC20;

  // Special address representing the native token (ETH)
  address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
  bytes32 public constant NUDGE_ADMIN_ROLE = keccak256("NUDGE_ADMIN_ROLE");
  bytes32 public constant SWAP_CALLER_ROLE = keccak256("SWAP_CALLER_ROLE");

  // Campaigns
  mapping(uint256 => Campaign) public campaigns;
  mapping(uint256 => bool) public isCampaignPaused;

  // Participations
  mapping(uint256 campaign => mapping(uint256 pID => Participation)) public participations;

  /// @notice Initializes the contract with required roles
  /// @param swapCaller Address to be granted SWAP_CALLER_ROLE
  /// @dev Grants DEFAULT_ADMIN_ROLE and NUDGE_ADMIN_ROLE to msg.sender
  constructor(address swapCaller) {
    _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    _grantRole(NUDGE_ADMIN_ROLE, msg.sender);
    _grantRole(SWAP_CALLER_ROLE, swapCaller);
  }

  /// @notice Ensures the campaign is not paused
  /// @param campaignId The ID of the campaign to check
  modifier whenNotPaused(uint256 campaignId) {
    if (isCampaignPaused[campaignId]) revert CampaignPaused();
    _;
  }

  /// @notice Creates a new points campaign
  /// @param campaignId Unique identifier for the campaign
  /// @param holdingPeriodInSeconds Duration users must hold tokens
  /// @param targetToken Address of the token users need to hold
  /// @return Campaign memory The newly created campaign
  /// @dev Only callable by NUDGE_ADMIN_ROLE
  function createPointsCampaign(
    uint256 campaignId,
    uint32 holdingPeriodInSeconds,
    address targetToken
  )
    external
    onlyRole(NUDGE_ADMIN_ROLE)
    returns (Campaign memory)
  {
    if (targetToken == address(0)) {
      revert InvalidTargetToken();
    }

    if (campaigns[campaignId].targetToken != address(0)) {
      revert CampaignAlreadyExists();
    }

    Campaign memory campaign = Campaign({
      holdingPeriodInSeconds: holdingPeriodInSeconds,
      targetToken: targetToken,
      pID: 0,
      totalReallocatedAmount: 0
    });

    campaigns[campaignId] = campaign;

    emit PointsCampaignCreated(campaignId, holdingPeriodInSeconds, targetToken);
    return campaign;
  }

  /// @notice Creates multiple points campaigns in a single transaction
  /// @param campaignIds Array of unique identifiers for the campaigns
  /// @param holdingPeriods Array of holding periods for each campaign
  /// @param targetTokens Array of target tokens for each campaign
  /// @return Campaign[] memory Array of newly created campaigns
  /// @dev Array lengths must match, only callable by NUDGE_ADMIN_ROLE
  function createPointsCampaigns(
    uint256[] calldata campaignIds,
    uint32[] calldata holdingPeriods,
    address[] calldata targetTokens
  )
    external
    onlyRole(NUDGE_ADMIN_ROLE)
    returns (Campaign[] memory)
  {
    // Input validation
    if (campaignIds.length != holdingPeriods.length || campaignIds.length != targetTokens.length) {
      revert InvalidInputArrayLengths();
    }

    Campaign[] memory newCampaigns = new Campaign[](campaignIds.length);

    for (uint256 i = 0; i < campaignIds.length; i++) {
      if (targetTokens[i] == address(0)) {
        revert InvalidTargetToken();
      }

      if (campaigns[campaignIds[i]].targetToken != address(0)) {
        revert CampaignAlreadyExists();
      }

      Campaign memory campaign = Campaign({
        holdingPeriodInSeconds: holdingPeriods[i],
        targetToken: targetTokens[i],
        pID: 0,
        totalReallocatedAmount: 0
      });

      campaigns[campaignIds[i]] = campaign;
      newCampaigns[i] = campaign;

      emit PointsCampaignCreated(campaignIds[i], holdingPeriods[i], targetTokens[i]);
    }

    return newCampaigns;
  }

  /// @notice Handles token reallocation for campaign participation
  /// @param campaignId ID of the campaign
  /// @param userAddress Address of the participating user
  /// @param toToken Address of the token being acquired
  /// @param toAmount Expected amount of tokens to be acquired
  /// @param data Additional data for the reallocation
  /// @dev Only callable by SWAP_CALLER_ROLE, handles both ERC20 and native tokens
  function handleReallocation(
    uint256 campaignId,
    address userAddress,
    address toToken,
    uint256 toAmount,
    bytes calldata data
  )
    external
    payable
    whenNotPaused(campaignId)
    onlyRole(SWAP_CALLER_ROLE)
  {
    Campaign storage campaign = campaigns[campaignId];

    if (toToken != campaign.targetToken) {
      revert InvalidToTokenReceived(toToken);
    }

    uint256 amountReceived;
    if (toToken == NATIVE_TOKEN) {
      amountReceived = msg.value;
    } else {
      if (msg.value > 0) {
        revert InvalidToTokenReceived(NATIVE_TOKEN);
      }

      IERC20 tokenReceived = IERC20(toToken);
      uint256 balanceOfSender = tokenReceived.balanceOf(msg.sender);
      uint256 balanceBefore = getBalanceOfSelf(toToken);
      //if sender balance is zero then revert is the best solution otherwise it will be a bug
      //@audit
      //   if (balanceOfSender == 0) {
      //     revert InsufficientAmountReceived();
      //   }
      SafeERC20.safeTransferFrom(tokenReceived, msg.sender, address(this), balanceOfSender);

      amountReceived = getBalanceOfSelf(toToken) - balanceBefore;
    }

    if (amountReceived < toAmount) {
      revert InsufficientAmountReceived();
    }

    _transfer(toToken, userAddress, amountReceived);

    campaign.totalReallocatedAmount += amountReceived;

    uint256 newpID = ++campaign.pID;

    // Store the participation details
    participations[campaignId][newpID] = Participation({
      status: ParticipationStatus.HANDLED_OFFCHAIN,
      userAddress: userAddress,
      toAmount: amountReceived,
      rewardAmount: 0,
      startTimestamp: block.timestamp,
      startBlockNumber: block.number
    });

    // entitledRewards & fees set to 0 since users only earn points
    emit NewParticipation(campaignId, userAddress, newpID, amountReceived, 0, 0, data);
  }

  /*//////////////////////////////////////////////////////////////////////////
                              ADMIN FUNCTIONS                             
  //////////////////////////////////////////////////////////////////////////*/

  /// @notice Pauses multiple campaigns
  /// @param campaignIds Array of campaign IDs to pause
  /// @dev Only callable by NUDGE_ADMIN_ROLE
  function pauseCampaigns(uint256[] calldata campaignIds) external onlyRole(NUDGE_ADMIN_ROLE) {
    for (uint256 i = 0; i < campaignIds.length; i++) {
      if (isCampaignPaused[campaignIds[i]]) revert CampaignAlreadyPaused();

      isCampaignPaused[campaignIds[i]] = true;
    }

    emit CampaignsPaused(campaignIds);
  }

  /// @notice Unpauses multiple campaigns
  /// @param campaignIds Array of campaign IDs to unpause
  /// @dev Only callable by NUDGE_ADMIN_ROLE
  function unpauseCampaigns(uint256[] calldata campaignIds) external onlyRole(NUDGE_ADMIN_ROLE) {
    for (uint256 i = 0; i < campaignIds.length; i++) {
      if (!isCampaignPaused[campaignIds[i]]) revert CampaignNotPaused();

      isCampaignPaused[campaignIds[i]] = false;
    }

    emit CampaignsUnpaused(campaignIds);
  }

  /*//////////////////////////////////////////////////////////////////////////
                              VIEW FUNCTIONS                              
  //////////////////////////////////////////////////////////////////////////*/

  /// @notice Gets the balance of this contract for a specific token
  /// @param token Address of the token to check balance for
  /// @return uint256 Balance of the token
  /// @dev Handles both ERC20 and native token balances
  function getBalanceOfSelf(address token) public view returns (uint256) {
    if (token == NATIVE_TOKEN) {
      return address(this).balance;
    } else {
      return IERC20(token).balanceOf(address(this));
    }
  }

  /*//////////////////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
  //////////////////////////////////////////////////////////////////////////*/

  /// @notice Internal function to transfer tokens
  /// @param token Address of the token to transfer
  /// @param to Recipient address
  /// @param amount Amount of tokens to transfer
  /// @dev Handles both ERC20 and native token transfers
  function _transfer(address token, address to, uint256 amount) internal {
    if (token == NATIVE_TOKEN) {
      (bool sent,) = to.call{ value: amount }("");
      if (!sent) revert NativeTokenTransferFailed();
    } else {
      SafeERC20.safeTransfer(IERC20(token), to, amount);
    }
  }
}
