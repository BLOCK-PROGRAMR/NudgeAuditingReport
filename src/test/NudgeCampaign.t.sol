// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import "forge-std/StdUtils.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import { NudgeCampaign } from "../campaign/NudgeCampaign.sol";
import { NudgeCampaignFactory, INudgeCampaignFactory } from "../campaign/NudgeCampaignFactory.sol";
import { INudgeCampaign, IBaseNudgeCampaign } from "../campaign/interfaces/INudgeCampaign.sol";
import { console } from "forge-std/console.sol";
import { ERC20, TestERC20 } from "../mocks/TestERC20.sol";
import { MockTokenDecimals } from "../mocks/MockTokenDecimals.sol";
import { TestUSDC } from "../mocks/TestUSDC.sol";
import { console } from "forge-std/console.sol";
import { Create2 } from "@openzeppelin/contracts/utils/Create2.sol";

contract NudgeCampaignTest is Test {
  NudgeCampaign private campaign;
  address ZERO_ADDRESS = address(0);
  address NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

  address owner;
  uint256 constant REWARD_PPQ = 2e13;
  uint256 constant INITIAL_FUNDING = 100_000e18;
  uint256 constant BPS_DENOMINATOR = 1e4;
  uint256 constant PPQ_DENOMINATOR = 1e15;
  address alice = address(11);
  address bob = address(12);
  address swapCaller = address(13);
  address campaignAdmin = address(14);
  address nudgeAdmin = address(15);
  address treasury = address(16);
  address operator = address(17);
  address alternativeWithdrawalAddress = address(16);
  address campaignAddress;
  uint32 holdingPeriodInSeconds = 60 * 60 * 24 * 7; // 7 days
  uint256 initialFundingAmount = 100_000e18;
  uint256 rewardPPQ = 2e13;
  uint256 RANDOM_UUID = 111_222_333_444_555_666_777;
  uint256[] pIDsWithOne = [1];
  uint16 DEFAULT_FEE_BPS = 1000;
  TestERC20 toToken;
  TestERC20 rewardToken;
  NudgeCampaignFactory factory;

  function setUp() public {
    owner = msg.sender;
    toToken = new TestERC20("Incentivized Token", "IT");
    rewardToken = new TestERC20("Reward Token", "RT");
    factory = new NudgeCampaignFactory(treasury, nudgeAdmin, operator, swapCaller);

    campaignAddress = factory.deployCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      0,
      alternativeWithdrawalAddress,
      RANDOM_UUID
    );
    campaign = NudgeCampaign(payable(campaignAddress));

    vm.deal(campaignAdmin, 10 ether);

    vm.prank(campaignAdmin);
    rewardToken.faucet(10_000_000e18);
    // Fund the campaign with reward tokens
    vm.prank(campaignAdmin);
    rewardToken.transfer(campaignAddress, INITIAL_FUNDING);
  }

  function deployCampaign(ERC20 toToken_, ERC20 rewardToken_, uint256 rewardPPQ_) internal returns (NudgeCampaign) {
    campaignAddress = factory.deployCampaign(
      holdingPeriodInSeconds,
      address(toToken_),
      address(rewardToken_),
      rewardPPQ_,
      campaignAdmin,
      0,
      alternativeWithdrawalAddress,
      RANDOM_UUID
    );
    campaign = NudgeCampaign(payable(campaignAddress));

    return campaign;
  }

  function simulateReallocation(address userAddress, uint256 toAmount) internal {
    // Simulate getting toTokens from end user
    vm.prank(swapCaller);
    toToken.faucet(toAmount);

    vm.prank(swapCaller);
    toToken.approve(address(campaign), toAmount);

    vm.prank(swapCaller);
    campaign.handleReallocation(RANDOM_UUID, userAddress, address(toToken), toAmount, "");
  }

  function simulateReallocationAndFastForward(address userAddress, uint256 toAmount) internal {
    simulateReallocation(userAddress, toAmount);
    vm.warp(block.timestamp + holdingPeriodInSeconds + 1);
  }

  function getUserRewardsAndFeesFromToAmount(
    NudgeCampaign campaign_,
    uint256 toAmount_
  )
    public
    view
    returns (uint256, uint256)
  {
    uint256 rewardAmountIncludingFees = campaign_.getRewardAmountIncludingFees(toAmount_);
    (uint256 userRewards, uint256 fees) = campaign_.calculateUserRewardsAndFees(rewardAmountIncludingFees);
    return (userRewards, fees);
  }

  /*//////////////////////////////////////////////////////////////////////////
                                CONSTRUCTOR                              
  //////////////////////////////////////////////////////////////////////////*/

  function test_Constructor() public {
    NudgeCampaign campaign_ = new NudgeCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      0,
      DEFAULT_FEE_BPS,
      alternativeWithdrawalAddress,
      RANDOM_UUID
    );

    assertEq(campaign_.holdingPeriodInSeconds(), holdingPeriodInSeconds);
    assertEq(campaign_.targetToken(), address(toToken));
    assertEq(campaign_.rewardToken(), address(rewardToken));
    assertEq(campaign_.rewardPPQ(), REWARD_PPQ);
    assertEq(campaign_.startTimestamp(), block.timestamp);
    assertTrue(campaign_.isCampaignActive());
    assertEq(campaign_.pendingRewards(), 0);
    assertEq(campaign_.totalReallocatedAmount(), 0);
    assertEq(campaign_.distributedRewards(), 0);
    assertEq(campaign_.claimableRewardAmount(), 0);
    assertEq(campaign_.feeBps(), DEFAULT_FEE_BPS);
    assertEq(campaign_.alternativeWithdrawalAddress(), alternativeWithdrawalAddress);
    assertEq(campaign_.campaignId(), RANDOM_UUID);
  }

  function test_ConstructorWithInvalidRewardToken() public {
    address targetToken_ = ZERO_ADDRESS;

    vm.expectRevert();
    new NudgeCampaign(
      holdingPeriodInSeconds,
      targetToken_,
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      0,
      DEFAULT_FEE_BPS,
      alternativeWithdrawalAddress,
      RANDOM_UUID
    );
  }

  function test_ConstructorWithInvalidCampaignAdmin() public {
    address campaignAdmin_ = ZERO_ADDRESS;

    vm.expectRevert();
    new NudgeCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin_,
      0,
      DEFAULT_FEE_BPS,
      alternativeWithdrawalAddress,
      RANDOM_UUID
    );
  }

  function test_ConstructorWithInvalidStartTimestamp() public {
    uint256 startTimestamp_ = block.timestamp - 1;

    vm.expectRevert();
    new NudgeCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      startTimestamp_,
      DEFAULT_FEE_BPS,
      alternativeWithdrawalAddress,
      RANDOM_UUID
    );
  }

  function test_ConstructorSetsFactoryFromMsgSender() public {
    vm.prank(alice);
    NudgeCampaign campaign_ = new NudgeCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      0,
      DEFAULT_FEE_BPS,
      alternativeWithdrawalAddress,
      RANDOM_UUID
    );

    INudgeCampaignFactory factory_ = campaign_.factory();
    assertEq(address(factory_), alice);
  }

  function test_ConstructorSetsRewardPPQ() public {
    NudgeCampaign campaign_ = new NudgeCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      0,
      DEFAULT_FEE_BPS,
      alternativeWithdrawalAddress,
      RANDOM_UUID
    );

    assertEq(campaign_.rewardPPQ(), REWARD_PPQ);
  }

  function test_ConstructorGrantsRoleToCampaignAdmin() public {
    NudgeCampaign campaign_ = new NudgeCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      0,
      DEFAULT_FEE_BPS,
      alternativeWithdrawalAddress,
      RANDOM_UUID
    );

    assertTrue(campaign_.hasRole(campaign.CAMPAIGN_ADMIN_ROLE(), campaignAdmin));
  }

  function test_ConststructorWithFutureStartDate() public {
    uint256 startTimestamp_ = block.timestamp + 10 days;

    // Fund test contract with reward tokens for deployment
    rewardToken.mintTo(INITIAL_FUNDING, address(this));
    rewardToken.approve(address(factory), INITIAL_FUNDING);

    // Deploy and fund campaign with future start date
    address futureCampaignAddress = factory.deployAndFundCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      startTimestamp_,
      alternativeWithdrawalAddress,
      INITIAL_FUNDING,
      RANDOM_UUID
    );

    NudgeCampaign futureCampaign = NudgeCampaign(payable(futureCampaignAddress));

    assertEq(futureCampaign.startTimestamp(), startTimestamp_);
    assertFalse(futureCampaign.isCampaignActive());

    // Trying to call handleReallocation should fail before the start timestamp
    vm.startPrank(swapCaller);
    vm.expectRevert(INudgeCampaign.StartDateNotReached.selector);
    futureCampaign.handleReallocation(RANDOM_UUID, alice, address(toToken), 100e18, "");
    vm.stopPrank();

    // Warp to after the start timestamp
    vm.warp(startTimestamp_ + 1);

    // Now handleReallocation should work and campaign should be automatically activated
    uint256 amount = 100e18;
    vm.prank(swapCaller);
    toToken.faucet(amount);

    vm.prank(swapCaller);
    toToken.approve(futureCampaignAddress, amount);

    vm.prank(swapCaller);
    futureCampaign.handleReallocation(RANDOM_UUID, alice, address(toToken), amount, "");

    // Verify campaign is now active
    assertTrue(futureCampaign.isCampaignActive());
  }

  function test_ConstructorAlternativeWithdrawalAddressCanBeZeroAddress() public {
    address alternativeWithdrawalAddress_ = ZERO_ADDRESS;

    NudgeCampaign campaign_ = new NudgeCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      0,
      DEFAULT_FEE_BPS,
      alternativeWithdrawalAddress_,
      RANDOM_UUID
    );

    assertEq(campaign_.alternativeWithdrawalAddress(), ZERO_ADDRESS);
  }

  function testCannotDeployCampaignWithCurrentBlockTimestamp() public {
    // Get current block timestamp
    uint256 currentTimestamp = block.timestamp;

    // Attempt to deploy campaign with current timestamp
    // vm.expectRevert(Create2.Create2FailedDeployment.selector); // Create2.Create2FailedDeployment was removed and
    // replaced with Errors.FailedDeployment but the test won't pass with this
    vm.expectRevert();
    factory.deployCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      currentTimestamp, // Set to current timestamp
      address(0),
      RANDOM_UUID
    );

    // Verify campaign can be deployed with future timestamp
    uint256 futureTimestamp = currentTimestamp + 1 hours;
    address campaignDeployed = factory.deployCampaign(
      holdingPeriodInSeconds,
      address(toToken),
      address(rewardToken),
      REWARD_PPQ,
      campaignAdmin,
      futureTimestamp,
      address(0),
      RANDOM_UUID
    );

    NudgeCampaign deployedCampaign = NudgeCampaign(payable(campaignDeployed));

    // Verify campaign was created with correct timestamp
    assertEq(deployedCampaign.startTimestamp(), futureTimestamp);
    assertFalse(deployedCampaign.isCampaignActive());

    // But it should still enforce the start timestamp when calling handleReallocation
    vm.prank(swapCaller);
    vm.expectRevert(INudgeCampaign.StartDateNotReached.selector);
    deployedCampaign.handleReallocation(RANDOM_UUID, alice, address(toToken), 100e18, "");
  }

  /*//////////////////////////////////////////////////////////////////////////
                              VIEW FUNCTIONS                              
  //////////////////////////////////////////////////////////////////////////*/

  function test_GetBalanceOfSelfWithNativeToken() public {
    // Send some ETH
    uint256 amount = 4200 gwei;
    vm.prank(campaignAdmin);
    (bool sent,) = campaignAddress.call{ value: amount }("");

    assertTrue(sent, "Failed to send ETH");
    assertEq(campaign.getBalanceOfSelf(campaign.NATIVE_TOKEN()), amount);
    assertEq(campaignAddress.balance, amount);
  }

  function test_GetBalanceOfSelfWithERC20() public {
    // Send some toToken
    uint256 amount = 69e18;
    vm.prank(campaignAdmin);
    toToken.faucet(amount);
    vm.prank(campaignAdmin);
    toToken.transfer(campaignAddress, amount);

    assertEq(campaign.getBalanceOfSelf(address(toToken)), amount);
    assertEq(toToken.balanceOf(campaignAddress), amount);
  }

  function test_ClaimableRewardAmount() public {
    // Before any reallocation the whole funding amount is claimable
    assertEq(campaign.claimableRewardAmount(), INITIAL_FUNDING);

    // Reallocation of 100 toTokens
    uint256 toAmount = 100e18;
    simulateReallocation(alice, toAmount);

    // Calculate 2% of toAmount
    uint256 expectedRewardAmountIncludingFees = (toAmount * REWARD_PPQ) / PPQ_DENOMINATOR;

    assertEq(campaign.claimableRewardAmount(), INITIAL_FUNDING - expectedRewardAmountIncludingFees);
  }

  function test_ClaimableRewardAmountAfterMultipleReallocations() public {
    // Reallocation of 100 toTokens three times
    uint256 toAmount = 100e18;
    simulateReallocation(alice, toAmount);
    simulateReallocation(bob, toAmount);
    simulateReallocation(alice, toAmount);

    // Calculate 2% of total reallocated amount (300e18)
    uint256 expectedRewardAmountIncludingFees = (toAmount * 3 * REWARD_PPQ) / PPQ_DENOMINATOR;

    assertEq(campaign.claimableRewardAmount(), INITIAL_FUNDING - expectedRewardAmountIncludingFees);
  }

  function test_ClaimableRewardAmount_NoRewardsLeft() public {
    uint256 toAmount = 2_500_000e18; // This will use exactly 50% of the rewards
    simulateReallocation(alice, toAmount);
    simulateReallocation(bob, toAmount);

    // Should be exactly zero (fees deducted etc..)
    assertEq(campaign.claimableRewardAmount(), 0);
  }

  function test_getRewardAmountIncludingFees() public view {
    // Campaign parameters:
    // toToken and rewardToken are both 18 decimals
    // rewardPPQ is 2e13 (2%)

    // Reallocation of 100 toTokens
    uint256 toAmount_ = 100e18;
    // 2% of 100 tokens = 2 tokens
    assertEq(campaign.getRewardAmountIncludingFees(toAmount_), (toAmount_ * REWARD_PPQ) / PPQ_DENOMINATOR);

    // Reallocation of 200 toTokens
    toAmount_ = 200e18;
    // 2% of 200 tokens = 4 tokens
    assertEq(campaign.getRewardAmountIncludingFees(toAmount_), (toAmount_ * REWARD_PPQ) / PPQ_DENOMINATOR);

    // Reallocation of 50 toTokens
    toAmount_ = 50e18;
    // 2% of 50 tokens = 1 token
    assertEq(campaign.getRewardAmountIncludingFees(toAmount_), (toAmount_ * REWARD_PPQ) / PPQ_DENOMINATOR);

    // Reallocation of 4269 toTokens
    toAmount_ = 4269e18;
    // 2% of 4269 tokens = 85.38 tokens
    assertEq(campaign.getRewardAmountIncludingFees(toAmount_), (toAmount_ * REWARD_PPQ) / PPQ_DENOMINATOR);
  }

  function test_getRewardAmountIncludingFeesWithDifferentRewardParams() public {
    // Campaign parameters:
    // toToken and rewardToken are both 18 decimals
    uint256 rewardPPQ_ = 5e13; // 5% reward

    NudgeCampaign campaign_ = deployCampaign(toToken, rewardToken, rewardPPQ_);

    // Reallocation of 100 toTokens
    uint256 toAmount_ = 100e18;
    // 5% of 100 tokens = 5 tokens
    assertEq(campaign_.getRewardAmountIncludingFees(toAmount_), (toAmount_ * rewardPPQ_) / PPQ_DENOMINATOR);

    // Reallocation of 200 toTokens
    toAmount_ = 200e18;
    // 5% of 200 tokens = 10 tokens
    assertEq(campaign_.getRewardAmountIncludingFees(toAmount_), (toAmount_ * rewardPPQ_) / PPQ_DENOMINATOR);
  }

  function test_getRewardAmountIncludingFeesWithRewardTokenWithSmallerDecimals() public {
    // Campaign parameters:
    // toToken is 18 decimals
    // rewardToken is 6 decimals (USDC)
    TestUSDC rewardToken_ = new TestUSDC("Reward Token", "RT");
    uint256 rewardPPQ_ = 2e13; // 2% reward

    NudgeCampaign campaign_ = deployCampaign(toToken, rewardToken_, rewardPPQ_);

    // Reallocation of 100 toTokens
    uint256 toAmount_ = 100e18;
    // 2% of 100 tokens = 2 USDC = 2e6
    uint256 expectedRewardAmount = (toAmount_ * rewardPPQ_) / PPQ_DENOMINATOR / 1e12; // Convert to 6 decimals
    assertEq(campaign_.getRewardAmountIncludingFees(toAmount_), expectedRewardAmount);

    // Reallocation of 200 toTokens
    toAmount_ = 200e18;
    // 2% of 200 tokens = 4 USDC = 4e6
    expectedRewardAmount = (toAmount_ * rewardPPQ_) / PPQ_DENOMINATOR / 1e12;
    assertEq(campaign_.getRewardAmountIncludingFees(toAmount_), expectedRewardAmount);
  }

  function test_getRewardAmountIncludingFeesWithRewardTokenWithLargerDecimals() public {
    // Campaign parameters:
    // toToken is 6 decimals (USDC)
    // rewardToken is 18 decimals
    TestUSDC toToken_ = new TestUSDC("Incentivized Token", "IT");
    uint256 rewardPPQ_ = 2e13; // 2% reward

    NudgeCampaign campaign_ = deployCampaign(toToken_, rewardToken, rewardPPQ_);

    // Reallocation of 100 USDC
    uint256 toAmount_ = 100e6;
    // 2% of 100 USDC = 2 tokens in 18 decimals
    uint256 expectedRewardAmount = ((toAmount_ * rewardPPQ_) / PPQ_DENOMINATOR) * 1e12;
    assertEq(campaign_.getRewardAmountIncludingFees(toAmount_), expectedRewardAmount);

    // Reallocation of 200 USDC
    toAmount_ = 200e6;
    // 2% of 200 USDC = 4 tokens in 18 decimals
    expectedRewardAmount = ((toAmount_ * rewardPPQ_) / PPQ_DENOMINATOR) * 1e12;
    assertEq(campaign_.getRewardAmountIncludingFees(toAmount_), expectedRewardAmount);
  }

  function testFuzz_getRewardAmountIncludingFeesDifferentRewardPPQsAndToAmounts(
    uint256 rewardPPQ_,
    uint256 toAmount_
  )
    public
  {
    vm.assume(toAmount_ < 10_000_000_000e18); // Assume less than 10 billion tokens
    vm.assume(rewardPPQ_ > 1 && rewardPPQ_ < 1e25);
    TestUSDC rewardToken_ = new TestUSDC("Reward Token", "RT");

    NudgeCampaign campaign_ = deployCampaign(toToken, rewardToken_, rewardPPQ_);
    uint256 expectedRewardAmount = (toAmount_ * rewardPPQ_) / PPQ_DENOMINATOR / 1e12; // Convert to 6 decimals
    assertEq(campaign_.getRewardAmountIncludingFees(toAmount_), expectedRewardAmount);
  }

  function test_GetCampaignInfoInitial() public view {
    (
      uint32 _holdingPeriodInSeconds,
      address _targetToken,
      address _rewardToken,
      uint256 _rewardPPQ,
      uint256 _startTimestamp,
      bool _isCampaignActive,
      uint256 _pendingRewards,
      uint256 _totalReallocatedAmount,
      uint256 _distributedRewards,
      uint256 _claimableRewards
    ) = campaign.getCampaignInfo();

    assertEq(_holdingPeriodInSeconds, holdingPeriodInSeconds);
    assertEq(_targetToken, address(toToken));
    assertEq(_rewardToken, address(rewardToken));
    assertEq(_rewardPPQ, REWARD_PPQ);
    assertEq(_startTimestamp, campaign.startTimestamp());
    assertTrue(_isCampaignActive);
    assertEq(_pendingRewards, 0);
    assertEq(_totalReallocatedAmount, 0);
    assertEq(_distributedRewards, 0);
    assertEq(_claimableRewards, INITIAL_FUNDING);
  }

  function test_GetCampaignInfoAfterReallocations() public {
    uint256 toAmount = 1_234_239_235_235_098;
    simulateReallocation(alice, toAmount);

    (
      uint32 _holdingPeriodInSeconds,
      address _targetToken,
      address _rewardToken,
      uint256 _rewardPPQ,
      uint256 _startTimestamp,
      bool _isCampaignActive,
      uint256 _pendingRewards,
      uint256 _totalReallocatedAmount,
      uint256 _distributedRewards,
      uint256 _claimableRewards
    ) = campaign.getCampaignInfo();

    uint256 earMarkedRewardsIncludingFees = campaign.getRewardAmountIncludingFees(toAmount);
    uint256 earnedFees = Math.mulDiv(earMarkedRewardsIncludingFees, campaign.feeBps(), BPS_DENOMINATOR);

    assertEq(_holdingPeriodInSeconds, holdingPeriodInSeconds);
    assertEq(_targetToken, address(toToken));
    assertEq(_rewardToken, address(rewardToken));
    assertEq(_rewardPPQ, REWARD_PPQ);
    assertEq(_startTimestamp, campaign.startTimestamp());
    assertTrue(_isCampaignActive);
    assertEq(_pendingRewards, earMarkedRewardsIncludingFees - earnedFees);
    assertEq(_totalReallocatedAmount, toAmount);
    assertEq(_distributedRewards, 0);
    assertEq(_claimableRewards, campaign.getBalanceOfSelf(address(rewardToken)) - earMarkedRewardsIncludingFees);
  }

  function test_ClaimRewards_Success(uint256 toAmount_) public {
    vm.assume(toAmount_ < 5_000_000e18); // Make sure it fits the initial funding amount
    simulateReallocationAndFastForward(alice, toAmount_);

    uint256 balanceBefore = rewardToken.balanceOf(alice);

    // Claim rewards
    vm.prank(alice);
    campaign.claimRewards(pIDsWithOne);

    uint256 balanceAfter = rewardToken.balanceOf(alice);
    (uint256 userRewards,) = getUserRewardsAndFeesFromToAmount(campaign, toAmount_);
    assertEq(balanceAfter, balanceBefore + userRewards);
  }

  function test_ClaimRewards_WithNativeTokenRewards_Success() public {
    address campaignWithNativeRewardsAddress = factory.deployAndFundCampaign{ value: 100 ether }(
      holdingPeriodInSeconds,
      address(toToken),
      NATIVE_TOKEN,
      REWARD_PPQ,
      campaignAdmin,
      0,
      alternativeWithdrawalAddress,
      100 ether,
      RANDOM_UUID
    );
    NudgeCampaign campaignWithNativeToken = NudgeCampaign(payable(campaignWithNativeRewardsAddress));

    uint256 toAmount = 100e18;
    // Simulate getting toTokens from end user
    vm.prank(swapCaller);
    toToken.faucet(toAmount);

    vm.prank(swapCaller);
    toToken.approve(campaignWithNativeRewardsAddress, toAmount);

    vm.prank(swapCaller);
    campaignWithNativeToken.handleReallocation(RANDOM_UUID, alice, address(toToken), toAmount, "");

    vm.warp(block.timestamp + holdingPeriodInSeconds + 1);

    uint256 balanceBefore = alice.balance;

    // Claim rewards
    vm.prank(alice);
    campaignWithNativeToken.claimRewards(pIDsWithOne);

    uint256 balanceAfter = alice.balance;
    (uint256 userRewards,) = getUserRewardsAndFeesFromToAmount(campaignWithNativeToken, toAmount);
    assertEq(balanceAfter, balanceBefore + userRewards);
  }

  function test_ClaimRewards_EmptyArrayReverts() public {
    vm.expectRevert(INudgeCampaign.EmptyParticipationsArray.selector);
    campaign.claimRewards(new uint256[](0));
  }

  function test_ClaimRewards_InvalidParticipationStatusReverts() public {
    uint256 toAmount = 94_768e18;
    simulateReallocation(alice, toAmount);

    vm.prank(operator);
    campaign.invalidateParticipations(pIDsWithOne);

    // Ensure the participation has the INVALIDATED status
    (IBaseNudgeCampaign.ParticipationStatus status,,,,,) = campaign.participations(1);
    assertEq(uint256(status), 1);

    // Claim rewards
    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(INudgeCampaign.InvalidParticipationStatus.selector, 1));
    campaign.claimRewards(pIDsWithOne);
  }

  function test_ClaimRewards_InvalidCallerReverts() public {
    uint256 toAmount = 100e18;
    simulateReallocationAndFastForward(alice, toAmount);

    // Attempt to claim from a different address
    vm.prank(bob);
    vm.expectRevert(abi.encodeWithSelector(INudgeCampaign.UnauthorizedCaller.selector, 1));
    campaign.claimRewards(pIDsWithOne);
  }

  function test_ClaimRewards_BeforeHoldingPeriodReverts() public {
    uint256 toAmount = 100e18;
    simulateReallocation(alice, toAmount);

    // Attempt to claim immediately
    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(INudgeCampaign.HoldingPeriodNotElapsed.selector, 1));
    campaign.claimRewards(pIDsWithOne);
  }

  // This should not happen because withdrawRewards does not allow to withdraw
  // already earmarked rewards and fees
  function test_ClaimRewards_NotEnoughRewardsAvailable() public {
    uint256 toAmount = 100e18;
    simulateReallocationAndFastForward(alice, toAmount);

    // Sets the rewardToken balance of the campaign contract to be less than
    // the reward amount the user is claiming
    (uint256 userRewards,) = getUserRewardsAndFeesFromToAmount(campaign, toAmount);
    deal(address(rewardToken), campaignAddress, userRewards - 10);
    assertEq(campaign.getBalanceOfSelf(address(rewardToken)), userRewards - 10);

    uint256 balanceBefore = rewardToken.balanceOf(alice);
    uint256 pendingRewardsBefore = campaign.pendingRewards();
    uint256 distributedRewardsBefore = campaign.distributedRewards();

    // Attempt to claim
    vm.prank(alice);
    campaign.claimRewards(pIDsWithOne);

    uint256 balanceAfter = rewardToken.balanceOf(alice);
    uint256 pendingRewardsAfter = campaign.pendingRewards();
    uint256 distributedRewardsAfter = campaign.distributedRewards();
    (IBaseNudgeCampaign.ParticipationStatus status,,,,,) = campaign.participations(1);

    assertEq(balanceAfter, balanceBefore);
    assertEq(pendingRewardsAfter, pendingRewardsBefore);
    assertEq(distributedRewardsAfter, distributedRewardsBefore);
    assertEq(uint256(status), 0); // PARTICIPATING
  }

  function test_ClaimRewards_MultipleSuccessfulClaimsUpdatesBalances() public {
    uint256 toAmountOne = 100e18;
    uint256 toAmountTwo = 200e18;
    uint256 toAmountThree = 300e18;
    simulateReallocationAndFastForward(alice, toAmountOne);
    simulateReallocationAndFastForward(bob, toAmountTwo);
    simulateReallocationAndFastForward(alice, toAmountThree);

    uint256[] memory alicePIDs = new uint256[](2);
    alicePIDs[0] = 1;
    alicePIDs[1] = 3;

    uint256[] memory bobPIDs = new uint256[](1);
    bobPIDs[0] = 2;

    uint256 aliceBalanceBefore = rewardToken.balanceOf(alice);
    uint256 bobBalanceBefore = rewardToken.balanceOf(bob);

    // Claim rewards
    vm.prank(alice);
    campaign.claimRewards(alicePIDs);

    vm.prank(bob);
    campaign.claimRewards(bobPIDs);

    uint256 aliceBalanceAfter = rewardToken.balanceOf(alice);
    uint256 bobBalanceAfter = rewardToken.balanceOf(bob);

    (uint256 aliceRewardsFromPidOne,) = getUserRewardsAndFeesFromToAmount(campaign, toAmountOne);
    (uint256 aliceRewardsFromPidTwo,) = getUserRewardsAndFeesFromToAmount(campaign, toAmountThree);
    (uint256 bobRewards,) = getUserRewardsAndFeesFromToAmount(campaign, toAmountTwo);

    assertEq(aliceBalanceAfter, aliceBalanceBefore + aliceRewardsFromPidOne + aliceRewardsFromPidTwo);
    assertEq(bobBalanceAfter, bobBalanceBefore + bobRewards);
  }

  function test_ClaimRewards_MultipleSuccessfulClaimsUpdatesContractState() public {
    uint256 toAmountOne = 100e18;
    uint256 toAmountTwo = 200e18;
    uint256 toAmountThree = 300e18;
    simulateReallocationAndFastForward(alice, toAmountOne);
    simulateReallocationAndFastForward(bob, toAmountTwo);
    simulateReallocationAndFastForward(alice, toAmountThree);

    uint256[] memory alicePIDs = new uint256[](2);
    alicePIDs[0] = 1;
    alicePIDs[1] = 3;

    uint256[] memory bobPIDs = new uint256[](1);
    bobPIDs[0] = 2;

    uint256 pendingRewardsBefore = campaign.pendingRewards();
    uint256 distributedRewardsBefore = campaign.distributedRewards();

    // Claim rewards
    vm.prank(alice);
    campaign.claimRewards(alicePIDs);

    vm.prank(bob);
    campaign.claimRewards(bobPIDs);

    uint256 pendingRewardsAfter = campaign.pendingRewards();
    uint256 distributedRewardsAfter = campaign.distributedRewards();

    (uint256 aliceRewardsFromPidOne,) = getUserRewardsAndFeesFromToAmount(campaign, toAmountOne);
    (uint256 aliceRewardsFromPidTwo,) = getUserRewardsAndFeesFromToAmount(campaign, toAmountThree);
    (uint256 bobRewards,) = getUserRewardsAndFeesFromToAmount(campaign, toAmountTwo);

    uint256 totalRewards = aliceRewardsFromPidOne + aliceRewardsFromPidTwo + bobRewards;
    assertEq(pendingRewardsAfter, pendingRewardsBefore - totalRewards);
    assertEq(distributedRewardsAfter, distributedRewardsBefore + totalRewards);
  }

  function test_ClaimRewards_MultipleSuccessfulClaimsUpdatesParticipationStatus() public {
    uint256 toAmountOne = 100e18;
    uint256 toAmountTwo = 200e18;
    uint256 toAmountThree = 300e18;
    simulateReallocationAndFastForward(alice, toAmountOne);
    simulateReallocationAndFastForward(bob, toAmountTwo);
    simulateReallocationAndFastForward(alice, toAmountThree);

    uint256[] memory alicePIDs = new uint256[](2);
    alicePIDs[0] = 1;
    alicePIDs[1] = 3;

    uint256[] memory bobPIDs = new uint256[](1);
    bobPIDs[0] = 2;

    // Claim rewards
    vm.prank(alice);
    campaign.claimRewards(alicePIDs);

    vm.prank(bob);
    campaign.claimRewards(bobPIDs);

    (IBaseNudgeCampaign.ParticipationStatus statusOne,,,,,) = campaign.participations(1);
    (IBaseNudgeCampaign.ParticipationStatus statusTwo,,,,,) = campaign.participations(2);
    (IBaseNudgeCampaign.ParticipationStatus statusThree,,,,,) = campaign.participations(3);

    // Check they have the CLAIMED status
    assertEq(uint256(statusOne), 2);
    assertEq(uint256(statusTwo), 2);
    assertEq(uint256(statusThree), 2);
  }

  function test_ClaimableRewards_MultiplSuccessfulClaimsEmitEvent() public {
    uint256 toAmountOne = 100e18;
    uint256 toAmountTwo = 200e18;
    uint256 toAmountThree = 300e18;
    simulateReallocationAndFastForward(alice, toAmountOne);
    simulateReallocationAndFastForward(bob, toAmountTwo);
    simulateReallocationAndFastForward(alice, toAmountThree);

    uint256[] memory alicePIDs = new uint256[](2);
    alicePIDs[0] = 1;
    alicePIDs[1] = 3;

    (uint256 aliceRewardsFromPidOne,) = getUserRewardsAndFeesFromToAmount(campaign, toAmountOne);
    (uint256 aliceRewardsFromPidTwo,) = getUserRewardsAndFeesFromToAmount(campaign, toAmountThree);

    // Claim rewards
    vm.prank(alice);
    vm.expectEmit(true, true, true, true);
    emit INudgeCampaign.NudgeRewardClaimed(1, alice, aliceRewardsFromPidOne);
    vm.expectEmit(true, true, true, true);
    emit INudgeCampaign.NudgeRewardClaimed(3, alice, aliceRewardsFromPidTwo);
    campaign.claimRewards(alicePIDs);
  }

  // This should not happen because withdrawRewards does not allow to withdraw
  // already earmarked rewards and fees
  function test_ClaimableRewards_PartialClaimFromLesserRewardBalance() public {
    uint256 toAmount = 100e18;

    simulateReallocationAndFastForward(alice, toAmount);
    simulateReallocationAndFastForward(alice, toAmount);

    // Sets the rewardToken balance of the campaign contract to be just enough to cover
    // the rewards from the first reallocation. not the second
    (uint256 rewardsFromOneReallocation,) = getUserRewardsAndFeesFromToAmount(campaign, toAmount);
    deal(address(rewardToken), campaignAddress, rewardsFromOneReallocation);
    assertEq(campaign.getBalanceOfSelf(address(rewardToken)), rewardsFromOneReallocation);

    uint256 balanceBefore = rewardToken.balanceOf(alice);
    uint256 pendingRewardsBefore = campaign.pendingRewards();
    uint256 distributedRewardsBefore = campaign.distributedRewards();

    // Attempt to claim
    uint256[] memory alicePIDs = new uint256[](2);
    alicePIDs[0] = 1;
    alicePIDs[1] = 2;

    vm.prank(alice);
    campaign.claimRewards(alicePIDs);

    uint256 balanceAfter = rewardToken.balanceOf(alice);
    uint256 pendingRewardsAfter = campaign.pendingRewards();
    uint256 distributedRewardsAfter = campaign.distributedRewards();

    assertEq(balanceAfter, balanceBefore + rewardsFromOneReallocation);
    assertEq(pendingRewardsAfter, pendingRewardsBefore - rewardsFromOneReallocation);
    assertEq(distributedRewardsAfter, distributedRewardsBefore + rewardsFromOneReallocation);

    (IBaseNudgeCampaign.ParticipationStatus statusOfFirstParticipation,,,,,) = campaign.participations(1);
    (IBaseNudgeCampaign.ParticipationStatus statusOfSecondParticipation,,,,,) = campaign.participations(2);
    assertEq(uint256(statusOfFirstParticipation), 2); // CLAIMED
    assertEq(uint256(statusOfSecondParticipation), 0); // PARTICIPATING
  }

  function test_TopUpERC20Rewards_Success() public {
    uint256 toAmount = 100_000e18;
    simulateReallocationAndFastForward(alice, toAmount);

    uint256 topUpAmount = 1_000_000e18;
    uint256 balanceBefore = rewardToken.balanceOf(campaignAddress);
    uint256 claimableRewardBefore = campaign.claimableRewardAmount();

    vm.prank(campaignAdmin);
    rewardToken.transfer(campaignAddress, topUpAmount);

    uint256 balanceAfter = rewardToken.balanceOf(campaignAddress);
    uint256 claimableRewardAfter = campaign.claimableRewardAmount();
    assertEq(balanceAfter, balanceBefore + topUpAmount);
    assertEq(claimableRewardAfter, claimableRewardBefore + topUpAmount);
  }

  function test_TopUpNativeRewards_Success() public {
    address campaignWithNativeRewardsAddress = factory.deployAndFundCampaign{ value: 100e18 }(
      holdingPeriodInSeconds,
      address(toToken),
      NATIVE_TOKEN,
      REWARD_PPQ,
      campaignAdmin,
      0,
      alternativeWithdrawalAddress,
      100e18,
      RANDOM_UUID
    );
    NudgeCampaign campaignWithNativeRewards = NudgeCampaign(payable(campaignWithNativeRewardsAddress));

    uint256 topUpAmount = 1e18;
    uint256 balanceBefore = campaignWithNativeRewardsAddress.balance;
    uint256 claimableRewardBefore = campaignWithNativeRewards.claimableRewardAmount();

    vm.prank(campaignAdmin);
    (bool success,) = campaignWithNativeRewardsAddress.call{ value: topUpAmount }("");

    assertTrue(success);

    uint256 balanceAfter = campaignWithNativeRewardsAddress.balance;
    uint256 claimableRewardAfter = campaignWithNativeRewards.claimableRewardAmount();

    assertEq(balanceAfter, balanceBefore + topUpAmount);
    assertEq(claimableRewardAfter, claimableRewardBefore + topUpAmount);
  }

  function test_RewardCalculationWithSameDecimals() public {
    // Both tokens have 18 decimals
    uint256 toAmount = 100e18;

    // 2% of 100e18 = 2e18
    uint256 expectedReward = (toAmount * REWARD_PPQ) / PPQ_DENOMINATOR;
    assertEq(campaign.getRewardAmountIncludingFees(toAmount), expectedReward);
  }

  function test_RewardCalculationWithDifferentDecimals() public {
    // Target token has 6 decimals (like USDC)
    TestUSDC usdcToken = new TestUSDC("USDC", "USDC");
    // Reward token has 18 decimals
    TestERC20 rewardToken_ = new TestERC20("Reward", "RWD");

    NudgeCampaign campaign_ = deployCampaign(usdcToken, rewardToken_, REWARD_PPQ);

    // Test with 100 USDC (6 decimals)
    uint256 toAmount = 100e6; // 100 USDC

    // When input is 100e6 (USDC), we need to scale up by 1e12 to match the 18 decimals of the reward token
    uint256 expectedReward = ((toAmount * REWARD_PPQ) / PPQ_DENOMINATOR) * 1e12;
    console.log("expectedReward", expectedReward);
    console.log("campaign_.getRewardAmountIncludingFees(toAmount)", campaign_.getRewardAmountIncludingFees(toAmount));

    assertEq(campaign_.getRewardAmountIncludingFees(toAmount), expectedReward);
  }

  function test_RewardCalculationWithLargeAmount() public {
    // Test with 1 million tokens
    uint256 toAmount = 1_000_000e18;

    // 2% of 1M tokens = 20k tokens
    uint256 expectedReward = (toAmount * REWARD_PPQ) / PPQ_DENOMINATOR;
    assertEq(campaign.getRewardAmountIncludingFees(toAmount), expectedReward);
  }

  function test_RewardCalculationWithSmallAmount() public {
    // Test with 0.1 token
    uint256 toAmount = 1e17;

    // 2% of 0.1 token = 0.002 token
    uint256 expectedReward = (toAmount * REWARD_PPQ) / PPQ_DENOMINATOR;
    assertEq(campaign.getRewardAmountIncludingFees(toAmount), expectedReward);
  }

  struct TestCase {
    uint8 toDecimals;
    uint8 rewardDecimals;
    uint256 toAmount;
    string description;
  }

  function test_RewardCalculationWithVariousDecimals() public {
    vm.pauseGasMetering();
    // Test cases with different decimal combinations
    TestCase[] memory testCases = new TestCase[](19 * 19); // All combinations from 0 to 18
    uint256 testIndex = 0;

    // Generate all possible combinations of decimals from 0 to 18
    for (uint8 toDecimals = 0; toDecimals <= 18; toDecimals++) {
      for (uint8 rewardDecimals = 0; rewardDecimals <= 18; rewardDecimals++) {
        // Calculate base amount: 100 * 10^toDecimals
        uint256 toAmount;
        unchecked {
          toAmount = 100 * (10 ** toDecimals);
        }

        testCases[testIndex] = TestCase({
          toDecimals: toDecimals,
          rewardDecimals: rewardDecimals,
          toAmount: toAmount,
          description: string.concat(
            "To decimals: ", Strings.toString(toDecimals), ", Reward decimals: ", Strings.toString(rewardDecimals)
          )
        });
        testIndex++;
      }
    }

    for (uint256 i = 0; i < testCases.length; i++) {
      TestCase memory tc = testCases[i];

      // Deploy tokens with specific decimals
      MockTokenDecimals toToken_ = new MockTokenDecimals("TT", "TT", tc.toDecimals);
      MockTokenDecimals rewardToken_ = new MockTokenDecimals("RT", "RT", tc.rewardDecimals);

      // Deploy campaign
      NudgeCampaign campaign_ = deployCampaign(toToken_, rewardToken_, REWARD_PPQ);

      // Calculate expected reward
      uint256 expectedReward = (tc.toAmount * REWARD_PPQ) / PPQ_DENOMINATOR;

      // If reward token has more decimals, scale up
      if (tc.rewardDecimals > tc.toDecimals) {
        expectedReward = expectedReward * (10 ** (tc.rewardDecimals - tc.toDecimals));
      }
      // If reward token has fewer decimals, scale down
      else if (tc.rewardDecimals < tc.toDecimals) {
        expectedReward = expectedReward / (10 ** (tc.toDecimals - tc.rewardDecimals));
      }

      console.log("Testing:", tc.description);
      console.log("Input amount:", tc.toAmount);
      console.log("Expected reward:", expectedReward);
      console.log("Actual reward:", campaign_.getRewardAmountIncludingFees(tc.toAmount));

      assertEq(
        campaign_.getRewardAmountIncludingFees(tc.toAmount),
        expectedReward,
        string.concat("Failed case: ", tc.description)
      );
    }
  }

  function testFuzz_RewardCalculationWithVariousDecimalsAndAmounts(uint256 toAmount) public {
    vm.pauseGasMetering();
    // Bound toAmount to reasonable values (up to 1 billion tokens)
    toAmount = bound(toAmount, 1, 1_000_000_000 * 1e18);

    // Test cases with different decimal combinations
    TestCase[] memory testCases = new TestCase[](19 * 19); // All combinations from 0 to 18
    uint256 testIndex = 0;

    // Generate all possible combinations of decimals from 0 to 18
    for (uint8 toDecimals = 0; toDecimals <= 18; toDecimals++) {
      for (uint8 rewardDecimals = 0; rewardDecimals <= 18; rewardDecimals++) {
        // Scale toAmount to the target token's decimals
        uint256 scaledAmount;
        if (toDecimals < 18) {
          scaledAmount = toAmount / (10 ** (18 - toDecimals));
        } else {
          scaledAmount = toAmount;
        }

        testCases[testIndex] = TestCase({
          toDecimals: toDecimals,
          rewardDecimals: rewardDecimals,
          toAmount: scaledAmount,
          description: string.concat(
            "To decimals: ", Strings.toString(toDecimals), ", Reward decimals: ", Strings.toString(rewardDecimals)
          )
        });
        testIndex++;
      }
    }

    for (uint256 i = 0; i < testCases.length; i++) {
      TestCase memory tc = testCases[i];

      // Deploy tokens with specific decimals
      MockTokenDecimals toToken_ = new MockTokenDecimals("TT", "TT", tc.toDecimals);
      MockTokenDecimals rewardToken_ = new MockTokenDecimals("RT", "RT", tc.rewardDecimals);

      // Deploy campaign
      NudgeCampaign campaign_ = deployCampaign(toToken_, rewardToken_, REWARD_PPQ);

      // Scale amount to 18 decimals for reward calculation
      uint256 targetScalingFactor = 10 ** (18 - tc.toDecimals);
      uint256 rewardScalingFactor = 10 ** (18 - tc.rewardDecimals);
      uint256 scaledAmount = tc.toAmount * targetScalingFactor;

      // Calculate reward in 18 decimals
      // Using mulDiv here to avoid overflow when multiplying large numbers
      // and to handle division rounding consistently
      uint256 rewardAmountIn18Decimals = Math.mulDiv(scaledAmount, REWARD_PPQ, PPQ_DENOMINATOR);

      uint256 expectedReward = rewardAmountIn18Decimals / rewardScalingFactor;

      // Only log on failure to avoid spam
      try campaign_.getRewardAmountIncludingFees(tc.toAmount) returns (uint256 actualReward) {
        if (actualReward != expectedReward) {
          console.log("Failed case:", tc.description);
          console.log("Input amount:", tc.toAmount);
          console.log("Expected reward:", expectedReward);
          console.log("Actual reward:", actualReward);
        }
        assertEq(actualReward, expectedReward, string.concat("Failed case: ", tc.description));
      } catch {
        console.log("Failed case:", tc.description);
        console.log("Input amount:", tc.toAmount);
        console.log("Expected reward:", expectedReward);
        revert(string.concat("Test failed for case: ", tc.description));
      }
    }
  }
}
