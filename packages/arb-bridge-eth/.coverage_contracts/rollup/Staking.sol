// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2019-2020, Offchain Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pragma solidity ^0.5.11;

import "./RollupUtils.sol";
import "../libraries/RollupTime.sol";

import "../challenge/ChallengeUtils.sol";
import "../challenge/IChallengeFactory.sol";

import "../interfaces/IERC20.sol";

contract Staking {
function coverage_0xed03da06(bytes32 c__0xed03da06) public pure {}

    // VM already initialized"
    string private constant INIT_TWICE = "INIT_TWICE";
    // Challenge factory must be nonzero
    string private constant INIT_NONZERO = "INIT_NONZERO";

    // Invalid staker
    string private constant INV_STAKER = "INV_STAKER";

    // must supply stake value
    string private constant STK_AMT = "STK_AMT";
    // Staker already exists
    string private constant TRANSFER_FAILED = "TRANSFER_FAILED";
    string private constant ALRDY_STAKED = "ALRDY_STAKED";

    // Challenge can only be resolved by spawned contract
    string private constant RES_CHAL_SENDER = "RES_CHAL_SENDER";

    // staker1 staked after deadline
    string private constant STK1_DEADLINE = "STK1_DEADLINE";
    // staker2 staked after deadline
    string private constant STK2_DEADLINE = "STK2_DEADLINE";
    // staker1 already in a challenge
    string private constant STK1_IN_CHAL = "STK1_IN_CHAL";
    // staker2 already in a challenge
    string private constant STK2_IN_CHAL = "STK2_IN_CHAL";
    // Child types must be ordered
    string private constant TYPE_ORDER = "TYPE_ORDER";
    // Invalid child type
    string private constant INVLD_CHLD_TYPE = "INVLD_CHLD_TYPE";
    // Challenge asserter proof
    string private constant ASSERT_PROOF = "ASSERT_PROOF";
    // Challenge challenger proof
    string private constant CHAL_PROOF = "CHAL_PROOF";

    // must include proof for all stakers
    string private constant CHCK_COUNT = "CHCK_COUNT";
    // Stakers must be ordered
    string private constant CHCK_ORDER = "CHCK_ORDER";
    // at least one active staker disagrees
    string private constant CHCK_STAKER_PROOF = "CHCK_STAKER_PROOF";
    string private constant CHCK_OFFSETS = "CHCK_OFFSETS";

    uint256 private constant MAX_CHILD_TYPE = 3;

    IChallengeFactory public challengeFactory;

    struct Staker {
        bytes32 location;
        uint128 creationTimeBlocks;
        bool inChallenge;
    }

    uint128 private stakeRequirement;
    address private stakeToken;
    mapping(address => Staker) private stakers;
    uint256 private stakerCount;
    mapping(address => bool) private challenges;
    mapping(address => uint256) withdrawnStakes;

    event RollupStakeCreated(address staker, bytes32 nodeHash);

    event RollupStakeRefunded(address staker);

    event RollupStakeMoved(address staker, bytes32 toNodeHash);

    event RollupChallengeStarted(
        address asserter,
        address challenger,
        uint256 challengeType,
        address challengeContract
    );

    event RollupChallengeCompleted(address challengeContract, address winner, address loser);

    function getStakeRequired() external view returns (uint128) {coverage_0xed03da06(0x8acc824a894c211012d1059a49d82974b5cb62ddb3766fc85941839775a4b5f7); /* function */ 

coverage_0xed03da06(0xb740b8e426c29f5fa5a3fce1c0f6791b68236351db5cfb5999023d028a9a8781); /* line */ 
        coverage_0xed03da06(0x99e00f79662abc38bc7b9b447b29145fd58b40a9dc3c6c6585b9bc300f6deae5); /* statement */ 
return stakeRequirement;
    }

    function getStakeToken() external view returns (address) {coverage_0xed03da06(0xee32af772618ec9a8dcc9f987b917d161ddf6c43d7998db04a03b76a0710cf4a); /* function */ 

coverage_0xed03da06(0x85698d7ea1864016f4926606a51e7e979a95f9d6d676bb27df612295b1ff5ed0); /* line */ 
        coverage_0xed03da06(0x618b181067a9ff539f2285269279a6f3ffd4fc5e25112a4ba7e699d3a7d64944); /* statement */ 
return stakeToken;
    }

    function isStaked(address _stakerAddress) external view returns (bool) {coverage_0xed03da06(0x1bf7171d86354338228ec10a0d53d89a4b0dc42e379fb28ea0cdf722b1c03132); /* function */ 

coverage_0xed03da06(0x32f2da19b55aa8f4334606464b2666df883f4951e6fc1477208d374b8a595357); /* line */ 
        coverage_0xed03da06(0xf33a97542ab56e558f4d78c24c0c6e0ff56d12241c5c11731f7de7eeafcd1b66); /* statement */ 
return stakers[_stakerAddress].location != 0x00;
    }

    function getWithdrawnStake(address payable _staker) external {coverage_0xed03da06(0x457483176bcda64282d5533511469b3273c3834d47e0687849f7b3bb2014a889); /* function */ 

coverage_0xed03da06(0x3c3163cd2e4f678972930a8ac83d807c850a7210414c4140cd6e929228560b63); /* line */ 
        coverage_0xed03da06(0x277d6f9a6d4e80598c7be85cffd478fd407d27427583bc74429844c4d61cbd02); /* statement */ 
uint256 amount = withdrawnStakes[_staker];
coverage_0xed03da06(0x11312e98ef789f38dfa2aea49cdf3a0a838d17401d7d5d9c402261947f5446bd); /* line */ 
        coverage_0xed03da06(0xac9038bcd36ebff8a74c69c60e1545c84a10f76652c723c8da8855c12e6a4b05); /* statement */ 
if (amount == 0) {coverage_0xed03da06(0x9519540c367803c7f72d24ef0e8891ade27eace19bd0c1f9b73cd309192fe12a); /* branch */ 

coverage_0xed03da06(0x0138302267fca5fd2784e811f3444648f3d9dedc6aa2a9b935f1170ab7d3694d); /* line */ 
            coverage_0xed03da06(0xbc935aa8c0f46fa3bf57ef5bbed6c6eeb2458a6297d321a8bb511229f87966d4); /* statement */ 
return;
        }else { coverage_0xed03da06(0x789f690d8b6526060faf9097dbd7461d7a63e6c6feef175ff2bd1532e245eff3); /* branch */ 
}
coverage_0xed03da06(0x8c6e2987eed61918cc6578109e4d59a61c0748a810997770d2528b6b801cb016); /* line */ 
        coverage_0xed03da06(0xc56f3c7f88ae9fdfe39dadbb2ca989b02b1df7111133cbbeb2ba49ae695dceac); /* statement */ 
if (stakeToken == address(0)) {coverage_0xed03da06(0x680cefd735e5a765ce761eec71a977131bad160df5dc288cd990d9adf5720da4); /* branch */ 

coverage_0xed03da06(0x5d25ba0220a456af9e8990a39dc6241b7df8a345bf64ff181688800e1ae5a8c8); /* line */ 
            coverage_0xed03da06(0xa44a598a05831c7bff5f15e576bd151fcb14733ead6b58b5b69d6785079e163d); /* statement */ 
_staker.transfer(amount);
        } else {coverage_0xed03da06(0xf1e6364212de9c39fcb27551117ea039efb61372db622f8d93714e1396830392); /* branch */ 

coverage_0xed03da06(0x4b7e25960adf9e7abb5e23a29b49b55ba4de22a6fd20f584a98431a9fa5512a1); /* line */ 
            coverage_0xed03da06(0x63dde9c1c52ae9fafa533abe86453580cb6125e66a633c1e218413e1f80ca884); /* assertPre */ 
coverage_0xed03da06(0x188abc39043f34501593b19f8fd4c9b4b75b1bd686d341ef82f0e4605991fada); /* statement */ 
require(IERC20(stakeToken).transfer(_staker, amount), TRANSFER_FAILED);coverage_0xed03da06(0xc3996780752b21cf0b5eca76eb3fce931eeadd3c12adaf3cf28f8fc3a95a248a); /* assertPost */ 

        }
    }

    /**
     * @notice Update stakers with the result of a challenge that has ended. The winner received half of the losers deposit and the rest is burned
     * @dev Currently the rollup contract keeps the burned funds. These are frozen since the rollup contract has no way to withdraw them
     * @dev This function can only be called by a challenge contract launched by this contract. Because of this we don't require any other input validator
     * @dev Consider using CREATE2 to eliminate the need to remember what challenges we've launched
     * @param winner The address of the staker who won the challenge
     * @param loser The address of the staker who lost the challenge
     */
    function resolveChallenge(address payable winner, address loser) external {coverage_0xed03da06(0x8b452bd8e083a8d8f1417dc2c4e7dd848919b621d0ad4763b2affd882bba2e35); /* function */ 

coverage_0xed03da06(0x0f4744dfbd6a3eaf51a4d82ddcc4d7529bf83cfd90ca4a47bf83561c76ae2b45); /* line */ 
        coverage_0xed03da06(0xc369f5eeff28fbd0fa870d46a399d24c4d584ce2ce9f1c583ba7c5f2ec766c9b); /* assertPre */ 
coverage_0xed03da06(0xaf1543e21431779c1f81f78e93da285862f13f64dfd49eb2c2efb0a5a330f7f1); /* statement */ 
require(challenges[msg.sender], RES_CHAL_SENDER);coverage_0xed03da06(0x3d3646f4b2cc6638e5e351bad803b69fae22d8888e1d9c80e2150a3adab22d1d); /* assertPost */ 

coverage_0xed03da06(0xa05776ee1ab0ab054cb4172978b380ea08247fdbf91619f33f90ded354db688b); /* line */ 
        delete challenges[msg.sender];

coverage_0xed03da06(0x3fdd89f8eeb25ff248c343b41f99033e6a1875b0c925c689460a5bd713d3eb07); /* line */ 
        coverage_0xed03da06(0xc1dcfcb430f3f2ae7c16522a22b92a7d8d7c6ba2ce1202fe772ec996fddf00c4); /* statement */ 
Staker storage winningStaker = getValidStaker(address(winner));
coverage_0xed03da06(0xb51a4a950bb1e362b16d682fa42d129590af81d1d0e986741ead70ce7062d831); /* line */ 
        coverage_0xed03da06(0xc3e961aab1867693f93286b06521bae0575dd8bf719e992a9ba3851cd48ea7cb); /* statement */ 
withdrawnStakes[winner] += stakeRequirement / 2;
coverage_0xed03da06(0x8a2bb94dee358e809cdce6c9f143659a5a0a3e38d8fa57d323fabd030333fc2f); /* line */ 
        coverage_0xed03da06(0xb557d5ba9479cc30afee4b35ad8a1a0529832037dafd62ebdd0be8b996ef6f28); /* statement */ 
winningStaker.inChallenge = false;
coverage_0xed03da06(0x86cdb3908dc5f2d75de0ccc8dd7c526fd96e3a28392d2bb54f5499540e561834); /* line */ 
        coverage_0xed03da06(0x5b5de9feec34068f594072c2ffb9de72c92dccaddcdbe33236b7b5ace52bf9bc); /* statement */ 
deleteStaker(loser);

coverage_0xed03da06(0x7ee130ef2594aa3b1edee290311a08e5ed63e6f6ff655adf11c5985688602734); /* line */ 
        coverage_0xed03da06(0x54e97bba68d39822b999cf00e15906c42647d03b1a7a2dde1e1569815a2196b6); /* statement */ 
emit RollupChallengeCompleted(msg.sender, address(winner), loser);
    }

    /**
     * @notice Initiate a challenge between two validators staked on this rollup chain.
     * @dev Anyone can force two conflicted validators to engage in a challenge
     * @dev The challenge will occur on the oldest node that the two validators disagree about
     * @param asserterAddress The staker who claimed a given node was valid
     * @param challengerAddress The address who claimed that the same node was invalid
     * @param prevNode The node which is the parent of the two conflicting nodes the asserter and challenger are on
     * @param deadlineTicks The deadline to challenge the asserter's node
     * @param stakerNodeTypes The type of nodes that the asserter and challenger are staked on
     * @param vmProtoHashes The protocol states claimed by each validator
     * @param asserterProof A proof that the asserter actually staked that the claimed node was correct
     * @param challengerProof A proof that the challenger actually staked that hte claimed node was invalid
     * @param asserterNodeHash Type specific data in the asserter's node
     * @param challengerDataHash Information from the challenger's node about the claim the asserter is disputing
     * @param challengerPeriodTicks Amount of time dedicated to rounds of the challenge created
     */
    function startChallenge(
        address payable asserterAddress,
        address payable challengerAddress,
        bytes32 prevNode,
        uint256 deadlineTicks,
        uint256[2] memory stakerNodeTypes, // [asserterNodeType, challengerNodeType]
        bytes32[2] memory vmProtoHashes, // [asserterVMProtoHash, challengerVMProtoHash]
        bytes32[] memory asserterProof,
        bytes32[] memory challengerProof,
        bytes32 asserterNodeHash,
        bytes32 challengerDataHash,
        uint128 challengerPeriodTicks
    ) public {coverage_0xed03da06(0x009a994456adb4cc10d5d92de26b402e88f48ff1d06210d810f338e48714968f); /* function */ 

coverage_0xed03da06(0x9077e4b39fc67807b82e928c0023236cb4c5233e3c171d110df12af185c22d2c); /* line */ 
        coverage_0xed03da06(0xf93b24ee98965411779bddc2a10ad184fbc006bc0e43f3a2caa901d22f8b3a51); /* statement */ 
Staker storage asserter = getValidStaker(asserterAddress);
coverage_0xed03da06(0x14389068166241631916f1f98a45580ad40a9edc5380108d04e83c023b9bd7fe); /* line */ 
        coverage_0xed03da06(0x602936d346e2181372be9e321911803956ef3eef43cd9b7984d4c845cc5b2f33); /* statement */ 
Staker storage challenger = getValidStaker(challengerAddress);

coverage_0xed03da06(0xb363c5f1ae4665d15f66f00dd2c2498f6a764f066f2707f2117f636fb8907f84); /* line */ 
        coverage_0xed03da06(0x82b71f6ce93a67c64c27adeb8582eae622dbdb178c19874906abe0ac8d631a01); /* assertPre */ 
coverage_0xed03da06(0x85e4cb4379a6b09c52d43bab89af2fce09046e240f4eedf4f6f3c4363612ae78); /* statement */ 
require(
            RollupTime.blocksToTicks(asserter.creationTimeBlocks) < deadlineTicks,
            STK1_DEADLINE
        );coverage_0xed03da06(0x4f439e2cca576e7c97d7d0c8071c69c7518c10388489e3b1ff76bb46993c2a7b); /* assertPost */ 

coverage_0xed03da06(0xe59a09b883f5e06cccbb19d792ded169dc0e441e12af65c5df091dea16656124); /* line */ 
        coverage_0xed03da06(0x1e7b1e9811ac94dc6537c30974ac9ff79b432ce40591c52c91b7da9436a496c3); /* assertPre */ 
coverage_0xed03da06(0x37438ef24daf7456ecf5b8f4441c49b925d0c87f7329db6a11853688640f27b7); /* statement */ 
require(
            RollupTime.blocksToTicks(challenger.creationTimeBlocks) < deadlineTicks,
            STK2_DEADLINE
        );coverage_0xed03da06(0xd88053e661d799e495b7f4491bc96c297a2a95d75eb11889759ae0873dfa9914); /* assertPost */ 

coverage_0xed03da06(0x01585636dd904b6cb8e12bbd9ed94d3b8951a30435a903596e91a946e097ff88); /* line */ 
        coverage_0xed03da06(0x138030998664cd6e4af6be3baf76ef0ab072aa9e8824199514a39b7e6192500e); /* assertPre */ 
coverage_0xed03da06(0x391b7d6d396e91009013863cfed465d1cdcc1d303c57e32030aa0090a9d9b5ea); /* statement */ 
require(!asserter.inChallenge, STK1_IN_CHAL);coverage_0xed03da06(0xe785b9eb50c197ce6a5afa4d82fa6a271ef1a6fd962f6087c070cbdeaa0e961b); /* assertPost */ 

coverage_0xed03da06(0x5a91bdb15725f4c2914e7f0e51bce8fab4faac4aca89cefdb0da0b562facdbec); /* line */ 
        coverage_0xed03da06(0xa4c95a719d7a5995dd8011722b28e2b3ef8e6763c24ff8eb8e8f0501a68828a6); /* assertPre */ 
coverage_0xed03da06(0x0684bb69b0db789b8d6f50136ca46ea0f72a4a39dc1b0b7be2b8e1ebc98f84de); /* statement */ 
require(!challenger.inChallenge, STK2_IN_CHAL);coverage_0xed03da06(0xc12c54dd0eb932db86da5bf4601e5573169b54510b1ee6ba84ca8a30a6593d9f); /* assertPost */ 

coverage_0xed03da06(0x977bda8be5223fef20d396ec72a51972d2558840acdce3ad0cf9e8590b2d963d); /* line */ 
        coverage_0xed03da06(0xf986f608445a7e211c2ec1cd25bccf90318d87c357fc44525ad6e7d61038ba44); /* assertPre */ 
coverage_0xed03da06(0x4bda80fdb6d2dbb1369f1cc265945a325a5b5bb3167b08ab04f5cdbb86cf6324); /* statement */ 
require(stakerNodeTypes[0] > stakerNodeTypes[1], TYPE_ORDER);coverage_0xed03da06(0x06682ac13c5c85654cc940d9b82f0129d5c1f443aaa5edf62b0bd2ddddb00db9); /* assertPost */ 

coverage_0xed03da06(0xede7ff19ff25ac76d34f97e330597cb61edb05b80747981df5fd658efb94390a); /* line */ 
        coverage_0xed03da06(0x06828a3db59b511644622f0c63d3c0db8691eb257d6bed4a044899a230ba4f25); /* assertPre */ 
coverage_0xed03da06(0x7da675799d22b468b6205a433a7740ed981550c9babcfde74031e3aae571a362); /* statement */ 
require(
            RollupUtils.calculateLeafFromPath(
                RollupUtils.childNodeHash(
                    prevNode,
                    deadlineTicks,
                    asserterNodeHash,
                    stakerNodeTypes[0],
                    vmProtoHashes[0]
                ),
                asserterProof
            ) == asserter.location,
            ASSERT_PROOF
        );coverage_0xed03da06(0xa9cf7ff7f49d1392018bc13e33779503e979fb4968d38eca7cba5f297544f6cd); /* assertPost */ 

coverage_0xed03da06(0x2d12708ef98559a47f50e3df6adffdd717f16f3cd552317d5a1b7e0c461d8901); /* line */ 
        coverage_0xed03da06(0xc9a5c2f421e76d7d46f08c749e7d2413fbbd35b3b2a88463635bd38def7fa37f); /* assertPre */ 
coverage_0xed03da06(0xc70b2caa67ae81e08b34cd83fe738c640c6b02b38bc55829e61866af18d5c74d); /* statement */ 
require(
            RollupUtils.calculateLeafFromPath(
                RollupUtils.childNodeHash(
                    prevNode,
                    deadlineTicks,
                    RollupUtils.challengeDataHash(challengerDataHash, challengerPeriodTicks),
                    stakerNodeTypes[1],
                    vmProtoHashes[1]
                ),
                challengerProof
            ) == challenger.location,
            CHAL_PROOF
        );coverage_0xed03da06(0x35c117d61865c6ed8ac1bbc7f06c5f32ea1a84c319edf4769c4a07d001e35978); /* assertPost */ 


coverage_0xed03da06(0xb252cd81987aabe0b500646270d296ae9ba074c686ba02fdea53c464eef17eed); /* line */ 
        coverage_0xed03da06(0xdc3909bd1d6e9af3d03dd93890d284b9eaf7f32b7363f7769525ae3ce72a7931); /* statement */ 
asserter.inChallenge = true;
coverage_0xed03da06(0x984f3e624d35fff3bd3bde6d4d0505b72d863be327b4787647e24359d1991d59); /* line */ 
        coverage_0xed03da06(0xd5c1c3872818ad64632fce19da93dadb3f1c65aa1eccfd57e967ec522a277d91); /* statement */ 
challenger.inChallenge = true;

coverage_0xed03da06(0x15a3be4c28885a4ad310b0fb3f938c8024c786af074f63465e3a4c3503e311de); /* line */ 
        coverage_0xed03da06(0xc99a1fe7c469a306c9a2b5eeaf288c31e9e010e03f8aaa79c5b38c87ff51b401); /* statement */ 
createChallenge(
            asserterAddress,
            challengerAddress,
            challengerPeriodTicks,
            challengerDataHash,
            stakerNodeTypes[1]
        );
    }

    function createChallenge(
        address payable asserterAddress,
        address payable challengerAddress,
        uint128 challengerPeriodTicks,
        bytes32 challengerDataHash,
        uint256 stakerNodeType
    ) internal {coverage_0xed03da06(0x665c7c35244f2a95c6c9670511343b9a4ba1ec458ff3a93dd03efeb624080619); /* function */ 

coverage_0xed03da06(0x852176584c325971e860baba83d90c11ca6cb5ffe2a0a2c7566ac6b6a1bb9d56); /* line */ 
        coverage_0xed03da06(0x1c8269e4341f5af8985ef65b548d8ae67152d1fa1b84ff4dc6d7e05fcc0a6670); /* statement */ 
address newChallengeAddr = challengeFactory.createChallenge(
            asserterAddress,
            challengerAddress,
            challengerPeriodTicks,
            challengerDataHash,
            stakerNodeType
        );

coverage_0xed03da06(0xf4200f5db202b5dbf2fdedf46bf33a214415bd30d0a18b23f8960da71bca159d); /* line */ 
        coverage_0xed03da06(0x32d627e44e15e012b34689bf7a19f3a993c9ff431d7507a5ee35618dca341cfd); /* statement */ 
challenges[newChallengeAddr] = true;

coverage_0xed03da06(0x268bff8b03e93d849e5a310c96074298af54a8383b6a8205833507264cc2d025); /* line */ 
        coverage_0xed03da06(0x4ffa82a01570b6da8184160e50d8f7eed1f5e874f721003174405b08e05c313a); /* statement */ 
emit RollupChallengeStarted(
            asserterAddress,
            challengerAddress,
            stakerNodeType,
            newChallengeAddr
        );
    }

    function init(
        uint128 _stakeRequirement,
        address _stakeToken,
        address _challengeFactoryAddress
    ) internal {coverage_0xed03da06(0xb61eb9ff2d69597f6c893b6abbaff7c9c86d7bb69030478ea63994afab50b7a0); /* function */ 

coverage_0xed03da06(0xcbf750fa8daf9bdf00ec40402cc0a858e38a318bd36aaca90c46728805fe0e1c); /* line */ 
        coverage_0xed03da06(0xa8da7a29e6f6722118aab8cc049d5132bab3e4018f230f0a17aa4a9bd1260151); /* assertPre */ 
coverage_0xed03da06(0xd9082bbcbb38cc632f496b531bf55d88365ae2b20daaa8fe78802a23fb77c8e0); /* statement */ 
require(address(challengeFactory) == address(0), INIT_TWICE);coverage_0xed03da06(0xdc0b8dd7aa98d64d079dd98c4c5defaa7d5d544cbb7e2ba1d2c0ea2f3ebaa2ff); /* assertPost */ 

coverage_0xed03da06(0xb98dc94309776483188b22b7c4f279f8a8448e354768c9270aee5f37fbdd0365); /* line */ 
        coverage_0xed03da06(0x5607e7f8c73a8206689e1f7a9e3ab1b0887373df43ae1a222095dc4bb8250e86); /* assertPre */ 
coverage_0xed03da06(0xae6df6b3b81f712c53bbe4faaa8800c29dfe278886d4c5eb1ae8f766a6cef0e2); /* statement */ 
require(_challengeFactoryAddress != address(0), INIT_NONZERO);coverage_0xed03da06(0xc304a83ecdfe4c006a9039fe693e0c97a4f86deae23ea97ba66ce348516ed80f); /* assertPost */ 


coverage_0xed03da06(0x471c4a271eefeda4870327a5b8dd0c19ce73201fda4901a9c21c99bcfd7e1057); /* line */ 
        coverage_0xed03da06(0x347908f9a1d32c90b9f094ea1fb56a4c79aad7e73cac8e48fbecf332b21a4128); /* statement */ 
challengeFactory = IChallengeFactory(_challengeFactoryAddress);

        // VM parameters
coverage_0xed03da06(0x66bbd106ddc1d994760c7cb721efe09d4597bfebf20633337047e4f8e54ddf3b); /* line */ 
        coverage_0xed03da06(0x7107b2e3af4104fd0bada31ca860ce4670bb90823909b6a673ade9ef8aa0d782); /* statement */ 
stakeRequirement = _stakeRequirement;
coverage_0xed03da06(0x0bd11024a2a64471ef345dc0184bb9605322a7f363fdb1a43782dc4b345a467e); /* line */ 
        coverage_0xed03da06(0x1e64f3074436d5af9009a76cf6bd4e5c87849a10ebad28224abd17156970710f); /* statement */ 
stakeToken = _stakeToken;
    }

    function getStakerLocation(address _stakerAddress) internal view returns (bytes32) {coverage_0xed03da06(0xa3944e8e6d76d62dc2249a69b20a07066ca47094e9b1e7ab4e78aa20ce51e92a); /* function */ 

coverage_0xed03da06(0x4c5af23a1b70d26c14eee3ae2c989ac61d2b7ac8a2d522907af450bd641552fd); /* line */ 
        coverage_0xed03da06(0x1667b1521cbdc5fcd54835d4e97c249f58e11e164a06e82e477242da2f4b741f); /* statement */ 
bytes32 location = stakers[_stakerAddress].location;
coverage_0xed03da06(0x86bb7f9bf135a15ffa7e9607b68f9122de5d3473b57783539f5fd36042aee0d1); /* line */ 
        coverage_0xed03da06(0x2c01f8b3f851671713772eb651795dd114db81ee9114602fa30be677f0cc9cd8); /* assertPre */ 
coverage_0xed03da06(0x796fca3af2fdd5e3942e1a1425898b79931f1f9322a7d79890fa99b3becb8e4f); /* statement */ 
require(location != 0x00, INV_STAKER);coverage_0xed03da06(0x3194b19c054e0ba2c579ba747fc918de6164a0aed14c5aba593495cee5e1a05d); /* assertPost */ 

coverage_0xed03da06(0x5051d27b29ac4074b389cf13665eced9d10c817f5d8302734c9e3aad6ddd8fff); /* line */ 
        coverage_0xed03da06(0x5e11986ee831944f6342b1b13764f2fd7388fd83ce94fc3d47f7f30db20ef0e8); /* statement */ 
return location;
    }

    function createStake(bytes32 location) internal {coverage_0xed03da06(0xc76ddb4bb20850ce0b8333714a13196b33012eb1967a0eb5a207e29d2c109e06); /* function */ 

coverage_0xed03da06(0x63a037d428714303563a9863433f54eb6e76b8b4d520bfc81ba6f4376bbcf02c); /* line */ 
        coverage_0xed03da06(0x0d02d1d2c5c985ea706d08e95f0db7897ac4f22271ce555515412d75c25cecc9); /* statement */ 
if (stakeToken == address(0)) {coverage_0xed03da06(0x650ed2fca96c57366eef4ca3a7bfe482b5bb1dd9fe48faf30df3074a47429b2c); /* branch */ 

coverage_0xed03da06(0x27a613151f58b5e0482764653106afc7136dfa8de8490a87902dc14889a223df); /* line */ 
            coverage_0xed03da06(0x5db80949f8aac77ccc453319466df3feafa6191cff2a62e3d97780460f85176d); /* assertPre */ 
coverage_0xed03da06(0x29f6acffb1d776336ed0ca15bc905e49da3368dd7198e5b95643214b3814d2b2); /* statement */ 
require(msg.value == stakeRequirement, STK_AMT);coverage_0xed03da06(0x35a0b8dfd5ec2340ce9f475c402917cbd73082f1fcf0841a5170ecb404671572); /* assertPost */ 

        } else {coverage_0xed03da06(0x2307c10096ce47a75d6b728864f2c5f7fba9c72f00c147faa1e29573110ce6ce); /* branch */ 

coverage_0xed03da06(0xa016cee25854db688f59f3a33e82b22ed9128b203b9c9d4dcd4a1ff17971fc1a); /* line */ 
            coverage_0xed03da06(0x0d1bbdc2e51f74da9ab17117f50fb1f2a7a39e6103a614c0b323a4bea22e54b7); /* assertPre */ 
coverage_0xed03da06(0xf4f977709d27d492f987e410360d163cb8cb027a11ab280669de5d16912b98ef); /* statement */ 
require(msg.value == 0, STK_AMT);coverage_0xed03da06(0x1a70aa4dff9a884021a33aa41628c760a0c6675cddd5d062642b6ab059a117ab); /* assertPost */ 

coverage_0xed03da06(0xff71550af9c86100b4728bd9de620ff3b84e5fd22d42cf73d4bd97431f79a144); /* line */ 
            coverage_0xed03da06(0xb67d40263e8f94d33402321577ad3b022dac68d582ac3b964bd4d729cc59c6ea); /* assertPre */ 
coverage_0xed03da06(0xe50ac4bddd9ff4e272f6872edddd570cce5195151139e72f5b16bceba930ac37); /* statement */ 
require(
                IERC20(stakeToken).transferFrom(msg.sender, address(this), stakeRequirement),
                TRANSFER_FAILED
            );coverage_0xed03da06(0xee2927aa7b78e14edf48eef40749eb7b86dba8b9309fc493a0f8e902ab0a56b8); /* assertPost */ 

        }

coverage_0xed03da06(0xd67fd40348f99e874f99e9486c0c21e57a244e1cc8b832cb425038cc314945b1); /* line */ 
        coverage_0xed03da06(0xd5ede4923f63e71656ce53747c2f02e0f1ba04612629666a0018ede4b73b02e0); /* assertPre */ 
coverage_0xed03da06(0xd887e60772c9b4ba5b9e63d8f9662a86e1d04c7d7842975384b0198e64bd548d); /* statement */ 
require(stakers[msg.sender].location == 0x00, ALRDY_STAKED);coverage_0xed03da06(0xfe4f5325e304904e995a3d57ca5cd94445a462f28bfcd7a858f60bdb318889dc); /* assertPost */ 

coverage_0xed03da06(0xf3caa492e17a8e2c3725f99a09f012509de5a692dbb9a554ce242ddf5e417deb); /* line */ 
        coverage_0xed03da06(0xf67d809cb41963586bbd9e33fe6c49ed290e214d1a53351b6e22e5d06780a9bb); /* statement */ 
stakers[msg.sender] = Staker(location, uint128(block.number), false);
coverage_0xed03da06(0x8ab9901e52090f41dc8c6201cd33d1c9c756596a7f8a3e27cf024e426b457cf0); /* line */ 
        stakerCount++;

coverage_0xed03da06(0x65914a790dac9e9d359a4cbc36242d183962ff27f2a56937bf8fcba711e56480); /* line */ 
        coverage_0xed03da06(0xb8095da277e2bf9c54f71e19728bb7e74ed19fd7a0da839df952161fef31b26a); /* statement */ 
emit RollupStakeCreated(msg.sender, location);
    }

    function updateStakerLocation(address _stakerAddress, bytes32 _location) internal {coverage_0xed03da06(0x0661978b663ac04ae82f721c3bc104400c474590db8b86a786023386cf1d0ccf); /* function */ 

coverage_0xed03da06(0x4f4e985c1f1f7cf408acd12d74e78b86886b355fca7905652b8a6f311cc517ce); /* line */ 
        coverage_0xed03da06(0x7a5a4c538dd4256366836f6bcd6fb23bd58f3f366bf2f4c56151dbd065fc9aa4); /* statement */ 
stakers[_stakerAddress].location = _location;
coverage_0xed03da06(0xb7fe40b4e8eb916d6abfd339ddc9c173e0bf22872a4b82ba7d5bcb9e6100e8aa); /* line */ 
        coverage_0xed03da06(0xbee4f9d6a938cb99cb89e0a316766482ae070cab20345a183360bc516cc40ec3); /* statement */ 
emit RollupStakeMoved(_stakerAddress, _location);
    }

    function refundStaker(address payable _stakerAddress) internal {coverage_0xed03da06(0x2c71730c01f5070408354dda2d91e540ee9ba704ef9b8fc57833a93fff1e4a49); /* function */ 

coverage_0xed03da06(0x4dc2846ed4235fccb7b135e27d73aa814874909c79fef0e76a14c9e9dce0aebe); /* line */ 
        coverage_0xed03da06(0x9ff637efcd06b15e7ffbca90c44085c07a429e3578313187551f93fc5890e203); /* statement */ 
deleteStaker(_stakerAddress);
coverage_0xed03da06(0xbcdc8b195433d935d880ccc46d8e21fd6bcae5be8efbd94495e30a55a5e38226); /* line */ 
        coverage_0xed03da06(0xcda5f06e228e42b3061acb3524b15551316f163b53af0be51140ae0b41d75499); /* statement */ 
withdrawnStakes[_stakerAddress] += stakeRequirement;

coverage_0xed03da06(0x833d974879a2e28e93d24f6e826fcb363e5fa898d3629cd7511c63fc14ba3b3f); /* line */ 
        coverage_0xed03da06(0x1eade6c03fe7acd144e8c0c7df7a07cef83c86267f0a1657bc1ea0b7201d73ae); /* statement */ 
emit RollupStakeRefunded(address(_stakerAddress));
    }

    function getValidStaker(address _stakerAddress) private view returns (Staker storage) {coverage_0xed03da06(0x35a4a23f2063aa3baf84b74f8fe7a789d4fb9ad8ff4606e44c22b8d03d0d66f3); /* function */ 

coverage_0xed03da06(0x6392c19569e7bae9a9cbaad7d144acfdc3f14fcd3e2bebbe9303c29a651fa3d5); /* line */ 
        coverage_0xed03da06(0x2daf9afe32ebf52a26ad0c41a311d3e660bc6a23857ffa36ee8423302b809da9); /* statement */ 
Staker storage staker = stakers[_stakerAddress];
coverage_0xed03da06(0x02d16884d1532859372a79b7dce68c2e27c4fb0c8c9437da2606f99052994e76); /* line */ 
        coverage_0xed03da06(0xed016550659b6e5c99afa808cdec5c20a05e76b97ce2284b7bccd48d6ac1a5a8); /* assertPre */ 
coverage_0xed03da06(0xd5538f3a8385de75fad23edb61e02363ea96ea32bf13b8c776f0102a936f08fc); /* statement */ 
require(staker.location != 0x00, INV_STAKER);coverage_0xed03da06(0xaede75c60bd440cd68a3cb071f28cb4cf1554aeeab7f973ea259e115520d418f); /* assertPost */ 

coverage_0xed03da06(0xbbf68f2cd8a328d93323db4633f47b393aaae59cd26addf12adb52899677aac8); /* line */ 
        coverage_0xed03da06(0xa15d5e5da3a88faf269051ee0376540d3cef6dd57374fd0c97a36f28f77e9d4a); /* statement */ 
return staker;
    }

    function deleteStaker(address _stakerAddress) private {coverage_0xed03da06(0x74f3688d09893d803ec018f59a20e66b4db8c545b281735e2b05c49a89d4b0e9); /* function */ 

coverage_0xed03da06(0x2295c32e80f058ce1fd9f6eab6d433198643c8dcafae9da574bccb8c9162c84e); /* line */ 
        delete stakers[_stakerAddress];
coverage_0xed03da06(0x60114cfb92b4d5e2a579882c76fee19dae1843254a753babe7be71e8e164a33a); /* line */ 
        stakerCount--;
    }

    function checkAlignedStakers(
        bytes32 node,
        uint256 deadlineTicks,
        address[] memory stakerAddresses,
        bytes32[] memory stakerProofs,
        uint256[] memory stakerProofOffsets
    ) internal view returns (uint256) {coverage_0xed03da06(0xbb1cdaca0442b3b01896cb35ed0cf43826ab8b37b7f8f10a191eb8d21ba91a8e); /* function */ 

coverage_0xed03da06(0x538d56ec33aac574b83d034da312e6d66fdb65a60d6baad28362a884f951d533); /* line */ 
        coverage_0xed03da06(0x5ff8ea6e761b612c80e5c1d20aaf5806519d957616a306db5737117a39cbb2a5); /* statement */ 
uint256 _stakerCount = stakerAddresses.length;
coverage_0xed03da06(0x5ac6014f521b5ceaa818bc1b94c38efeef1b4a5b33dcba841cc743896c8c7dff); /* line */ 
        coverage_0xed03da06(0x4839b4ebf315b7ebbd8ced55f75cf8c4cb8e54cbca4af5f001e2ad060617ae7c); /* assertPre */ 
coverage_0xed03da06(0x1a95541409eccd13720e1e27528f47f60a9d77bffc898403dd32fbc156bff8cf); /* statement */ 
require(_stakerCount == stakerCount, CHCK_COUNT);coverage_0xed03da06(0x76cba09644d076a9c2f194fe819bd871b7ca9a359844b3a34f2f605df6f5587c); /* assertPost */ 

coverage_0xed03da06(0xdb5e9a3bc243b06d6d33e88657ede516a6b981d64ce516ed93e11be659994bc8); /* line */ 
        coverage_0xed03da06(0xfb532b7bb8ddd070307dabb4ff7b931f4a54b6eae5e35a581414708e866891c1); /* assertPre */ 
coverage_0xed03da06(0x9aee34574074ba0b8eea825576f8567471e6b0371a66190f1d484c5106b2efe2); /* statement */ 
require(_stakerCount + 1 == stakerProofOffsets.length, CHCK_OFFSETS);coverage_0xed03da06(0x4edb0d0b2143ea2336ff9496564f85d272090c381ef4f752c876afb8db1ce474); /* assertPost */ 


coverage_0xed03da06(0x4207a709d32a7d8b7cbf3a63cd772c410a6f3256ca73a0955f0d47368d0cd446); /* line */ 
        coverage_0xed03da06(0x8393b197d133b1917143a5d3169665e0045e20ce3b76bc09dba84d63fe085ab5); /* statement */ 
bytes20 prevStaker = 0x00;
coverage_0xed03da06(0x375024ad6cbfe8a8ca5bbfec162d3d148de5e610d374607af21548f13ead389d); /* line */ 
        coverage_0xed03da06(0x2f419b3f6e8701e6cc71c393cdf4c2d05b64036dd65868718d5ee9e59513aeec); /* statement */ 
uint256 activeCount = 0;
coverage_0xed03da06(0xfc3f3eda71235557ecae9777417d715efb3cdbabb7a397d18bd00dd2a8b06080); /* line */ 
        coverage_0xed03da06(0x7cfc38fd8bba0c6952a4f8d2f2db985febba43ef7c7facb9210bbdb8896bc583); /* statement */ 
bool isActive = false;

coverage_0xed03da06(0x22e0e0112afa8fb8f227ec6067f39c079ad4abb7049652485b3014b0e49723a1); /* line */ 
        coverage_0xed03da06(0x74662dfbe6b6b5f8cd0b3d4700a7bfe980c267b3d321c92e4c94d9f1b9719a29); /* statement */ 
for (uint256 index = 0; index < _stakerCount; index++) {
coverage_0xed03da06(0x61882a0219cf0359b48ace3fed64dd94db7cbdae16208b4e265a5296ea812848); /* line */ 
            coverage_0xed03da06(0x3e23eb29021a60440e8505c195ddc1644d65d8862d65ae96176a5062272f7281); /* statement */ 
address currentStaker = stakerAddresses[index];

coverage_0xed03da06(0xb2f5c7772412f0ab299e3ed5f3afbb4f34ba674f71ea887974051b7695263d61); /* line */ 
            coverage_0xed03da06(0xe0ca672affec913f68f86b557928cc6dd769616aab636d2eb195054f6f2fe850); /* statement */ 
isActive = _verifyAlignedStaker(
                node,
                stakerProofs,
                deadlineTicks,
                currentStaker,
                prevStaker,
                stakerProofOffsets[index],
                stakerProofOffsets[index + 1]
            );

coverage_0xed03da06(0x95183200d78463d3b9a404cc165a2bfd6f8a6062427fab078ccb9568924d6110); /* line */ 
            coverage_0xed03da06(0x954922f5a85e7f7d49cf40c13f59b77ee4b390886d3a272c756f87f622666e9c); /* statement */ 
if (isActive) {coverage_0xed03da06(0x42ac6c84fdbaa6383886ca143033696dd13d9e1f61c8c372d8f672ccc4aa214e); /* branch */ 

coverage_0xed03da06(0xae26b466ea3b7517468a575fe75c0f427f066da1ff15c72d65bcc52ed1e7a1d0); /* line */ 
                activeCount++;
            }else { coverage_0xed03da06(0xf9e1ad10ea44b6efa676356e76cff204e87f83660a1e2b214a83e993986bd252); /* branch */ 
}

coverage_0xed03da06(0xdd7dea38c607313785c54155ca0cf48eef4e0519be2cb27303ea1e883596f643); /* line */ 
            coverage_0xed03da06(0xb9ad65ace05d9f8e97fc4caf254190a83ab15d0a2d902f3e82971e493f2f2db1); /* statement */ 
prevStaker = bytes20(currentStaker);
        }
coverage_0xed03da06(0x42c88ad1866ffb6e569f862fc611834664e04b1c551b6c9ec38f95635f180a0b); /* line */ 
        coverage_0xed03da06(0x0acbb2bfc437c72a757013088c14c190f24f9b37a8d56eaafcf69badc7d5e1ef); /* statement */ 
return activeCount;
    }

    function _verifyAlignedStaker(
        bytes32 node,
        bytes32[] memory stakerProofs,
        uint256 deadlineTicks,
        address stakerAddress,
        bytes20 prevStaker,
        uint256 proofStart,
        uint256 proofEnd
    ) private view returns (bool) {coverage_0xed03da06(0x58c99160d2eea2eecfb8a65c96c48b9a487a0fe30d867451fbdb0fd4aa9022ce); /* function */ 

coverage_0xed03da06(0xae5dcc99aae0547820dab0187216e1fed68e8d4d189fa9cada4583b1c454627b); /* line */ 
        coverage_0xed03da06(0xd51aefed06ca172b6458ba9877e7efe7ea172001c58801a31f8d43e1ba13ceb7); /* assertPre */ 
coverage_0xed03da06(0xf99bdda7f94fd89c4a4c4a8426f69f87bdbfe695726971c6bb0f8ab04dbfcfca); /* statement */ 
require(bytes20(stakerAddress) > prevStaker, CHCK_ORDER);coverage_0xed03da06(0x306e4896580225896799520c28a720acdd16b369e9c602ba35c897ee69ba6942); /* assertPost */ 

coverage_0xed03da06(0x8e56b1216e3043dd8d5866da4e28779bd0cd1e9184d0473aee0a0549383d030f); /* line */ 
        coverage_0xed03da06(0x9e1ff97584d04f16778eb619aa75d082546b3410e6887ac3b00d4b6ee5d0b843); /* statement */ 
Staker storage staker = getValidStaker(stakerAddress);
coverage_0xed03da06(0x0967d141896149ccf6b9c6b8ab82073da3d3afc4e49fc2edfebf197babf1fbd8); /* line */ 
        coverage_0xed03da06(0xcb873071276ccd18c48f5c173e2c1bb329dcf341e97e5ae7f4517514d2ae4a22); /* statement */ 
bool isActive = RollupTime.blocksToTicks(staker.creationTimeBlocks) < deadlineTicks;

coverage_0xed03da06(0x2a91c911da85b2078dd249d524daab820d090ead6447d5abd16cde10f6b36ad4); /* line */ 
        coverage_0xed03da06(0xe6940ad4c8e964ff403b1b91655cb5989e56fedc70467d4896568e5e688d4083); /* statement */ 
if (isActive) {coverage_0xed03da06(0x0f0ba21b2eecad4d692919141b276f5dcb6e59bf33cc4ddbf898c097fd00ec1d); /* branch */ 

coverage_0xed03da06(0xf55551a2fcc340c349ffde127c04759350c1e2dde81e08985071ea91c305bb0a); /* line */ 
            coverage_0xed03da06(0x8e204fb16959c1928f94a85bf6da13c0b6a10fe4a5f09e808b4e204a785a58ad); /* assertPre */ 
coverage_0xed03da06(0xa0cef8f39d05d88a202320c81297ee330b0685a5f2552429368b3f753b56707d); /* statement */ 
require(
                RollupUtils.calculateLeafFromPath(node, stakerProofs, proofStart, proofEnd) ==
                    staker.location,
                CHCK_STAKER_PROOF
            );coverage_0xed03da06(0xa178715403a77dbb97aeb32f1e32750d0fce8971fc0684ac1215f9e2cf3014c2); /* assertPost */ 

        }else { coverage_0xed03da06(0x76bde3103d82afb07209329ddd2c035d6827eb71f896b498222b6ec18f906d3e); /* branch */ 
}

coverage_0xed03da06(0xc6429b24051a42bddae0b47995a92484eaa6dce569dc9606158d2bb096398483); /* line */ 
        coverage_0xed03da06(0x477ca2e9f9837f36f95c33a692c4ef45a8d3f3ef8e82da4c63ee07743ad4b518); /* statement */ 
return isActive;
    }
}
