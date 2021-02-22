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

import "./IArbRollup.sol";
import "./NodeGraph.sol";
import "./Staking.sol";
import "../inbox/IGlobalInbox.sol";
import "../libraries/Cloneable.sol";

contract ArbRollup is IArbRollup, Cloneable, NodeGraph, Staking {
function coverage_0xe495bf77(bytes32 c__0xe495bf77) public pure {}

    // invalid path proof
    string private constant PLACE_LEAF = "PLACE_LEAF";

    // invalid leaf
    string private constant MOVE_LEAF = "MOVE_LEAF";

    // invalid path proof
    string private constant RECOV_PATH_PROOF = "RECOV_PATH_PROOF";
    // Invalid conflict proof
    string private constant RECOV_CONFLICT_PROOF = "RECOV_CONFLICT_PROOF";
    // Proof must be of nonzero length
    string private constant RECVOLD_LENGTH = "RECVOLD_LENGTH";
    // invalid leaf
    string private constant RECOV_DEADLINE_LEAF = "RECOV_DEADLINE_LEAF";
    // Node is not passed deadline
    string private constant RECOV_DEADLINE_TIME = "RECOV_DEADLINE_TIME";

    // invalid staker location proof
    string private constant MAKE_STAKER_PROOF = "MAKE_STAKER_PROOF";

    // Type is not invalid
    string private constant CONF_INV_TYPE = "CONF_INV_TYPE";
    // Node is not passed deadline
    string private constant CONF_TIME = "CONF_TIME";
    // There must be at least one staker
    string private constant CONF_HAS_STAKER = "CONF_HAS_STAKER";

    // Only callable by owner
    string private constant ONLY_OWNER = "ONLY_OWNER";

    string public constant VERSION = "0.7.2";

    address payable public owner;

    IGlobalInbox public globalInbox;

    event RollupCreated(
        bytes32 initVMHash,
        uint128 gracePeriodTicks,
        uint128 arbGasSpeedLimitPerTick,
        uint64 maxExecutionSteps,
        uint128 stakeRequirement,
        address owner,
        bytes extraConfig
    );

    event ConfirmedAssertion(bytes32[] logsAccHash);

    event ConfirmedValidAssertion(bytes32 indexed nodeHash);

    function init(
        bytes32 _vmState,
        uint128 _gracePeriodTicks,
        uint128 _arbGasSpeedLimitPerTick,
        uint64 _maxExecutionSteps,
        uint128 _stakeRequirement,
        address _stakeToken,
        address payable _owner,
        address _challengeFactoryAddress,
        address _globalInboxAddress,
        bytes calldata _extraConfig
    ) external {coverage_0xe495bf77(0x9b1888562e0c15ff909cc4a271b14343c80cec3081cf3ea9866689ed36e14dbc); /* function */ 

coverage_0xe495bf77(0x0b065c221b37658bd17a0ae5ffcccca9b0f9343f56f404f7ca0c3b0ee68c5e3c); /* line */ 
        coverage_0xe495bf77(0x2bd54ccf888ff8c60b7aea48eae7338fd0cf085b8d2117d02c9cec1d6f541e97); /* statement */ 
emit RollupCreated(
            _vmState,
            _gracePeriodTicks,
            _arbGasSpeedLimitPerTick,
            _maxExecutionSteps,
            _stakeRequirement,
            _owner,
            _extraConfig
        );

coverage_0xe495bf77(0x797344592f2755c3a037b39ab442f086af24e27d08f584149dc58645079eea9f); /* line */ 
        coverage_0xe495bf77(0x07d715e10d2b63f40ae27677d73a9fb5b35548660c6a52bb4acd0ec13935ff98); /* statement */ 
NodeGraph.init(_vmState, _gracePeriodTicks, _arbGasSpeedLimitPerTick, _maxExecutionSteps);
coverage_0xe495bf77(0x96909e0c4484e7af1d4b90843c1d5afe2aae847b03361142c0a03e55a61586c8); /* line */ 
        coverage_0xe495bf77(0x4b622e22e7ab9b79f34ffbb63f8b7cfa1a5ffdf184c859b609c3dd683edb2c88); /* statement */ 
Staking.init(_stakeRequirement, _stakeToken, _challengeFactoryAddress);
coverage_0xe495bf77(0xe0433bbab2883269be543f3176895278b5d82e8a661720a70491d82304cf302c); /* line */ 
        coverage_0xe495bf77(0xbbd735f657e3d88683d3a09533aac6df44307d77c61cb318a4f1832687843b4e); /* statement */ 
globalInbox = IGlobalInbox(_globalInboxAddress);
coverage_0xe495bf77(0xfcd46717a3960c64eeae8167a6df9ddecc2040f44870d6309f50faa08be285a7); /* line */ 
        coverage_0xe495bf77(0x1b3f4b76e80900812fcecb5784a4a269d396729c89bde56ac403f7011bcf1c5a); /* statement */ 
owner = _owner;

coverage_0xe495bf77(0x33f892aa8844d30a611ad45e5e1432eedbfbbe89fb78fec2b50f8fc5f0b8d7a4); /* line */ 
        coverage_0xe495bf77(0xcee3116c4031d0009bf93fc97ad1ea798b66f5d26ed619280fe26339559a1acf); /* statement */ 
globalInbox.sendInitializationMessage(
            abi.encodePacked(
                uint256(_gracePeriodTicks),
                uint256(_arbGasSpeedLimitPerTick),
                uint256(_maxExecutionSteps),
                uint256(_stakeRequirement),
                bytes32(bytes20(_stakeToken)),
                bytes32(bytes20(_owner)),
                _extraConfig
            )
        );
    }

    /**
     * @notice Place a stake on an existing node at or after the latest confirmed node
     * @param proof1 Node graph proof that the stake location is a decendent of latest confirmed
     * @param proof2 Node graph proof that the stake location is an ancestor of a current leaf
     */
    function placeStake(bytes32[] calldata proof1, bytes32[] calldata proof2) external payable {coverage_0xe495bf77(0x248674c7942f31c1386a5fbbbad4f5e8c06cc178c6985f1d750ad40f9e426d85); /* function */ 

coverage_0xe495bf77(0xb987bb7c10d15636c7d8bfaf4a35c51afc48bdb4a32a3255fe5fe6eb66bab472); /* line */ 
        coverage_0xe495bf77(0xb1e2981f3e8a629b039b99a72d753e24d8bfdb7d95be7966f01320e31fff7531); /* statement */ 
bytes32 location = RollupUtils.calculateLeafFromPath(latestConfirmed(), proof1);
coverage_0xe495bf77(0x27ad703817a3a95dc45ab2b62b42d0bdef2a99f95ef8c1d9ff6eae4738f68764); /* line */ 
        coverage_0xe495bf77(0x4ae5ae44629dcbd08ae2e0cbb3a79bc7355e3174d686230efe7641938fe6b412); /* statement */ 
bytes32 leaf = RollupUtils.calculateLeafFromPath(location, proof2);
coverage_0xe495bf77(0x8358c0e032a50655389b4501eab6f6bd4929b66614733baf62c2d637786aad21); /* line */ 
        coverage_0xe495bf77(0x57b03eaf749c744bef7dc2625d12dc7c690aadefc2376b7d90c1c03cdadc151e); /* assertPre */ 
coverage_0xe495bf77(0x0a33dbc4a79093bf17a80de1bc0b304193f189247e9feeaf7163ec6caa44f454); /* statement */ 
require(isValidLeaf(leaf), PLACE_LEAF);coverage_0xe495bf77(0x16f04599ee89675673eab5d2fefc0a4a993a83444d1e9270b267bf2e66099890); /* assertPost */ 

coverage_0xe495bf77(0xfbd469966bd3ed757bada30758bc5f0cb406cf49ff8f5e63584028ea75445757); /* line */ 
        coverage_0xe495bf77(0xa0ff22663a4227ecf2d747ab9df5ce89136debc9a50ac04b5d927a52d3ef4839); /* statement */ 
createStake(location);
    }

    /**
     * @notice Move an existing stake to an existing leaf that is a decendent of the node the stake exists on
     * @param proof1 Node graph proof that the destination location is a decendent of the current location
     * @param proof2 Node graph proof that the stake location is an ancestor of a current leaf
     */
    function moveStake(bytes32[] calldata proof1, bytes32[] calldata proof2) external {coverage_0xe495bf77(0xeb073d8619981c8e806cd2fb2b865f7eab5ab6b3e02860b11ba8f2afd36c6d74); /* function */ 

coverage_0xe495bf77(0xb786863733881d4d899cba43ab22d013e0342012df8887a9672d83709732b43b); /* line */ 
        coverage_0xe495bf77(0x6844e768f3761dff204859ef8fcfe492646afda5e3faf1f609a494e92a2dd774); /* statement */ 
bytes32 stakerLocation = getStakerLocation(msg.sender);
coverage_0xe495bf77(0x7e9a7455e8f10d56b0cfb8591f3b43b5e000d4d65a3189bc271b53ae02d77c2f); /* line */ 
        coverage_0xe495bf77(0x87553871393a1959dc34e7ff5a98562fc2cdf1c78624cb631bcbf52be9e4260d); /* statement */ 
bytes32 newLocation = RollupUtils.calculateLeafFromPath(stakerLocation, proof1);
coverage_0xe495bf77(0x0d4e815a046f0c7f0d55b62d77e6f13f2a6df2148bb860ff46063f24fbd85a86); /* line */ 
        coverage_0xe495bf77(0xf8b6f937b919191da46709b15b6ef1ddfccb1471998f64f7a97e7dfe8957e36f); /* statement */ 
bytes32 leaf = RollupUtils.calculateLeafFromPath(newLocation, proof2);
coverage_0xe495bf77(0x47c87d9153171312963f94831f5f61b7a4b35fecf1e26573e1b975cd07aa8082); /* line */ 
        coverage_0xe495bf77(0x080f09be5537b29f5dfb223e8a77d1144168bd86a0c8fb7fca0442d8a8b4a507); /* assertPre */ 
coverage_0xe495bf77(0xfc4154127c8c9ddf969a6556a6fe7dd98c50b9236cb4b7f449a31c92ee7cccdc); /* statement */ 
require(isValidLeaf(leaf), MOVE_LEAF);coverage_0xe495bf77(0xe4184504224a86c3b328f4f803423d5e897f3aafd40cd826ce9de0bf80acba95); /* assertPost */ 

coverage_0xe495bf77(0x9780fee777a080a4fb6141f119716856e0a09331260b0b3f1fea87a3f41e7979); /* line */ 
        coverage_0xe495bf77(0x96c0b73a7d8aacc763b615391af9ff74ebc5ad1812b6f6dc3a12428ae178f9bf); /* statement */ 
updateStakerLocation(msg.sender, newLocation);
    }

    /**
     * @notice Redeem your stake if it is on or before the current latest confirmed node
     * @param proof Node graph proof your stake is on or before the latest confirmed node
     */
    function recoverStakeConfirmed(bytes32[] calldata proof) external {coverage_0xe495bf77(0xe3fd17075661cdf9bf8ba61092f2c632fe889a33ca12524099deae9cc081e44f); /* function */ 

coverage_0xe495bf77(0xea9ab2e0906a1c06a292c627ec68e12e00fe7fa396d1d5b2787374ba35cbd2ce); /* line */ 
        coverage_0xe495bf77(0x1be3a172ba6b231201e3f2639f8042c78dfdc41085f41656ee66b98a3e503d10); /* statement */ 
_recoverStakeConfirmed(msg.sender, proof);
    }

    /**
     * @notice Force a stake to be redeemed if it is before the current latest confirmed node
     * @param stakerAddress Address of the staker whose stake will be removed
     * @param proof Node graph proof your stake is before the latest confirmed node
     */
    function recoverStakeOld(address payable stakerAddress, bytes32[] calldata proof) external {coverage_0xe495bf77(0x393cb823d99d47a2e7fe3877273816f6f95b1b0faad3cff86cc2b67a93b97b12); /* function */ 

coverage_0xe495bf77(0xc824853ee21cc30d1d960b64107c325802dacb201513e0983b22391f6a3a162f); /* line */ 
        coverage_0xe495bf77(0x1faef500445777354f895b5bf9736233b1e7f731a8fc0047e6d5f5dfe7c4d236); /* assertPre */ 
coverage_0xe495bf77(0xdada95af7d516ed1befcec1a23277bd4c7449bb37581c59962da0e4ea251836d); /* statement */ 
require(proof.length > 0, RECVOLD_LENGTH);coverage_0xe495bf77(0xb1cf82e7d7489832a31db6398f933cf1060e68a3ca56ad25d3946c8018dc6412); /* assertPost */ 

coverage_0xe495bf77(0xd0ba2b145782667503890c215267531fefe22429b7ad74ddc55dd1352b90f722); /* line */ 
        coverage_0xe495bf77(0xb4803584ddecb28942dd582065a35d830902c1005ae70594340f6bfe1011d3bb); /* statement */ 
_recoverStakeConfirmed(stakerAddress, proof);
    }

    /**
     * @notice Force a stake to be redeemed if it is place on a node which can never be confirmed
     * @dev This method works by showing that the staker's position conflicts with the latest confirmed node
     * @param stakerAddress Address of the staker whose stake will be removed
     * @param node Identifier of a node which is a common ancestor of the latest confirmed node and the staker's location
     * @param latestConfirmedProof Node graph proof that the latest confirmed node is a decendent of the supplied node
     * @param stakerProof Node graph proof that the staker's node is a decendent of the supplied node
     */
    function recoverStakeMooted(
        address payable stakerAddress,
        bytes32 node,
        bytes32[] calldata latestConfirmedProof,
        bytes32[] calldata stakerProof
    ) external {coverage_0xe495bf77(0xc819383f621ea08eee0981c984bd750572be8856a0061a0b9d9d78805e82b94e); /* function */ 

coverage_0xe495bf77(0xac143098a0a19287d095d40c38f54c9771d26c146a31500e9196c6248c252619); /* line */ 
        coverage_0xe495bf77(0x5c525f9953205ee99cc01c2e9ffeec73e2a64f6d53cf9f3cc9ecbc6e6381be74); /* statement */ 
bytes32 stakerLocation = getStakerLocation(stakerAddress);
coverage_0xe495bf77(0x1b540b6c41faa527e1488fdac2f421d2b2d41dd5cd3bf4ee500fe1a2bf25c262); /* line */ 
        coverage_0xe495bf77(0x0a93bc5131e78b2f74652eb24a30bbd29996c548b7e278e71c606ef539c5297a); /* assertPre */ 
coverage_0xe495bf77(0x2a6e5d8a24fb58e35446ae75f94499b4c5492919918aab1fed7cbc828453d8a7); /* statement */ 
require(
            latestConfirmedProof[0] != stakerProof[0] &&
                RollupUtils.calculateLeafFromPath(node, latestConfirmedProof) ==
                latestConfirmed() &&
                RollupUtils.calculateLeafFromPath(node, stakerProof) == stakerLocation,
            RECOV_CONFLICT_PROOF
        );coverage_0xe495bf77(0x422c39b7012ba3f4b6bd80866b3ee39eddac3b8ec432d960e73fb0ac8c091ebd); /* assertPost */ 

coverage_0xe495bf77(0xae258aea5e81a90aa181f749416e7233addd34a4669482863426994362f4ce04); /* line */ 
        coverage_0xe495bf77(0xb3c013885e3977b42ad77ef5d6820d0559a0ffc99549131c227335d2c891f55c); /* statement */ 
refundStaker(stakerAddress);
    }

    // Kick off if successor node whose deadline has passed
    // TODO: Add full documentation
    function recoverStakePassedDeadline(
        address payable stakerAddress,
        uint256 deadlineTicks,
        bytes32 disputableNodeHashVal,
        uint256 childType,
        bytes32 vmProtoStateHash,
        bytes32[] calldata proof
    ) external {coverage_0xe495bf77(0x5b68b16fabf226dd471dadae02df3913d121311071beb9fec3efe022f57b931f); /* function */ 

coverage_0xe495bf77(0xa3340267e5e61cb856cac489f695b183a53e5d6bd9ddb435fc2b1e638742f4d1); /* line */ 
        coverage_0xe495bf77(0xe69249788faa9f480fc08416135abbb02fb2713dc54b07696edf6c67afdd4b65); /* statement */ 
bytes32 stakerLocation = getStakerLocation(stakerAddress);
coverage_0xe495bf77(0x12692e0f98b7cfee8f74a78e02f874d059e5cbc0c02826f5a72088632f7da066); /* line */ 
        coverage_0xe495bf77(0x7608c0f414ee0ed8755606bd411ca7bbfbd30cb38f3de7d9213ec40ae9fe9ff0); /* statement */ 
bytes32 nextNode = RollupUtils.childNodeHash(
            stakerLocation,
            deadlineTicks,
            disputableNodeHashVal,
            childType,
            vmProtoStateHash
        );
coverage_0xe495bf77(0x0901b3ffba5e2df9a904111d9652337ba2ce3b21d00079f333cced3430640d71); /* line */ 
        coverage_0xe495bf77(0x60f5957dcac22e92322fa03046cf1dcd4142414b379988d48cb503eb583b1e90); /* statement */ 
bytes32 leaf = RollupUtils.calculateLeafFromPath(nextNode, proof);
coverage_0xe495bf77(0x12c29bfe757e6c300995c59ff8d467b499ddfeec4758e84420815e7ea7869b60); /* line */ 
        coverage_0xe495bf77(0x284afe1a06a29c4231847ab46107a6937156bb70ac7b703ad99d21c22db85bee); /* assertPre */ 
coverage_0xe495bf77(0x52a01f24e9c8e377136987712c3f6e55072c35b2f72c279fd30a6d5871474246); /* statement */ 
require(isValidLeaf(leaf), RECOV_DEADLINE_LEAF);coverage_0xe495bf77(0x931c87a035f38ecc8f552843c6ec3ea402e613a63cd2ad3121ad7c5343bbbe44); /* assertPost */ 

coverage_0xe495bf77(0x11a51d3c5668c2aa8778aba1435ca4583eba459a3617de03742813ce8d13a0c7); /* line */ 
        coverage_0xe495bf77(0xfdbaa5d4d743864598f47efc5c0fea4038a6d01000a64ad5940b8ab2e017c3da); /* assertPre */ 
coverage_0xe495bf77(0x28a0db09f99f00f4f700038429fc864aa54394f3d1a7abab05972feb499b6ba0); /* statement */ 
require(block.number >= RollupTime.blocksToTicks(deadlineTicks), RECOV_DEADLINE_TIME);coverage_0xe495bf77(0x5e7731837cc39598c25d733164169f801fd80045a480d086caeeeb4ef4128dce); /* assertPost */ 


coverage_0xe495bf77(0x6753c4283959bf783e097e77a3cf3e3d3f99a652114dbed29e656ac997271a6c); /* line */ 
        coverage_0xe495bf77(0xfc3865b9f01183606b363e385a9e3e71be350d4c254f5da4a376bd658a87e9df); /* statement */ 
refundStaker(stakerAddress);
    }

    /**
     * @notice Submit a new assertion to be built on top of the specified leaf if it is validly constructed
     * @dev This method selects an existing leaf to build an assertion on top of. If it succeeds that leaf is eliminated and four new leaves are created. The asserter is automatically moved to stake on the new valid leaf.
     * @param fields Packed data for the following fields
     *   beforeMachineHash The hash of the machine at the end of the previous assertion
     *   afterMachineHash Claimed machine hash after this assertion is completed
     *   beforeInboxTop The hash of the global inbox that the previous assertion had read up to
     *   afterInboxTop Claimed hash of the global inbox at height beforeInboxCount + importedMessageCount
     *   messagesAccHash Claimed commitment to a set of messages output in the assertion
     *   logsAccHash Claimed commitment to a set of logs output in the assertion
     *   prevPrevLeafHash The hash of the leaf that was the ancestor of the leaf we're building on
     *   prevDataHash Type specific data of the node we're on

     * @param fields2 Packed data for the following fields
     *   beforeInboxCount The total number of messages read after the previous assertion executed
     *   prevDeadlineTicks The challenge deadline of the node this assertion builds on
     *   importedMessageCount Argument specifying the number of messages read
     *   beforeMessageCount The total number of messages that have been output by the chain before this assertion
     *   beforeLogCount The total number of messages that have been output by the chain before this assertion
     * @param validBlockHashPrecondition Hash of a known block to invalidate the assertion if too deep a reorg occurs
     * @param validBlockHeightPrecondition Height of the block with hash validBlockHash
     * @param messageCount Claimed number of messages emitted in the assertion
     * @param logCount Claimed number of logs emitted in the assertion
     * @param prevChildType The type of node that this assertion builds on top of
     * @param numSteps Argument specifying the number of steps execuited
     * @param numArbGas Claimed amount of ArbGas used in the assertion
     * @param stakerProof Node graph proof that the asserter is on or can move to the leaf this assertion builds on
     */
    function makeAssertion(
        bytes32[8] calldata fields,
        uint256[5] calldata fields2,
        bytes32 validBlockHashPrecondition,
        uint256 validBlockHeightPrecondition,
        uint64 messageCount,
        uint64 logCount,
        uint32 prevChildType,
        uint64 numSteps,
        uint64 numArbGas,
        bytes32[] calldata stakerProof
    ) external {coverage_0xe495bf77(0x6695ae39c8ea8876d1aaf59c22dd08506595e38895d77dcd595b09d14ae627f7); /* function */ 

coverage_0xe495bf77(0x9c750cef9a5a1eeb24f8a50af8c26ed16a107b4309da83ab1e44a80e90705dca); /* line */ 
        coverage_0xe495bf77(0xa371a55ed00d100cba911a7a3069e45004d02cc4c412820b34cb9f8bf5406e1f); /* assertPre */ 
coverage_0xe495bf77(0xa3948926a3731b3207d04db9c78e7c238c42de8d10a3a61e2ed831fa6f359448); /* statement */ 
require(
            blockhash(validBlockHeightPrecondition) == validBlockHashPrecondition,
            "invalid known block"
        );coverage_0xe495bf77(0x75ffd7c8c2e68e30879aacecf9d96782a37fedbf02fe868ed1d8270dee20fc62); /* assertPost */ 

coverage_0xe495bf77(0x9c958b697496b04c16f8f43815971e42e0cc658260650ac644df68bec5809d24); /* line */ 
        coverage_0xe495bf77(0x7c595c8721d18828bc6b7d0de3f7fd58e94746c85836b642eca4781800fa4599); /* statement */ 
NodeGraphUtils.AssertionData memory assertData = NodeGraphUtils.makeAssertion(
            fields,
            fields2,
            prevChildType,
            numSteps,
            numArbGas,
            messageCount,
            logCount
        );

coverage_0xe495bf77(0x4c538511f2c0723b9029cda4a772a5f9c8b6514d1dae22bbb8b2dfbdc448093e); /* line */ 
        coverage_0xe495bf77(0x63fba200ea8c73932f9f42a66feb25fae5c0f77292ed4899d282653b884db7c4); /* statement */ 
(bytes32 inboxValue, uint256 inboxCount) = globalInbox.getInbox(address(this));

coverage_0xe495bf77(0xf533d2772e63885749cedbbe4a5ae0e334b724b37e06ddd7f2258db7eb87ad9f); /* line */ 
        coverage_0xe495bf77(0xf3d73fbb18f2bbabb93dfd330f12b8edc331355f79b8dfd2cf19b706c10a048c); /* statement */ 
(bytes32 prevLeaf, bytes32 newValid) = makeAssertion(assertData, inboxValue, inboxCount);

coverage_0xe495bf77(0x2ed2c3c4f5975f8cd5697de81425dcdae2013e0a5bbcc0b223a79d719ee1f5ed); /* line */ 
        coverage_0xe495bf77(0xe73ca04e8b9978e7c1ac074995fda64bbeea1c543f74ad41c56c0c674facbca9); /* statement */ 
bytes32 stakerLocation = getStakerLocation(msg.sender);
coverage_0xe495bf77(0xf1239df4313595b34febe7f195ade128aba797aae5eb9280f094ad062bd539ec); /* line */ 
        coverage_0xe495bf77(0x88a7e9210b1c11ccd5aaaf934cab2de2283f0ae37f7f54df0bd2972b4eff39c9); /* assertPre */ 
coverage_0xe495bf77(0x5db78c0705eaa5da6d8e487851b7ff82c4d89c61ad28d654e96407cb878848b2); /* statement */ 
require(
            RollupUtils.calculateLeafFromPath(stakerLocation, stakerProof) == prevLeaf,
            MAKE_STAKER_PROOF
        );coverage_0xe495bf77(0xa18bd817c2ff3ebd9d59fae452d9040e63dca70a09fd5432a458f86bfde6cc66); /* assertPost */ 

coverage_0xe495bf77(0x9eaea70552bd1906cdd1a01d522114d1eeff68dd376844cacbc17a1d4fdf486c); /* line */ 
        coverage_0xe495bf77(0xfd9b18ba13fb3714d3acda2614c91827c9bee8d4854cdb873fb45c6b1e6f20f0); /* statement */ 
updateStakerLocation(msg.sender, newValid);
    }

    modifier onlyOwner() {coverage_0xe495bf77(0xe2615b1f811e677849e1044680cc811ba37969306a169c0099dc0075df55b7d1); /* function */ 

coverage_0xe495bf77(0x8efd25e100471e745675ee51ba814fbfda582ec8807519b6e81e3672d1a0bc1b); /* line */ 
        coverage_0xe495bf77(0x7ed6976b86bd6576ecff78f6b8399650da0c1173d686fc40a1904cf55165ce30); /* assertPre */ 
coverage_0xe495bf77(0x2e09b186b75c0cae0f2732b9e0cb3cbcd5708895824222d0a5330538eaad8391); /* statement */ 
require(msg.sender == owner, ONLY_OWNER);coverage_0xe495bf77(0x0802580efe92cebe811e0dfa9eb67acc2cfe43c614d268848efda138bf9c8d78); /* assertPost */ 

coverage_0xe495bf77(0xa0cc697dad893237ccda9d9677de521d5258bd755993810c39ffea14b01b3756); /* line */ 
        _;
    }

    function ownerShutdown() external onlyOwner {coverage_0xe495bf77(0x0c843d284738be5d83377cdc66205f09cdf7be5da1febf970c506b4b4af4a9f0); /* function */ 

coverage_0xe495bf77(0xcfcace67cb5c1282a6b11974db2e3100d2e689872ab96ce6ac2ffaae5aaa0b69); /* line */ 
        coverage_0xe495bf77(0x2add06608e7e679d2e5dc837144255e0a3c562377b1dc34793cab8f412084e08); /* statement */ 
safeSelfDestruct(msg.sender);
    }

    function _recoverStakeConfirmed(address payable stakerAddress, bytes32[] memory proof) private {coverage_0xe495bf77(0xc083cf9550f90ca029c0fa477aee2836f618babd928afeb365cae448fcc6e250); /* function */ 

coverage_0xe495bf77(0x2bff6245c1abd69bdc3a53d3a8fd31016a3cc17ad379132e017a87f84777e0d1); /* line */ 
        coverage_0xe495bf77(0xc0b29b4636c169505f5e8645bccb637b19143d0f0cc2248d2b047bdf5d15c74e); /* statement */ 
bytes32 stakerLocation = getStakerLocation(msg.sender);
coverage_0xe495bf77(0x7e8f75f8368afa6837468f25733bdafbe546f374533b58cc72a0d5257690be82); /* line */ 
        coverage_0xe495bf77(0xf5f2563254e7dd22ed81131559cfc617e62684c750a7b892641815f90a76e930); /* assertPre */ 
coverage_0xe495bf77(0x9f08682544cff550aaa4c1f46e89a10351f948425c3402397fc6d5a6a18c56c0); /* statement */ 
require(
            RollupUtils.calculateLeafFromPath(stakerLocation, proof) == latestConfirmed(),
            RECOV_PATH_PROOF
        );coverage_0xe495bf77(0x6d2941259d7a05695c8c608409f342ec4d9dc56bb1a0361428ee5369d4944e50); /* assertPost */ 

coverage_0xe495bf77(0x77641c1b702c395173e7248c9f29b7b78e74aab76752aa4f792650d4ff1f56c0); /* line */ 
        coverage_0xe495bf77(0x5dc6ef97b5e905b0701faa52e7af68e535b32a1d160ee449cd14fe7dea9163c7); /* statement */ 
refundStaker(stakerAddress);
    }

    /**
     * @notice Confirm an arbitrary number of pending assertions
     * @dev Confirming multiple assertions at once has the advantage that we can skip most checks for all nodes but the final one
     * @dev TODO: An adversary could potentially make this method too expensive to call by creating a large number of validators. This issue could be avoided by providing an interactive confirmation challenge along with this synchronous one.\
     * @param initalProtoStateHash Hash of the protocol state of the predecessor to the first node confirmed
     * @param branches For each node being confirmed, this is the type of node it was
     * @param deadlineTicks For each node being confirmed, this is the deadline for validators challenging it
     * @param challengeNodeData For the invalid nodes being confirmed, this is the hash of the challenge specific data in that node
     * @param logsAcc For the valid nodes being confirmed, this is the claim about what logs were emitted
     * @param vmProtoStateHashes For the valid nodes being confirmed, this is the state after that node is confirmed
     * @param messageCounts The number of messages in each valid assertion confirmed
     * @param messages All the messages output by the confirmed assertions marshaled in order from oldest to newest
     * @param stakerAddresses The list of all currently staked validators
     * @param stakerProofs A concatenated list of proofs for each validator showing that they agree with the given node
     * @param stakerProofOffsets A list of indexes into stakerProofs to break it into pieces for each validator
     */
    function confirm(
        bytes32 initalProtoStateHash,
        uint256 beforeSendCount,
        uint256[] memory branches,
        uint256[] memory deadlineTicks,
        bytes32[] memory challengeNodeData,
        bytes32[] memory logsAcc,
        bytes32[] memory vmProtoStateHashes,
        uint256[] memory messageCounts,
        bytes memory messages,
        address[] memory stakerAddresses,
        bytes32[] memory stakerProofs,
        uint256[] memory stakerProofOffsets
    ) public {coverage_0xe495bf77(0x0bb9ccd3600b4f4a1a3972a57141dd4e26b1954d78acb4edba1ac3043d04b566); /* function */ 

coverage_0xe495bf77(0xfa6e51e0c85e87c442e95e399b08a483e726a766065dfb9f9952311f31de6630); /* line */ 
        coverage_0xe495bf77(0xf0ff4bd41fca84f88e0f1e6b1d7fe7e9db52f3f60edc66c086123a113f8b6593); /* statement */ 
return
            _confirm(
                RollupUtils.ConfirmData(
                    initalProtoStateHash,
                    beforeSendCount,
                    branches,
                    deadlineTicks,
                    challengeNodeData,
                    logsAcc,
                    vmProtoStateHashes,
                    messageCounts,
                    messages
                ),
                stakerAddresses,
                stakerProofs,
                stakerProofOffsets
            );
    }

    function _confirm(
        RollupUtils.ConfirmData memory data,
        address[] memory stakerAddresses,
        bytes32[] memory stakerProofs,
        uint256[] memory stakerProofOffsets
    ) private {coverage_0xe495bf77(0x0e1875b280660e869ab501885c055b4c5443cb79dd483e3df91e9471f960be9b); /* function */ 

coverage_0xe495bf77(0x0fbcab400c834981d6b6687b90aa51e3f84cd82d01a44276c305faf2bf49e690); /* line */ 
        coverage_0xe495bf77(0x8b57ae1c252c1a46a7b77a6e0fb40bdd1d3f067099a4d50a0a65c231f2b7be34); /* statement */ 
uint256 totalNodeCount = data.branches.length;
        // If last node is after deadline, then all nodes are
coverage_0xe495bf77(0x878a5c4722c4a40c3767e9c2d43ea664254fdaf652e2e0ebb86cd8eff18afcd8); /* line */ 
        coverage_0xe495bf77(0x991281a7898fc265883b02fbed9c9a6d30978e5c1014da68916d4084906ea6db); /* assertPre */ 
coverage_0xe495bf77(0x1d9e1f0050f2f37b9921cb975cf7270fec095ad5cd9d3f969736bd26ed558aee); /* statement */ 
require(
            RollupTime.blocksToTicks(block.number) >= data.deadlineTicks[totalNodeCount - 1],
            CONF_TIME
        );coverage_0xe495bf77(0x387d381333ed52ba80360c94612ae3728a7c765ec47aed1e37e0f0cba4c072bf); /* assertPost */ 


coverage_0xe495bf77(0xcdf0ca2b9ef99913f31cd66fd0b6ee3bf43003623d7dfa388c946eae68324898); /* line */ 
        coverage_0xe495bf77(0x0771bbfc6e3956eb460bad77c0b9f1d194639858732c49b0ba28d5e061f49b87); /* statement */ 
(bytes32[] memory validNodeHashes, RollupUtils.NodeData memory finalNodeData) = RollupUtils
            .confirm(data, latestConfirmed());

coverage_0xe495bf77(0xe886d88e3421053e751a14d239fff0cd816fde36446f926774a9437403cd32f5); /* line */ 
        coverage_0xe495bf77(0xbc2d4cf24c361e6fd521171393d79bc12d923091f974038ac56a5896b0fe0d6f); /* statement */ 
uint256 validNodeCount = validNodeHashes.length;
coverage_0xe495bf77(0x54233c6e7778f0ae61b4793881edb7fc4a0c6515fcc10e298380f585225671a1); /* line */ 
        coverage_0xe495bf77(0xc3ef24b584ebe1d21dfff4c85cba8bca018768ed9b0916668d1e8d371476f539); /* statement */ 
for (uint256 i = 0; i < validNodeCount; i++) {
coverage_0xe495bf77(0x81116d64782eaf15a55df39e5fe955a1f5cfb85992cb1daa40fe1e5cebf13930); /* line */ 
            coverage_0xe495bf77(0xe072d2bd9ab6ef6dd5fa6be0f6902beff23c7ee133c2f5f14979f923edf84981); /* statement */ 
emit ConfirmedValidAssertion(validNodeHashes[i]);
        }
coverage_0xe495bf77(0xe1d85b2ba4c7207860215ed08e016f0d3ccd3186df0cdd8bd1647242e5e8e5e9); /* line */ 
        coverage_0xe495bf77(0xe6c846a47fc36f507526fbc65c04aff77880cf166d37674d7f6f685caef4071f); /* statement */ 
uint256 activeCount = checkAlignedStakers(
            finalNodeData.nodeHash,
            data.deadlineTicks[totalNodeCount - 1],
            stakerAddresses,
            stakerProofs,
            stakerProofOffsets
        );
coverage_0xe495bf77(0x3cfd7cb70d8e50f0b5a9ce5f679f5fbb19316f236129cff811e612edb7017d0e); /* line */ 
        coverage_0xe495bf77(0x86c56a33e00e63e20a1be9cbee5b9aeabf42f37dba71affe089dde9ea5c991c0); /* assertPre */ 
coverage_0xe495bf77(0xa88dbf8090c800e5ea9c325c38140548f211dbefaafabd4e6bbe639aba5f7a84); /* statement */ 
require(activeCount > 0, CONF_HAS_STAKER);coverage_0xe495bf77(0xb3707e51d1e803d204655d32624547bdbd75d26c6133173c86c15aa88829a2b0); /* assertPost */ 


coverage_0xe495bf77(0xe7cea2634f052a8e8780f266792a40a3feebd999243c4644e8a4c2c25559ad17); /* line */ 
        coverage_0xe495bf77(0xe822c34fe3f0a398a839b1e9ec669e00f73c81f8ed018e7632ae594ded0b3e9c); /* statement */ 
confirmNode(finalNodeData.nodeHash);

        // Send all messages is a single batch
coverage_0xe495bf77(0x7f5203550172a7440b9d7d55a308cba3fa1576aba6482058cb09c2deeac1a55b); /* line */ 
        coverage_0xe495bf77(0x6ef11f1c7af947256ce3b3a5c9f8f5d99a75607649ec8cdac2d2405296d305fc); /* statement */ 
globalInbox.sendMessages(
            data.messages,
            data.initialSendCount,
            finalNodeData.beforeSendCount
        );

coverage_0xe495bf77(0x78f4ed20945fbc5284e202104c791a803a69813df2d83ac34a2749f4e8e2d182); /* line */ 
        coverage_0xe495bf77(0x9c65a7f9ae76af111343f10d06ce2c205c636479c33c172aa3afd44d81da08d0); /* statement */ 
if (validNodeCount > 0) {coverage_0xe495bf77(0x2bd5653ffb2d94f5cd94cef04dcb51fc78ed0992e59e367a487e2e5b2863e915); /* branch */ 

coverage_0xe495bf77(0x110b8ad7a7166cfa1dc7edf1ed1e90e5ef82fa42fa7d2d9ab4217be399f654b4); /* line */ 
            coverage_0xe495bf77(0xbef564819eea00544a83d6f7e73abb6e23081ee6050f663d467c54508737da9b); /* statement */ 
emit ConfirmedAssertion(data.logsAcc);
        }else { coverage_0xe495bf77(0x3e401e1b2d7767985d7faa25012e09d467215ede47c469ff4bd91b4bf6606e85); /* branch */ 
}
    }
}
