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
import "./NodeGraphUtils.sol";
import "./VM.sol";

import "../arch/Value.sol";

import "../libraries/RollupTime.sol";

contract NodeGraph {
function coverage_0xb698eaca(bytes32 c__0xb698eaca) public pure {}

    using SafeMath for uint256;
    using Hashing for Value.Data;

    // invalid leaf
    string private constant MAKE_LEAF = "MAKE_LEAF";
    // Can only disputable assert if machine is not errored or halted
    string private constant MAKE_RUN = "MAKE_RUN";
    // Tried to execute too many steps
    string private constant MAKE_STEP = "MAKE_STEP";
    // Tried to import more messages than exist in ethe inbox
    string private constant MAKE_MESSAGE_CNT = "MAKE_MESSAGE_CNT";

    string private constant PRUNE_LEAF = "PRUNE_LEAF";
    string private constant PRUNE_PROOFLEN = "PRUNE_PROOFLEN";
    string private constant PRUNE_CONFLICT = "PRUNE_CONFLICT";

    // Fields
    //  prevLeaf
    //  inboxValue
    //  afterMachineHash
    //  afterInboxHash
    //  messagesAccHash
    //  logsAccHash
    //  validNodeHash

    event RollupAsserted(
        bytes32[7] fields,
        uint256 inboxCount,
        uint256 importedMessageCount,
        uint64 numArbGas,
        uint64 numSteps,
        uint256 beforeMessageCount,
        uint64 messageCount,
        uint256 beforeLogCount,
        uint64 logCount
    );

    event RollupConfirmed(bytes32 nodeHash);

    event RollupPruned(bytes32 leaf);

    VM.Params public vmParams;
    mapping(bytes32 => bool) private leaves;
    bytes32 private latestConfirmedPriv;

    /**
     * @notice Prune an arbitrary number of leaves from the node graph
     * @dev Pruning leaves frees up blockchain storage, but is otherwise unnecessary
     * @notice See _pruneLeaf for parameter documentation
     */
    function pruneLeaves(
        bytes32[] calldata fromNodes,
        bytes32[] calldata leafProofs,
        uint256[] calldata leafProofLengths,
        bytes32[] calldata latestConfProofs,
        uint256[] calldata latestConfirmedProofLengths
    ) external {coverage_0xb698eaca(0xff5612a088b92b31f7cf9a50b7f2965c859550ddef06c8a6c9518d62e8c23130); /* function */ 

coverage_0xb698eaca(0x46053dbf79eacd25860fb106a0ce23044a5ce66cafd445d378a0622d4cddc9d0); /* line */ 
        coverage_0xb698eaca(0xb933ad2ad4872d696ea427deefb94c6273cef320bf2746dad114b3047bde268a); /* statement */ 
uint256 pruneCount = fromNodes.length;

coverage_0xb698eaca(0x9be385ba40957a072079dcc2bf9478f587e8f26cc6e16b071bec9e5328c3e00d); /* line */ 
        coverage_0xb698eaca(0x873ccc695f2ce4b2df63d0ae2186350e6cf19b47181c37fb9dc1f818fcce7528); /* assertPre */ 
coverage_0xb698eaca(0x5be1b23a02ee11db128d9e8ba7e5837aa552ee2261220d775effd6193e67f455); /* statement */ 
require(
            leafProofLengths.length == pruneCount &&
                latestConfirmedProofLengths.length == pruneCount,
            "input length mistmatch"
        );coverage_0xb698eaca(0xa8edeba80ba18b2879c9ed4c83a1c652aedd30935403bf6f39974c7ae7170682); /* assertPost */ 

coverage_0xb698eaca(0x929aecb0ed6f4434f509541ee093324433b33af28e05ce61ffab3dabcb8aa98c); /* line */ 
        coverage_0xb698eaca(0xe4bd5b1742988017b92414996fc940f79f023a04d7324a1211b28fefc7c8567a); /* statement */ 
uint256 prevLeafOffset = 0;
coverage_0xb698eaca(0x32580c290595fad57765ab06dc626cbf5a72af21b31b31395671dfbfda738c0a); /* line */ 
        coverage_0xb698eaca(0x8e8335d1546cf5e9125a2d9555e2dc4c68fcd989a87cc42cc1f2fc96ecb3631e); /* statement */ 
uint256 prevConfOffset = 0;

coverage_0xb698eaca(0x3fb0a3d84dcd0006bb58b21a216bdeecfbeb9eb72a4c4d2af30c43ab3b0821d0); /* line */ 
        coverage_0xb698eaca(0xa9ec65acc4213522da5ca82d07d1ba77628b1f2f89ea97ee2c9f591cc2612da1); /* statement */ 
for (uint256 i = 0; i < pruneCount; i++) {
coverage_0xb698eaca(0x03d43749694382d6a9f15dcb88be3e14c981117db9cbdc6339f95d3126cd3f42); /* line */ 
            coverage_0xb698eaca(0x16d2ddc30e6acb2f87bd8d04e439cc0878e7831d958ec7c5fa8cb456d2f87d10); /* statement */ 
(prevLeafOffset, prevConfOffset) = _pruneLeaf(
                fromNodes[i],
                latestConfirmedProofLengths[i],
                leafProofLengths[i],
                leafProofs,
                latestConfProofs,
                prevLeafOffset,
                prevConfOffset
            );
        }
    }

    function latestConfirmed() public view returns (bytes32) {coverage_0xb698eaca(0x4d0b55c2907784d94753fd0625256f59815039145bd994a2b09eb89357bb2d70); /* function */ 

coverage_0xb698eaca(0x97d999cb54ea013baf0964aadd62aecbc311c4692d2fc4224a5b2c6ffb104d14); /* line */ 
        coverage_0xb698eaca(0x0457d5d0c3790c32e33092083974e9ab2022782a2ed28c6fa3de1865c3c149ca); /* statement */ 
return latestConfirmedPriv;
    }

    function isValidLeaf(bytes32 leaf) public view returns (bool) {coverage_0xb698eaca(0xe0bb44084c9f55f6a5b7766912e4ea51833d06fc814d952d1d58fda99df1f3ee); /* function */ 

coverage_0xb698eaca(0xf6892d53b7aad2f6c1abcce7517bc6b8f058bf38f7fb1a7b0efab64beee64430); /* line */ 
        coverage_0xb698eaca(0x83f5aee98bd7ac93a7f432a63eac91c58200ffa200cd6b674610a0948a99276d); /* statement */ 
return leaves[leaf];
    }

    function init(
        bytes32 _vmState,
        uint128 _gracePeriodTicks,
        uint128 _arbGasSpeedLimitPerTick,
        uint64 _maxExecutionSteps
    ) internal {coverage_0xb698eaca(0x25dbc35a3f18fcf255015a37462f8f6f02452087508479aadddfeb6b8120af78); /* function */ 

        // VM protocol state
coverage_0xb698eaca(0x62b985fe6b6ad75a23915c9dfff8d7721b4faa27117e0cbfa54dc32a0de831a1); /* line */ 
        coverage_0xb698eaca(0x3c63543e5937bc5dcd7f1d82836a620f05581d3fb46341d10660a12a2b480ae7); /* statement */ 
bytes32 vmProtoStateHash = RollupUtils.protoStateHash(_vmState, 0, 0, 0, 0);
coverage_0xb698eaca(0x6bffb3639ef7535d5220bbd61b5c33fed7232a5ca60b701426f7923db9b5fb2f); /* line */ 
        coverage_0xb698eaca(0xb3d7e256db1978c6c9efa0f971f6d3de841e0b1fe4c3f6ee256f50890cdb8a4c); /* statement */ 
bytes32 initialNode = RollupUtils.childNodeHash(0, 0, 0, 0, vmProtoStateHash);
coverage_0xb698eaca(0xfd73298c545bded538da340d669edf270a4745b3651815c9ecf5bdab16a69e3c); /* line */ 
        coverage_0xb698eaca(0x07534113fa0bc9d11af1331e4536e266d01908113f543d328c950d92d8fa73bd); /* statement */ 
latestConfirmedPriv = initialNode;
coverage_0xb698eaca(0x1d0fb851e8ff9cdd7e931f3dc2fa1e233aa66c88391189b0f56f1a0d346f8607); /* line */ 
        coverage_0xb698eaca(0x1e74e79151dff9a486887cb1d0c9974ed26e4c248d00099e4e6b6a68c63337d6); /* statement */ 
leaves[initialNode] = true;

        // VM parameters
coverage_0xb698eaca(0xb877f1ee1dfca632452905e85b3aace5939465fcd850c0a46c71e7a0426cd3a3); /* line */ 
        coverage_0xb698eaca(0x68fa781d2ee113323c0c839d1112e2f2a9f6af4c4804650e970cf7f074d3a170); /* statement */ 
vmParams.gracePeriodTicks = _gracePeriodTicks;
coverage_0xb698eaca(0x326bee06d19b73549b340b425cbdf84d406778f27a95607a9e1c716eee36402a); /* line */ 
        coverage_0xb698eaca(0x30731f87b121e0409c45a06d3376e35169ecd467c6e32cda7e444525f2649712); /* statement */ 
vmParams.arbGasSpeedLimitPerTick = _arbGasSpeedLimitPerTick;
coverage_0xb698eaca(0x8fb06d7108a7f8ad200b8c1be347eaf367cdfca9fa47bb78f3e53ce4a57287a9); /* line */ 
        coverage_0xb698eaca(0x26a9d2d4b9ef4e266db85a8daeeb5a12998769aed12b8a11c1424297862aae30); /* statement */ 
vmParams.maxExecutionSteps = _maxExecutionSteps;
    }

    function makeAssertion(
        NodeGraphUtils.AssertionData memory data,
        bytes32 inboxValue,
        uint256 inboxCount
    ) internal returns (bytes32, bytes32) {coverage_0xb698eaca(0xdeb8166dc2a367266a005875742ac780d5d7a6a97084a1accd2fa0f7c3eea929); /* function */ 

coverage_0xb698eaca(0xfb4de23574e3c75f07987c903d71d4d6fc590560645389cc43b6a81c7d81f7c9); /* line */ 
        coverage_0xb698eaca(0x2220fd4f510a4549a8daf5bd1f11466bfda211fb90a20ddbe3060deacb5e9bf4); /* statement */ 
(bytes32 prevLeaf, bytes32 vmProtoHashBefore) = NodeGraphUtils.computePrevLeaf(data);
coverage_0xb698eaca(0xa13e1f0baf1c841de876325c42d05de62f2b2bd21ef8fbbf022cc4a211f3b041); /* line */ 
        coverage_0xb698eaca(0x3df305371e01b7861dba2aaf03ae62671289d548dbdf78a63714ae01e821d413); /* assertPre */ 
coverage_0xb698eaca(0x276fae31f8f24b886653a7b75fdbee7253b2e8be1f31ab9e4f14d0f5abc822b7); /* statement */ 
require(isValidLeaf(prevLeaf), MAKE_LEAF);coverage_0xb698eaca(0xf6e77f6d20130089757c607f4ee31be47f3ca30d4a1faa529e8a5449df84bcf6); /* assertPost */ 

coverage_0xb698eaca(0x6a7388f618c1cc596f6cf33d9a9bde3230fe8d2ed260176922f4e05abef71afd); /* line */ 
        coverage_0xb698eaca(0x3ea55caa3e10f12a3f38b8d984ab59ff04a2fa721ab12ea47c6213e4b8bc69b6); /* statement */ 
_verifyAssertionData(data);

coverage_0xb698eaca(0x4ce468bf13ae00d89928f460156589e02bb47f63194fa9b552af94d369ae2bfc); /* line */ 
        coverage_0xb698eaca(0xae9b0d39fff9733a6531afc2bde3febbce6eada7dafb7bb131b08e1014826647); /* assertPre */ 
coverage_0xb698eaca(0x96156a28627f2dc6bd5aa4ea11da365237c3085aa0616f71ad0872a8e7bc052f); /* statement */ 
require(
            data.importedMessageCount <= inboxCount.sub(data.beforeInboxCount),
            MAKE_MESSAGE_CNT
        );coverage_0xb698eaca(0x25d7573ca725f004c43797acc88c141b65672c886203333f10de89edb1d0140c); /* assertPost */ 


coverage_0xb698eaca(0xc784619ca75a8f0feae93340aaa43b7fc1a7dca0a214975d8e6593aabc3a2373); /* line */ 
        coverage_0xb698eaca(0x7caa328163f432627b1c46a2770a80faf9620621906e2beb2b2b08da27d0537f); /* statement */ 
bytes32 validLeaf = _initializeAssertionLeaves(
            data,
            prevLeaf,
            vmProtoHashBefore,
            inboxValue,
            inboxCount
        );

coverage_0xb698eaca(0x281549b0a5a5385de156e70e1d199271ed0e1d8ca050b641b1e3b1b3c1c546c2); /* line */ 
        delete leaves[prevLeaf];

coverage_0xb698eaca(0xa32488f048ddb06d2d0539a91c559d4daa3913cdbe75c519e7d631797aad3289); /* line */ 
        coverage_0xb698eaca(0xe60fa3c4f10714d17eba0d05ecdd292fa4a54d832eaa7f0b1d1b2a43c18f35c9); /* statement */ 
emitAssertedEvent(data, prevLeaf, validLeaf, inboxValue, inboxCount);
coverage_0xb698eaca(0x7a0047951041dd98d63842572930249743c55bba5504250160ec2a4923678398); /* line */ 
        coverage_0xb698eaca(0xde8bcd2f6583f011fd155da58b7f655605d2e9e632d9abf12e054ee739525a91); /* statement */ 
return (prevLeaf, validLeaf);
    }

    function confirmNode(bytes32 to) internal {coverage_0xb698eaca(0xf762c770cc9a1fa8e65a220ce0a0b5abac6bbf18442b9ec03442a954417c7313); /* function */ 

coverage_0xb698eaca(0x3b8e0eb438e4bf15375e6f912478fb93dd93bc735b550a4bf1eba6f042886481); /* line */ 
        coverage_0xb698eaca(0x57bc98ce7c56c2d4ac9073e053f0c79f627dd1309c4251600626074e16aaf507); /* statement */ 
latestConfirmedPriv = to;
coverage_0xb698eaca(0xaf96b6e8f95adf0244b7ab8fb6b2a37d9a41218f1e24772805f7949c4fe04687); /* line */ 
        coverage_0xb698eaca(0x0ade80b0f0eb2f87a3005f827eb6e22da2c4f583f712ef9faf7e2809d427a444); /* statement */ 
emit RollupConfirmed(to);
    }

    function emitAssertedEvent(
        NodeGraphUtils.AssertionData memory data,
        bytes32 prevLeaf,
        bytes32 validLeaf,
        bytes32 inboxValue,
        uint256 inboxCount
    ) private {coverage_0xb698eaca(0xb62f76426e26367617fff49c0f4fd484a64bb0e9430a0556e18efe18a99c06a7); /* function */ 

coverage_0xb698eaca(0xff0b7f7a36a835d0366a74397e834dfc8d9839927ab514574b30504395d916b8); /* line */ 
        coverage_0xb698eaca(0x341e18ef9c5c8be4810c79f051fb0c315b97472425ec729ca9a1155f42f11369); /* statement */ 
emit RollupAsserted(
            [
                prevLeaf,
                inboxValue,
                data.assertion.afterMachineHash,
                data.assertion.afterInboxHash,
                data.assertion.lastMessageHash,
                data.assertion.lastLogHash,
                validLeaf
            ],
            inboxCount,
            data.importedMessageCount,
            data.assertion.numArbGas,
            data.assertion.numSteps,
            data.beforeMessageCount,
            data.assertion.messageCount,
            data.beforeLogCount,
            data.assertion.logCount
        );
    }

    /**
     * @notice Prune a leaf from the node graph if it conflicts with the latest confirmed node
     * @dev Pruning leaves frees up blockchain storage, but is otherwise unnecessary
     * @param from The node where the leaf we want to prune diverged from the correct path
     * @param latestConfirmedProofLength Length of the proof showing the from is an ancestor of latest confirmed
     * @param leafProofLength Length of the proof showing the the pruned leaf conflicts with the from node
     * @param leafProofs Array containing the leaf conflict proof
     * @param latestConfProofs Array containing the leaf confirmed proof
     * @param prevLeafOffset Index into the leaf proof
     * @param prevConfOffset Index into the confirm proof
     */
    function _pruneLeaf(
        bytes32 from,
        uint256 latestConfirmedProofLength,
        uint256 leafProofLength,
        bytes32[] memory leafProofs,
        bytes32[] memory latestConfProofs,
        uint256 prevLeafOffset,
        uint256 prevConfOffset
    ) private returns (uint256, uint256) {coverage_0xb698eaca(0x980d73b0545cb15249aabffb9fdf0b4de441a7d6b6ece6d33abc92b7f57d9c85); /* function */ 

coverage_0xb698eaca(0xc2a0728b0c7dc476773bf7acc63881aa5181870f9a5a13d9a596e34df252649f); /* line */ 
        coverage_0xb698eaca(0x2f0e40cbe66bb322eca47b162a0ae8dfc24bb293bcc81c6b6397528adbedafbb); /* assertPre */ 
coverage_0xb698eaca(0x4283c3d2e9e6daf233c41c0efb840d24a3c65f7650e4bd7a0abf7d8e7b31d8d9); /* statement */ 
require(leafProofLength > 0 && latestConfirmedProofLength > 0, PRUNE_PROOFLEN);coverage_0xb698eaca(0x9636a98501186dcabac198b55e9ead2cd3e317fbd0ea64780da9622d12528053); /* assertPost */ 

coverage_0xb698eaca(0x232bed43816aba8182b31d98f8fb0900fa173cc9978085422e514d60d2279018); /* line */ 
        coverage_0xb698eaca(0xf227711f596d55ad6f4a7e6972732fc8f7263d8460ec09224483a24c66e6ce40); /* statement */ 
uint256 nextLeafOffset = prevLeafOffset + leafProofLength;
coverage_0xb698eaca(0xbf96bd81b50e5110b8f72ad6a63a4a6b0bb41706b0a3dc106c05f9bcc2f693b9); /* line */ 
        coverage_0xb698eaca(0xefcbe848b31570ce69aed8b27f86a312cc31bc535178aa530197ba69e212eb82); /* statement */ 
uint256 nextConfOffset = prevConfOffset + latestConfirmedProofLength;

        // If the function call was produced valid at any point, either all these checks will pass or all will fail
coverage_0xb698eaca(0x7f1d4eda9151931a51e4200ec051776976c72a5cd868483fe7873bb1cb3137e3); /* line */ 
        coverage_0xb698eaca(0x0e03ced6491d194620d03021212211b77a52f897f314ed24138cbca4a9a6a8ad); /* statement */ 
bool isValidNode = RollupUtils.calculateLeafFromPath(
            from,
            latestConfProofs,
            prevConfOffset,
            nextConfOffset
        ) == latestConfirmed();

coverage_0xb698eaca(0x52d9f84d6a2e087c0748e26030a009a0e63179bba413c51410c9edbca8e6a456); /* line */ 
        coverage_0xb698eaca(0xa93f7c2d86647a249b9e3eeedfd7a1321bb9f2f03e30075cbee6abe50de7e508); /* assertPre */ 
coverage_0xb698eaca(0xfd185b0fda0982e28480d18e18a3eed083ee1d020b94637038f9bab201ee672f); /* statement */ 
require(
            isValidNode && leafProofs[prevLeafOffset] != latestConfProofs[prevConfOffset],
            PRUNE_CONFLICT
        );coverage_0xb698eaca(0xa2da265a85f1f56aa24df194162bbd3b38c7315741e9108f836e0e3344514c35); /* assertPost */ 


coverage_0xb698eaca(0xb44fa96c737dbc918195bee47faff9d71c72ea78e256c2f2351331d957b2bd3e); /* line */ 
        coverage_0xb698eaca(0xe1e6d7d3e1a95458ace6e0b4e7f0ff85119bf8ee7a84ccd5179ad227490cbb02); /* statement */ 
bytes32 leaf = RollupUtils.calculateLeafFromPath(
            from,
            leafProofs,
            prevLeafOffset,
            nextLeafOffset
        );
coverage_0xb698eaca(0xf095f1e54ce1f5d35f535309c67aaf61a8d25d7d515936048c2548f9e9bcd685); /* line */ 
        coverage_0xb698eaca(0x9b7d3bf15e74502b64d1e8d55433b7c9ae3313f58502d2e5522bc443e82ad847); /* statement */ 
if (isValidLeaf(leaf)) {coverage_0xb698eaca(0x049f9dc16d6a0d57aa895da05afe55df8dc8b596df1eb6c42f5f18c2bdc1eeeb); /* branch */ 

coverage_0xb698eaca(0xe6f713bfb09a9246be367c9a09cb5194ade4e805052195caaa30d825326bdd58); /* line */ 
            delete leaves[leaf];
coverage_0xb698eaca(0x04bbb325706b8ad28a4ccec932c1ae3f399b2c850fbd8e500f771d3042c03f5c); /* line */ 
            coverage_0xb698eaca(0x476527b93fb16d0b4a93f5388ff4b89163e05185c144d3bafbee710402b6b15a); /* statement */ 
emit RollupPruned(leaf);
        }else { coverage_0xb698eaca(0xba9f1c6429ec12abd7a301b6547b6d29a71636e86b11a13af8c8676daaae2ec7); /* branch */ 
}

coverage_0xb698eaca(0xf4f4525bfdc972e722a5c03533d4fb69669fd9d75e77363a2b70424048f45d9c); /* line */ 
        coverage_0xb698eaca(0x01614e32dc63247de0b2540e3d2189f043f5ac8c7ba6ff9d416587dfbaa8c8be); /* statement */ 
return (nextLeafOffset, nextConfOffset);
    }

    function _verifyAssertionData(NodeGraphUtils.AssertionData memory data) private view {coverage_0xb698eaca(0xdfcc21ec42fae0b197ed7c57dbcfdc5c31af417335c59631a613e2bda3e040b4); /* function */ 

coverage_0xb698eaca(0x65756a80d5b56055042d9d381d1726015cae7ac41c6d3659ad133de589f04c41); /* line */ 
        coverage_0xb698eaca(0x1691f09d8df1e92f4cb04aafd792ee03feeae74df8c7e06bb38dae8605f04129); /* assertPre */ 
coverage_0xb698eaca(0x6556a20cb8c3d8abf1c8b52a32dfaca9742894a0da73edb7aa3fe9162dd78d44); /* statement */ 
require(
            !VM.isErrored(data.assertion.beforeMachineHash) &&
                !VM.isHalted(data.assertion.beforeMachineHash),
            MAKE_RUN
        );coverage_0xb698eaca(0x42edde2fa17041d5ecee6e438d061daefc1fb2bf501b0f4e1526036fd6fa1b48); /* assertPost */ 

coverage_0xb698eaca(0x0ddf5d926a43714494766b7e9bebdcdecc72ce2f4993d82786339110fe1ce385); /* line */ 
        coverage_0xb698eaca(0x7ce1a2b9d359b3902662f870249e01342fe0d32ce4116c5743b4cf0a448f6ef1); /* assertPre */ 
coverage_0xb698eaca(0x5ba71e73d9484a2d3825b9633b6eefc52124176a949df6790d7cfb738585561c); /* statement */ 
require(data.assertion.numSteps <= vmParams.maxExecutionSteps, MAKE_STEP);coverage_0xb698eaca(0x28b256d14aa0d9a674b175c1f8d2c617790327e6035b35d69c0774df23f8a09c); /* assertPost */ 

    }

    function _initializeAssertionLeaves(
        NodeGraphUtils.AssertionData memory data,
        bytes32 prevLeaf,
        bytes32 vmProtoHashBefore,
        bytes32 inboxValue,
        uint256 inboxCount
    ) private returns (bytes32) {coverage_0xb698eaca(0xd5a22ebd0db84bb9a149c3b78d625cea2fe621f406ff13ddf5dc91567e82097f); /* function */ 

coverage_0xb698eaca(0x2e47e12139384014871ab4aa7950cf9403542ec318f3c7efbf204527897e091e); /* line */ 
        coverage_0xb698eaca(0x9c52e663934d5885a7009976e2f40f9cbddd4573ab97932c484d68e5049a7c02); /* statement */ 
(uint256 checkTimeTicks, uint256 deadlineTicks) = NodeGraphUtils.getTimeData(
            vmParams,
            data,
            block.number
        );

coverage_0xb698eaca(0x3e31b4b09438c648dc5d8895d8625e0eb9290260a4c0538fbe177211b4bc12da); /* line */ 
        coverage_0xb698eaca(0x1d7c543d9f9f33e78223a44d761339e71ce4f5aeec1b894b3a02eacfc55e550d); /* statement */ 
bytes32 invalidInboxLeaf = NodeGraphUtils.generateInvalidInboxTopLeaf(
            data,
            prevLeaf,
            deadlineTicks,
            inboxValue,
            inboxCount,
            vmProtoHashBefore,
            vmParams.gracePeriodTicks
        );
coverage_0xb698eaca(0x9dd4edee0ac375f6a8f5fd36d268eb298aaab1fdfaff0ea991c989334340cbed); /* line */ 
        coverage_0xb698eaca(0xa0924b59ca306da4a89f9f5d4f65022aab09295a86db7c248c6ac3b4cb21c769); /* statement */ 
bytes32 invalidExecLeaf = NodeGraphUtils.generateInvalidExecutionLeaf(
            data,
            prevLeaf,
            deadlineTicks,
            vmProtoHashBefore,
            vmParams.gracePeriodTicks,
            checkTimeTicks
        );
coverage_0xb698eaca(0x64ac1a95b35b8b78d01c760242342ba23e89dea70ef0bfb8bd477fec93bc6bbd); /* line */ 
        coverage_0xb698eaca(0xa313a25fe1e70a6efac70c5da6dcec03ff25ef3d0c0d56ec60ace7de8dd6a038); /* statement */ 
bytes32 validLeaf = NodeGraphUtils.generateValidLeaf(data, prevLeaf, deadlineTicks);

coverage_0xb698eaca(0xc572575cb19c21a463fbeea74ece308c3e8a63b767982e4218d8676766e806cd); /* line */ 
        coverage_0xb698eaca(0x41d751bae5c74c740af9b64f491f0696714acc143eda22de05345af4b7edca3c); /* statement */ 
leaves[invalidInboxLeaf] = true;
coverage_0xb698eaca(0xba855d865f5087e28eb7b62cc3a613bbda858f65016a8189fe0a0b0b66301a50); /* line */ 
        coverage_0xb698eaca(0xbec13d37d311f6496a7837633792ea29bea42988270a01125a68a109473f4a1e); /* statement */ 
leaves[invalidExecLeaf] = true;
coverage_0xb698eaca(0x3facaa86b4320cad178af4be8cac572b9bf1df63a833adeba90c1ee9f223832a); /* line */ 
        coverage_0xb698eaca(0xff48323d709ce2025741434c5d47ebef388998124e64b7df53e07e9b7432e79a); /* statement */ 
leaves[validLeaf] = true;

coverage_0xb698eaca(0x9676872ba3c908d96e1bb89a05b4b84d2499071b218f1d41a23bf2b1a0b28ce0); /* line */ 
        coverage_0xb698eaca(0x52ef351e74d6a7ed3dcea68837464ad6e61a1cf380232614c9ae4d15518ed973); /* statement */ 
return validLeaf;
    }
}
