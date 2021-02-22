// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2020, Offchain Labs, Inc.
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
import "./VM.sol";

library NodeGraphUtils {
function coverage_0x47df6391(bytes32 c__0x47df6391) public pure {}

    using Hashing for Value.Data;

    struct AssertionData {
        uint256 beforeInboxCount;
        bytes32 prevPrevLeafHash;
        uint256 prevDeadlineTicks;
        bytes32 prevDataHash;
        uint32 prevChildType;
        uint256 importedMessageCount;
        uint256 beforeMessageCount;
        uint256 beforeLogCount;
        ChallengeUtils.ExecutionAssertion assertion;
    }

    function makeAssertion(
        bytes32[8] memory fields,
        uint256[5] memory fields2,
        uint32 prevChildType,
        uint64 numSteps,
        uint64 numArbGas,
        uint64 messageCount,
        uint64 logCount
    ) internal pure returns (AssertionData memory) {coverage_0x47df6391(0xd28e23ff0123096cc3fcf4b4d48b1b73d8a5b5f9d2fc79303a841ee6eff17e7e); /* function */ 

coverage_0x47df6391(0x43a0d8a3b835075986d1f3288f6ed6432f52358951f4627f231d8d680d76eb47); /* line */ 
        coverage_0x47df6391(0xd7f6fbb48138663ca4020e0fd80feda38dce127bcee35015bcc61ed4b81623fd); /* statement */ 
ChallengeUtils.ExecutionAssertion memory assertion = ChallengeUtils.ExecutionAssertion(
            numSteps,
            numArbGas,
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            0,
            fields[4],
            messageCount,
            0,
            fields[5],
            logCount
        );
coverage_0x47df6391(0x1ddd1cfdf786ac776c23c914e0500482602e2418cfae2493810fbc0a48a6976f); /* line */ 
        coverage_0x47df6391(0xeaf4fd4eac0b7772d63ff3150f46d8b1a6d644e7aa0f0cd44b71c3717c96f49f); /* statement */ 
return
            AssertionData(
                fields2[0],
                fields[6],
                fields2[1],
                fields[7],
                prevChildType,
                fields2[2],
                fields2[3],
                fields2[4],
                assertion
            );
    }

    function computePrevLeaf(AssertionData memory data)
        internal
        pure
        returns (bytes32 prevLeaf, bytes32 vmProtoHashBefore)
    {coverage_0x47df6391(0x2b9c4942c389b4bd4647877e412e0e81fb959b81c9fb42ea6aaf142688452c20); /* function */ 

coverage_0x47df6391(0xd46f40c60f3d35cb84b8caa2032c218f3aaa83060be67acd000c5935f6600585); /* line */ 
        coverage_0x47df6391(0xb73ad2df5c0c0b8f6ce9d5d9c24dd746fabb7f297ad7d8c780bad668cece0ab2); /* statement */ 
vmProtoHashBefore = RollupUtils.protoStateHash(
            data.assertion.beforeMachineHash,
            data.assertion.beforeInboxHash,
            data.beforeInboxCount,
            data.beforeMessageCount,
            data.beforeLogCount
        );
coverage_0x47df6391(0xaeb6f1bb2cc01151c4fe283b7d3f0d8a1cba7f2ece265e5ac546405c81ff4e23); /* line */ 
        coverage_0x47df6391(0x9b9956fce04bb97760e85ee50cb7aef4aa317671347ae4049350328fb4f0f388); /* statement */ 
prevLeaf = RollupUtils.childNodeHash(
            data.prevPrevLeafHash,
            data.prevDeadlineTicks,
            data.prevDataHash,
            data.prevChildType,
            vmProtoHashBefore
        );
    }

    function getTimeData(
        VM.Params memory vmParams,
        AssertionData memory data,
        uint256 blockNum
    ) internal pure returns (uint256, uint256) {coverage_0x47df6391(0xcc33bfe366a9a0727848881c1ceee5d4982937bbede2c16c846e5fc9bb5bbfdf); /* function */ 

coverage_0x47df6391(0x161288b6c8c044852dda56c9a211cd1a2d82b8673927131526cda9fa4c135244); /* line */ 
        coverage_0x47df6391(0xd301a55070c9c7b14c3063ad96a247c00bbf736e66d20de42d447b5ed795c6e7); /* statement */ 
uint256 checkTimeTicks = data.assertion.numArbGas / vmParams.arbGasSpeedLimitPerTick;
coverage_0x47df6391(0xf313344c9cf3af44f8045ae85d5b379d8cab62b659bf850c7f509e268f0ce494); /* line */ 
        coverage_0x47df6391(0x0e3e08696d9d532ef1de23f4dc03548761bf516ea3509abb078f985055ca63fd); /* statement */ 
uint256 deadlineTicks = RollupTime.blocksToTicks(blockNum) + vmParams.gracePeriodTicks;
coverage_0x47df6391(0x0ceac69c135db2cbc99eec43703228fd0b90a02b2a479b70152bf34157f59751); /* line */ 
        coverage_0x47df6391(0x33369742ddb14840ac8173e378545d478ce756d95d888979d95ea36edd67967c); /* statement */ 
if (deadlineTicks < data.prevDeadlineTicks) {coverage_0x47df6391(0x2bfc29ab6c2d38d60abcdc26f51c658d00d52a050f1c9cbb354b1a78ea3caaf0); /* branch */ 

coverage_0x47df6391(0xcd7b42f23d20c1d6200b5623a5edb3a30ee8a5c6fe1ae24252bb933951fdb2a9); /* line */ 
            coverage_0x47df6391(0x8429fd93231cc5143573507031eb6c84e9a79515971acd9b76dc66f65629e2c9); /* statement */ 
deadlineTicks = data.prevDeadlineTicks;
        }else { coverage_0x47df6391(0xe2d07ff1ece53d757c05bb9444fab24f18ec6c55e962320d333139c78345f401); /* branch */ 
}
coverage_0x47df6391(0x4deec32f26d5771463e6526c50140cf9ac4354cda5e72b3ad8a6cb2f535792f5); /* line */ 
        coverage_0x47df6391(0x533ae11684d926ef29481073139946b43ef5ec66eaf4c00a05a62e7ead803388); /* statement */ 
deadlineTicks += checkTimeTicks;

coverage_0x47df6391(0xec4efb908cb94021442a85d8d6fffecb667fa0505cde28f48803f75935459aed); /* line */ 
        coverage_0x47df6391(0x3ed2b7bdb83c2ebc614ad64a29be01f5664cd7571bb790c78f6e6c202a67041a); /* statement */ 
return (checkTimeTicks, deadlineTicks);
    }

    function generateInvalidInboxTopLeaf(
        AssertionData memory data,
        bytes32 prevLeaf,
        uint256 deadlineTicks,
        bytes32 inboxValue,
        uint256 inboxCount,
        bytes32 vmProtoHashBefore,
        uint256 gracePeriodTicks
    ) internal pure returns (bytes32) {coverage_0x47df6391(0x9446f4785bfe65841c64a5164ceedc872137b80bfd0933741d7d7546df099b32); /* function */ 

coverage_0x47df6391(0xd81a6fdaf436eaa5634b64f2414cc16b16e293fe9a51699298e7731bf33276e9); /* line */ 
        coverage_0x47df6391(0x9258b3571c2b4a1516f21eee11531ed9c0f59709f8bd8f7541fc70d960f2f0e4); /* statement */ 
bytes32 challengeHash = ChallengeUtils.inboxTopHash(
            data.assertion.afterInboxHash,
            inboxValue,
            inboxCount - (data.beforeInboxCount + data.importedMessageCount)
        );
coverage_0x47df6391(0xcce478e5f5b15d349663dedcb6b07bdbe5b66bbb16aefe733467d4dea7ad9cbe); /* line */ 
        coverage_0x47df6391(0x7ff2778ba1cc3eff6f20d4b30283d6ef0204b7fab15bea188bab2f32ab03baba); /* statement */ 
return
            RollupUtils.childNodeHash(
                prevLeaf,
                deadlineTicks,
                RollupUtils.challengeDataHash(
                    challengeHash,
                    gracePeriodTicks + RollupTime.blocksToTicks(1)
                ),
                ChallengeUtils.getInvalidInboxType(),
                vmProtoHashBefore
            );
    }

    function generateInvalidExecutionLeaf(
        AssertionData memory data,
        bytes32 prevLeaf,
        uint256 deadlineTicks,
        bytes32 vmProtoHashBefore,
        uint256 gracePeriodTicks,
        uint256 checkTimeTicks
    ) internal pure returns (bytes32 leaf) {coverage_0x47df6391(0xec881faed8ca38792f42e55797b1a80a6ed0cbcd7e50672ca68eeae413ba5a3d); /* function */ 

coverage_0x47df6391(0xafde0ca665140b8ccff2dd6de9a409a7a663e2e760de877dcf1ab4c407c3d87c); /* line */ 
        coverage_0x47df6391(0xfec7b8311021b7a34655d63a3c896077cde8fd9360ec7c76b3aaa47d4648e26a); /* statement */ 
return
            RollupUtils.childNodeHash(
                prevLeaf,
                deadlineTicks,
                RollupUtils.challengeDataHash(
                    ChallengeUtils.hash(data.assertion),
                    gracePeriodTicks + checkTimeTicks
                ),
                ChallengeUtils.getInvalidExType(),
                vmProtoHashBefore
            );
    }

    function generateValidLeaf(
        AssertionData memory data,
        bytes32 prevLeaf,
        uint256 deadlineTicks
    ) internal pure returns (bytes32) {coverage_0x47df6391(0x931ba5aef9e35b60577d5698e20d7abe8d86d44b501ddce004b062b5f88fa045); /* function */ 

coverage_0x47df6391(0x26d32fb918c30128604fb5f03e47abfb036c2568c802e5bc98364f808a2fb198); /* line */ 
        coverage_0x47df6391(0xbcbd0555afa7d123be37bf77f901dadc80394bd5c1db61775a3ad954c475eed0); /* statement */ 
return
            RollupUtils.childNodeHash(
                prevLeaf,
                deadlineTicks,
                RollupUtils.validDataHash(
                    data.beforeMessageCount,
                    data.assertion.lastMessageHash,
                    data.assertion.lastLogHash
                ),
                ChallengeUtils.getValidChildType(),
                RollupUtils.protoStateHash(
                    data.assertion.afterMachineHash,
                    data.assertion.afterInboxHash,
                    data.beforeInboxCount + data.importedMessageCount,
                    data.beforeMessageCount + data.assertion.messageCount,
                    data.beforeLogCount + data.assertion.logCount
                )
            );
    }
}
