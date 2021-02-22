// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2019, Offchain Labs, Inc.
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

import "./BisectionChallenge.sol";
import "./ChallengeUtils.sol";

import "../inbox/Messages.sol";

contract InboxTopChallenge is BisectionChallenge {
function coverage_0x5f761338(bytes32 c__0x5f761338) public pure {}

    event Bisected(bytes32[] chainHashes, uint256 totalLength, uint256 deadlineTicks);

    event OneStepProofCompleted();

    // Proof was incorrect
    string private constant HC_OSP_PROOF = "HC_OSP_PROOF";

    function bisect(bytes32[] calldata _chainHashes, uint256 _chainLength) external asserterAction {coverage_0x5f761338(0xf6e859e39d98c4b1c60084b45be6883f59dded15f160d4de3123e541843d85e2); /* function */ 

coverage_0x5f761338(0xf735c9d87d39e659618f5d4a15da323558bb86fc212a8ef616b6ccfb6ca3e0e8); /* line */ 
        coverage_0x5f761338(0xad63645d1f77963b48e83130830261bd2cb0d4d7cd7834091412c67a752a607f); /* statement */ 
uint256 bisectionCount = _chainHashes.length - 1;

coverage_0x5f761338(0x1d590220f4153f5d2c402d922869481b5c9bbca00111ed725f440be36b8de8a3); /* line */ 
        coverage_0x5f761338(0x99b5b97adfe9e69862b0fbf1db99bb2b8960340771bcb13af0a2bc87776b6a2d); /* statement */ 
requireMatchesPrevState(
            ChallengeUtils.inboxTopHash(_chainHashes[0], _chainHashes[bisectionCount], _chainLength)
        );

coverage_0x5f761338(0x582905ef3e8ee4b0963f54ab354ed8faa4e420baf86a1b8ccc579ddd81258d6d); /* line */ 
        coverage_0x5f761338(0x8d40c3f675f812c4f86aab947f6d305e42d400a82cdc99cb41d146e90a73eb59); /* assertPre */ 
coverage_0x5f761338(0x6a423a23c3bd0915aad282933131a8afe07fbe53a1a0c26a1a51f517dcc1659b); /* statement */ 
require(_chainLength > 1, "bisection too short");coverage_0x5f761338(0xb482cc1c00804f944355a1c04d75ba9ad2e339a270eac315b7585366536aa310); /* assertPost */ 

coverage_0x5f761338(0x005d7c9cefef6d5a1f0c60d8bfc1c6f2495bf79b7080489bed0725f812d02ac2); /* line */ 
        coverage_0x5f761338(0xf071a18d71399c08f451b39f9ad31b59cea14f26a433f2266a89a35f458a4c61); /* statement */ 
bytes32[] memory hashes = new bytes32[](bisectionCount);
coverage_0x5f761338(0xb2a5ffab2bdd73dc1fe6e4ee5e904da44668ad6f1e95577aa5bc0c84b550a7ed); /* line */ 
        coverage_0x5f761338(0x95ce7b178a974f06411c535b4064a2af7e7ae26beded09495897a3a64b89b1c8); /* statement */ 
hashes[0] = ChallengeUtils.inboxTopHash(
            _chainHashes[0],
            _chainHashes[1],
            firstSegmentSize(_chainLength, bisectionCount)
        );
coverage_0x5f761338(0x00b2eb2b66d6687be5d33edef95bacbe183844bd2b1bac6ddaee127d3ebe6038); /* line */ 
        coverage_0x5f761338(0x01978c79b05d4c46c3edd007d59dbc800d3694a373fc7ce54a379c650c99803d); /* statement */ 
for (uint256 i = 1; i < bisectionCount; i++) {
coverage_0x5f761338(0xce7d37d95da48fc352baa91c25e510e2aaa52c88761159bf2284fbdc7fea9441); /* line */ 
            coverage_0x5f761338(0xb42c447557e5bdc8f311f95513ebcbf04e60e8d7b7d47bfe0ab9090115414717); /* statement */ 
hashes[i] = ChallengeUtils.inboxTopHash(
                _chainHashes[i],
                _chainHashes[i + 1],
                otherSegmentSize(_chainLength, bisectionCount)
            );
        }

coverage_0x5f761338(0x4d12b0b809676c0065c193c6aecd99bed558c6dea8dc5ab30a4688fded36cc7a); /* line */ 
        coverage_0x5f761338(0x22b72ab0dbe573e7997ada72faa8310200cb090b899ec444f84da815a681535b); /* statement */ 
commitToSegment(hashes);
coverage_0x5f761338(0xe98c81cbf4ce8fe90021d63293c8f93d82c363a6bc01b9c4165619ed84f4597a); /* line */ 
        coverage_0x5f761338(0xb3ef3fcfbef1a131fdfe8a0f5e230a7f19d219350c5cac5909c26a6c2c0c1fe7); /* statement */ 
asserterResponded();
coverage_0x5f761338(0x8c538f003488730ef26b7c0152968abe7da061feed35de6bfe41c128d18a0841); /* line */ 
        coverage_0x5f761338(0xa4e6544d38bd45a5640f8884bcc550a75434d794478c412ea9efeed4f5bc141d); /* statement */ 
emit Bisected(_chainHashes, _chainLength, deadlineTicks);
    }

    function oneStepProof(bytes32 _lowerHash, bytes32 _value) external asserterAction {coverage_0x5f761338(0x07de813b27f79fcff2ed6e5efdc023b97b03ffda8bcb901dfcc47364fd7e437c); /* function */ 

coverage_0x5f761338(0x35d4c64c3a8f1ee3d8f98e29332678f0275d143df638e932ec762ad9cda84378); /* line */ 
        coverage_0x5f761338(0xdddff336cc039fcde21d66118d6b548bb75865642ec338da402636027b0eac6a); /* statement */ 
requireMatchesPrevState(
            ChallengeUtils.inboxTopHash(
                _lowerHash,
                Messages.addMessageToInbox(_lowerHash, _value),
                1
            )
        );

coverage_0x5f761338(0xf9ef0939d6f133429106a22cdf39ec3eb14a174e281ac139740edfbc9bae46f6); /* line */ 
        coverage_0x5f761338(0x7bd23bb15b1625be7bf6d77e7a28c4b8b7f6cf4b1c50a0c16fb5c11a81f5ee93); /* statement */ 
emit OneStepProofCompleted();
coverage_0x5f761338(0x16e9657490844f03d4dc2eb68179876dc16a2515df73253206e06a3262b9ce70); /* line */ 
        coverage_0x5f761338(0x9d6b8960f4b0e95b6184bd691bae9426caf06c545d2198e86af45c29ef5c7f55); /* statement */ 
_asserterWin();
    }
}
