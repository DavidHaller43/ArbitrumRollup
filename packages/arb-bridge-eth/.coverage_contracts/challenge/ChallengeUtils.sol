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

library ChallengeUtils {
function coverage_0x84104f58(bytes32 c__0x84104f58) public pure {}

    uint256 public constant INVALID_INBOX_TOP_TYPE = 0;
    uint256 public constant INVALID_EXECUTION_TYPE = 1;
    uint256 public constant VALID_CHILD_TYPE = 2;

    function getInvalidInboxType() internal pure returns (uint256) {coverage_0x84104f58(0x6a67646a2625981085d879f42be358955b165cef60418e4e84b78f4fb70a72f6); /* function */ 

coverage_0x84104f58(0x96c4a7354fa4937a511997861091e86385e63c3eb67e5f5d8abb9154fff6087c); /* line */ 
        coverage_0x84104f58(0xd593cfe5ffb6a4a6819fa2922aa77daaee0d56dc9709037a86c4ab811ed57af5); /* statement */ 
return INVALID_INBOX_TOP_TYPE;
    }

    function getInvalidExType() internal pure returns (uint256) {coverage_0x84104f58(0x1365d6183bb397a6e2159e9e9a9c29746f0f9f11103cb2021407289ce4dbd79f); /* function */ 

coverage_0x84104f58(0x41034e62ed3c940e58c9c1e0827f4f30411569cf458279f085f97a66d0e9e33e); /* line */ 
        coverage_0x84104f58(0xaf912f26dc9814ddadaeb3b02d4102c6f724cb14e56f18d181be9d7e3c351999); /* statement */ 
return INVALID_EXECUTION_TYPE;
    }

    function getValidChildType() internal pure returns (uint256) {coverage_0x84104f58(0xad3b8098093609ee987ee9f187929212e4d9f5c6cd08764af24d937ba8a7aba7); /* function */ 

coverage_0x84104f58(0x0585f4c98387d8f5a1f8c0a304a0487734d1f7a1f527f81bab831aae59e9cf7d); /* line */ 
        coverage_0x84104f58(0xd7c5cae4362614ee36a7c8092f724404c192021c00211b243e9ae6854c509049); /* statement */ 
return VALID_CHILD_TYPE;
    }

    function inboxTopHash(
        bytes32 _lowerHash,
        bytes32 _topHash,
        uint256 _chainLength
    ) internal pure returns (bytes32) {coverage_0x84104f58(0xe17cbc141f8287b72a50ab25340117290bdf4e94da4053082a38f0e8efbd8e43); /* function */ 

coverage_0x84104f58(0xf5e29479ea5b22d2b9787840e7ee566df7501107327126960ead25293815f134); /* line */ 
        coverage_0x84104f58(0xb1230632bdd6804e3e2d5bfa56b37081c499ff6eeba4376b0da05bf5fb749f36); /* statement */ 
return keccak256(abi.encodePacked(_lowerHash, _topHash, _chainLength));
    }

    struct ExecutionAssertion {
        uint64 numSteps;
        uint64 numArbGas;
        bytes32 beforeMachineHash;
        bytes32 afterMachineHash;
        bytes32 beforeInboxHash;
        bytes32 afterInboxHash;
        bytes32 firstMessageHash;
        bytes32 lastMessageHash;
        uint64 messageCount;
        bytes32 firstLogHash;
        bytes32 lastLogHash;
        uint64 logCount;
    }

    function hash(ExecutionAssertion memory assertion) internal pure returns (bytes32) {coverage_0x84104f58(0x02cab0eb21b30507e321cf572847febbd07815ceb067c3b6cac698bd70a51da1); /* function */ 

coverage_0x84104f58(0x608763fbcfedac601f3f7741aa123fa3530be84ee991253496470c897d581db4); /* line */ 
        coverage_0x84104f58(0xd42fc37361e423f35008d6a01678f9de85a3f18812d92eac7187f47a96d14852); /* statement */ 
return
            keccak256(
                abi.encodePacked(
                    assertion.numSteps,
                    assertion.numArbGas,
                    assertion.beforeMachineHash,
                    assertion.afterMachineHash,
                    assertion.beforeInboxHash,
                    assertion.afterInboxHash,
                    assertion.firstMessageHash,
                    assertion.lastMessageHash,
                    assertion.messageCount,
                    assertion.firstLogHash,
                    assertion.lastLogHash,
                    assertion.logCount
                )
            );
    }
}
