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

import "./Challenge.sol";
import "./IBisectionChallenge.sol";

import "../libraries/MerkleLib.sol";

contract BisectionChallenge is IBisectionChallenge, Challenge {
function coverage_0xd237be53(bytes32 c__0xd237be53) public pure {}

    event Continued(uint256 segmentIndex, uint256 deadlineTicks);

    // Incorrect previous state
    string private constant BIS_PREV = "BIS_PREV";

    // Incorrect previous state
    string private constant CON_PREV = "CON_PREV";
    // Invalid assertion selected
    string private constant CON_PROOF = "CON_PROOF";
    // Incorrect previous state

    // After bisection this is an array of all sub-assertions
    // After a challenge, the first assertion is the main assertion
    bytes32 private challengeState;

    function initializeBisection(
        address _rollupAddress,
        address payable _asserter,
        address payable _challenger,
        uint256 _challengePeriodTicks,
        bytes32 _challengeState
    ) external {coverage_0xd237be53(0xed569db8fae6f33858ddc33e7709609db42e83f6a0282a642ec0283ecd2b4088); /* function */ 

coverage_0xd237be53(0x15626b63772430419b20e81d57a32031c8c22ed05c3c5f4b3df52a7dd4e8f5ee); /* line */ 
        coverage_0xd237be53(0xd67aa9b83fa6596bf5817c8c340e9dbd58fd3720c925e3e360e7950078a95f0d); /* statement */ 
Challenge.initializeChallenge(
            _rollupAddress,
            _asserter,
            _challenger,
            _challengePeriodTicks
        );
coverage_0xd237be53(0x342c248440d251be7f33b7974bf6a72e2373210272ca8d16e6e1bd0f815e5a00); /* line */ 
        coverage_0xd237be53(0xb3cb5b8eb33182afc069d7c7478b1271ce5e3d46c0c24471475f52d06662b327); /* statement */ 
challengeState = _challengeState;
    }

    function chooseSegment(
        uint256 _segmentToChallenge,
        bytes memory _proof,
        bytes32 _bisectionRoot,
        bytes32 _bisectionHash
    ) public challengerAction {coverage_0xd237be53(0xf09805e73de6e44e3e288d6f26e3e6755c4c942ad56995d9894a1ac4bcf44932); /* function */ 

coverage_0xd237be53(0x58cc3d00f9b6805cf4a3acf0fa289f9f47d8a6e3eda5162ccd8fb63a67079d1b); /* line */ 
        coverage_0xd237be53(0x2ee1b051353601464e043e0cdfd92304b232ae231e57db9046a5a1e61d5ad79e); /* assertPre */ 
coverage_0xd237be53(0x7f7efb09f3e46f3f68e4e754bc3df39fbbb7638f9c1bbb68556ff1329d0614fc); /* statement */ 
require(_bisectionRoot == challengeState, CON_PREV);coverage_0xd237be53(0x75bbcc753d85e5c25d27214f77ad8ca3cc2bd6c0bebda5952b793e8e52aef40c); /* assertPost */ 

coverage_0xd237be53(0x7ead284189ff935a5d7c174442d33f88a8722ce2d990dfb54da0334ba8e7d6f5); /* line */ 
        coverage_0xd237be53(0x6f22d2aba5e1f187a352ee38914149a61376ce82f148c707079f1a537d15a7d9); /* assertPre */ 
coverage_0xd237be53(0x92385db04b657f2bfa8afa289f3fd514e17fc44f81e3451e49648c8e9169e81c); /* statement */ 
require(
            MerkleLib.verifyProof(_proof, _bisectionRoot, _bisectionHash, _segmentToChallenge + 1),
            CON_PROOF
        );coverage_0xd237be53(0x2e72dabc0cdc0f4bfa9a4e046f774387c0f30649ed7d5fa8aa2a2e27d31046ac); /* assertPost */ 


coverage_0xd237be53(0xdd06e3b0ecd15a71346080bbc8eccfc546258657b0eda7ec2b229018a08d7df6); /* line */ 
        coverage_0xd237be53(0x152005e239b9bd68076a292086ea4ed9a0770089efeb4794c553ef2694a95353); /* statement */ 
challengeState = _bisectionHash;

coverage_0xd237be53(0x3a9f0e9e187b9397dca33022717ee0f2741c92d2b8835dab6e6852075842462a); /* line */ 
        coverage_0xd237be53(0x3b47685509011b0823e46706c52f24f5fb6c781fa9907034e6d33d05513c7bf9); /* statement */ 
challengerResponded();
coverage_0xd237be53(0x1f770c4584e61e36e070160b4fa5df94a6536daa890bf1da5d2cdd108d86139e); /* line */ 
        coverage_0xd237be53(0x61a10934255b49d5c65da0a3139601b0a7421f33f12403fcf589534f2cfbdf11); /* statement */ 
emit Continued(_segmentToChallenge, deadlineTicks);
    }

    function commitToSegment(bytes32[] memory hashes) internal {coverage_0xd237be53(0xeee50ce5301f3dbd1593d1aa1ace489f62de6e82c668b0d86f166e0c7dade81b); /* function */ 

coverage_0xd237be53(0x3d222b6747a7e0448a807cd6db730c95dfaa440e4316a554416bfa232cca3366); /* line */ 
        coverage_0xd237be53(0xfd367f662386aa8c0dbfe0b3960d6cdbf6c3ea5b7874a833bfa0092058833c77); /* statement */ 
challengeState = MerkleLib.generateRoot(hashes);
    }

    function requireMatchesPrevState(bytes32 _challengeState) internal view {coverage_0xd237be53(0xb2aaf7ac141332c336200af5a87c069ba04e5e4d3f0b2ef6fe07f756badbd0fc); /* function */ 

coverage_0xd237be53(0x1301867a9411c2e7fb315aebe8d264fbab15511e9ee1aad5b1b2f36896d35db0); /* line */ 
        coverage_0xd237be53(0x1f276d667d1b7d3e78393a84382cee6a07b58dd8742d4faa6b4cb95171b809ec); /* assertPre */ 
coverage_0xd237be53(0x304776e48fdc2c6c2eb20a877606708b7c9943ac845ce0ed9e1a776f0223dbdc); /* statement */ 
require(_challengeState == challengeState, BIS_PREV);coverage_0xd237be53(0xcf24270c81234f204a3cde8376914380d49787de8e3da888522a722442a4bce2); /* assertPost */ 

    }

    function firstSegmentSize(uint256 totalCount, uint256 bisectionCount)
        internal
        pure
        returns (uint256)
    {coverage_0xd237be53(0x4becd8eac75021a495badfdc92ea4d1e60d67a4da4c6d3c232f60306d458f76d); /* function */ 

coverage_0xd237be53(0x35650cd04379c58a1ca872772a33b6520c7e1800c28e9b9853cadb81e4cb7fbc); /* line */ 
        coverage_0xd237be53(0x5b744dacd66ff2eee967b5875f0c3177ee4b781ae25b5dd81f7cec0c53c75b63); /* statement */ 
return totalCount / bisectionCount + (totalCount % bisectionCount);
    }

    function otherSegmentSize(uint256 totalCount, uint256 bisectionCount)
        internal
        pure
        returns (uint256)
    {coverage_0xd237be53(0xe551847ff0921a515bb70ee32007902bbdd3363034fd356246c01d24cb44c49f); /* function */ 

coverage_0xd237be53(0x28df3d5445e1101a79b62f74d340338d4f6f174c56962cfe4bd2c66f5fe72289); /* line */ 
        coverage_0xd237be53(0x7f155f8bd16bdabbc0689c5f70c6dce3a83757f0332a0e524b75b5f68df02f96); /* statement */ 
return totalCount / bisectionCount;
    }
}
