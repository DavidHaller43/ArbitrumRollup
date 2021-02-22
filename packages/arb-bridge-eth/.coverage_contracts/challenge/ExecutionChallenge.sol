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

import "./IExecutionChallenge.sol";
import "./BisectionChallenge.sol";
import "./ChallengeUtils.sol";

import "../arch/IOneStepProof.sol";

import "../libraries/MerkleLib.sol";

contract ExecutionChallenge is IExecutionChallenge, BisectionChallenge {
function coverage_0x06d0f4ef(bytes32 c__0x06d0f4ef) public pure {}

    using ChallengeUtils for ChallengeUtils.ExecutionAssertion;

    event BisectedAssertion(bytes32[] assertionHashes, uint256 deadlineTicks);

    event OneStepProofCompleted();

    IOneStepProof private executor;

    // Incorrect previous state
    string private constant BIS_INPLEN = "BIS_INPLEN";
    // Proof was incorrect
    string private constant OSP_PROOF = "OSP_PROOF";

    struct BisectAssertionData {
        bytes32[] machineHashes;
        bytes32[] inboxAccs;
        bytes32[] messageAccs;
        bytes32[] logAccs;
        uint64[] outCounts;
        uint64[] gases;
        uint64 totalSteps;
    }

    function connectOneStepProof(address oneStepProof) external {coverage_0x06d0f4ef(0x4fb6502ab671983150d280708b9ccd7b04af043418c927d003bf5a33d8ffe1c8); /* function */ 

coverage_0x06d0f4ef(0x279c5884e84952a587542cfaa6da23ecd4bd00119db65b05868ddd0356e2622a); /* line */ 
        coverage_0x06d0f4ef(0x4b63712e79957e99829fbebd46db41798007c1dcd5d0605b4b72c2ecd401a30c); /* statement */ 
executor = IOneStepProof(oneStepProof);
    }

    function bisectAssertion(
        bytes32[] memory _machineHashes,
        bytes32[] memory _inboxAccs,
        bytes32[] memory _messageAccs,
        bytes32[] memory _logAccs,
        uint64[] memory _outCounts,
        uint64[] memory _gases,
        uint64 _totalSteps
    ) public asserterAction {coverage_0x06d0f4ef(0xaca783054d6502288f5dd5bc4ad4b8f0e6d69280e1527b0e3ea83ff22b999611); /* function */ 

coverage_0x06d0f4ef(0x403e1d0504602186601a1dbdc896e23701907fd6906e65eb8b26ebd4ebcce11a); /* line */ 
        coverage_0x06d0f4ef(0xfed517b91ea83fe57f39ded40c788dea1bef568fa1ea9e53791cf3f22f2b7ee3); /* statement */ 
BisectAssertionData memory bisection = BisectAssertionData(
            _machineHashes,
            _inboxAccs,
            _messageAccs,
            _logAccs,
            _outCounts,
            _gases,
            _totalSteps
        );
coverage_0x06d0f4ef(0x3926215e2fcc78b29ed0cc91055e2c442803b0ed487b9162913538fe63ea0c22); /* line */ 
        coverage_0x06d0f4ef(0xe0ad02222c76367b723ff615633bbbe4b2b97e7600015b08b15d88628f73d1d1); /* statement */ 
_bisectAssertion(bisection);
    }

    function _checkBisectionPrecondition(BisectAssertionData memory _data) private view {coverage_0x06d0f4ef(0x688424b9a38dbaaade5d734690dabcd385cd5163ea1716d24c02290cc8a0e5f6); /* function */ 

coverage_0x06d0f4ef(0xfd4f776acb88647f8283ef89d5be6099a4cbe91b51c6e0368a9b17cfdc545615); /* line */ 
        coverage_0x06d0f4ef(0x4d3dd9d31fac79987c59a0155986dffd8b01056d48444e08712736439dba079f); /* statement */ 
uint256 bisectionCount = _data.machineHashes.length - 1;
coverage_0x06d0f4ef(0x155ade10eb6140461d94b8429b80e08071cf6bb0a7b37cfeaa794e035872a8fe); /* line */ 
        coverage_0x06d0f4ef(0xfa04fab7fb3e3183f630e0145ad7775ab8380c4ba7904a2dc159ec3e66f549ee); /* assertPre */ 
coverage_0x06d0f4ef(0xbb48e8cbf9314dac1e6a1861259de388d7a03fc8c5a2a988f45cbb7b0a6ba79d); /* statement */ 
require(bisectionCount + 1 == _data.inboxAccs.length, BIS_INPLEN);coverage_0x06d0f4ef(0x2f43f517f780f0a1637207ffc6749e829e6be8abe266dc469884a6d6a029f6f4); /* assertPost */ 

coverage_0x06d0f4ef(0xb0d56cae432df0cfdfbed4aa59286707e11a76a4663a2fcc8a1befe34dd0c0bc); /* line */ 
        coverage_0x06d0f4ef(0x9895d64b573d3e976e5fde72716af6b125d870713bb0aebde108e49794fab80f); /* assertPre */ 
coverage_0x06d0f4ef(0x59ed9f8121581406655f2045e951966a0d8ec8ec611c5d27ec38d96edc11b403); /* statement */ 
require(bisectionCount + 1 == _data.messageAccs.length, BIS_INPLEN);coverage_0x06d0f4ef(0xf7e922a67d05855071f6585dc9c26da90c20cb1266e2392e8a4f89241696553c); /* assertPost */ 

coverage_0x06d0f4ef(0x3b2c76751379a75364eee2b7ae20626e070cd82954b0ad004bba9fe4608927bb); /* line */ 
        coverage_0x06d0f4ef(0x913ad12a79ee6b4575636e381dc75b89e588e76aec9e881a1f685f2866652ab4); /* assertPre */ 
coverage_0x06d0f4ef(0x938a326889ceb41a6a9a0feac5bbbfc1fdae38c25a53f57568cf0acd1231db4e); /* statement */ 
require(bisectionCount + 1 == _data.logAccs.length, BIS_INPLEN);coverage_0x06d0f4ef(0xe3e8fb0be60d9229c1f4dc5c3f81881b380665bed0d0a1fc7e4d11af73c79f62); /* assertPost */ 

coverage_0x06d0f4ef(0x4f27c57a14112f758c1bfbbc9f3485b2faef13b34e7fbd1be6ff45e3ec258e3a); /* line */ 
        coverage_0x06d0f4ef(0x664b7d7b4c572b1924180aad2cb8b9ce1f12610e4e8f3d36fc11c9b2be5575b5); /* assertPre */ 
coverage_0x06d0f4ef(0x17e43bf8829e673a869964bb615347adaec1d5929612d2c1eb3722bdf8489931); /* statement */ 
require(bisectionCount == _data.gases.length, BIS_INPLEN);coverage_0x06d0f4ef(0xfdeeecf09ba83e2bca3002b83495616466b3b1b943d93c196e878d099460b203); /* assertPost */ 

coverage_0x06d0f4ef(0x1bbaeeb15ea2f5446677eebaed23ae41b0c3a2136435584a78dd0d5a5e0273b8); /* line */ 
        coverage_0x06d0f4ef(0x0744b2aeba96d598bed724b7fcd990cd001ef52cc935416a8f5581c5572a630a); /* assertPre */ 
coverage_0x06d0f4ef(0x0cddc8f56a3a3fe1fc28d3aba0ac490d9d24c39f3537f765f2c7255f3935fa75); /* statement */ 
require(bisectionCount * 2 == _data.outCounts.length, BIS_INPLEN);coverage_0x06d0f4ef(0xac03473e31aa4eb6fc3b2b41351d15fc26b7bf3f5b34ba552cd50db84de7a05f); /* assertPost */ 

coverage_0x06d0f4ef(0xfff68735e0229188ebeeb34a61105d04393686f6c2dd0d99382215ba1eea33c7); /* line */ 
        coverage_0x06d0f4ef(0x7745addee59e2d422d53e69ee75b605dbc788f3de793162a00f75d381f2f66e3); /* statement */ 
uint64 totalGas = 0;
coverage_0x06d0f4ef(0x3c0aea219632ea1742bcfba8ca9780c1e7e32f92beb796074f12f85f434c8a36); /* line */ 
        coverage_0x06d0f4ef(0xf0f09bb459a34432b90971ceafca5691944edcd9e3f465c8c15814f531472573); /* statement */ 
uint64 totalMessageCount = 0;
coverage_0x06d0f4ef(0xb9d92fc55c30510d140b608f249efd9c101f63cfe5c8a5233c6b35b71e7ca477); /* line */ 
        coverage_0x06d0f4ef(0x6a637985e6aca5f583117ffd3238b2e13ee65e6529946ea41932938ea05c46ba); /* statement */ 
uint64 totalLogCount = 0;
coverage_0x06d0f4ef(0x0732dbfcf50948abad1a4e9e0ab12cd5064b2bd4465d3f343deb34b30510951a); /* line */ 
        coverage_0x06d0f4ef(0x329a032cd25d31ccc51289f1aa3a164c033ee32a569c6e2aca05e3eb57a555ce); /* statement */ 
for (uint256 i = 0; i < bisectionCount; i++) {
coverage_0x06d0f4ef(0xca7a2cc0115cb8a4228337d822c0b3e44d7f8673d859085d4726ef5ac4cc34b8); /* line */ 
            coverage_0x06d0f4ef(0x4c01ae453063fef0bfa318a23babf822fde75a5360cd94b4829632ce54bc00a4); /* statement */ 
totalGas += _data.gases[i];
coverage_0x06d0f4ef(0xf3dedec569ac58449286b7f53c6ba78f565e468e4166834e1847a0ceaf747f8f); /* line */ 
            coverage_0x06d0f4ef(0xd17575918971b33ae98a4b29a06f5079019e5b3a1a497bbad9b17e8e8b51117b); /* statement */ 
totalMessageCount += _data.outCounts[i];
coverage_0x06d0f4ef(0xd13d1e0f1ea413973a94420462189094dd883b99ee368440c15db6a9a42b9651); /* line */ 
            coverage_0x06d0f4ef(0x94bc4bc66d7277e7380342058ff493a8a84d9b7f1201ed800e46a2cae35986a2); /* statement */ 
totalLogCount += _data.outCounts[bisectionCount + i];
        }

coverage_0x06d0f4ef(0x7ae3719f31697dbb0624be19e53614bdb106402aa56475b06c1aa7871c819aba); /* line */ 
        coverage_0x06d0f4ef(0xd4e0990aa5e23db7e3ff6367578f088cf59c21cb78fbb61f30dbbf35441814aa); /* statement */ 
requireMatchesPrevState(
            _generateAssertionHash(
                _data,
                _data.totalSteps,
                0,
                bisectionCount,
                totalGas,
                totalMessageCount,
                totalLogCount
            )
        );
    }

    function _generateBisectionHash(
        BisectAssertionData memory data,
        uint64 stepCount,
        uint256 bisectionCount,
        uint256 i
    ) private pure returns (bytes32) {coverage_0x06d0f4ef(0xfd5260284b1786df5dcf498f7a96b86118325c2d68a9e5ad561751cafb78d162); /* function */ 

coverage_0x06d0f4ef(0xe8df15b113d4ccd34714d9c648b07e3c9c889a79a7e4b0901dd10807b9952233); /* line */ 
        coverage_0x06d0f4ef(0xf8731435b2b6531de2d732271d6fcb3ca5aa9557d042fe4027806be97e356b42); /* statement */ 
return
            _generateAssertionHash(
                data,
                stepCount,
                i,
                i + 1,
                data.gases[i],
                data.outCounts[i],
                data.outCounts[bisectionCount + i]
            );
    }

    function _generateAssertionHash(
        BisectAssertionData memory data,
        uint64 stepCount,
        uint256 start,
        uint256 end,
        uint64 gas,
        uint64 messageCount,
        uint64 logCount
    ) private pure returns (bytes32) {coverage_0x06d0f4ef(0x1cc8252642402fd609c357c171d9538543636f934a854a42bc5806c05316bbc4); /* function */ 

coverage_0x06d0f4ef(0xd5d2b979d391603c964af976ab7593b4c1f0190ca998d8016f1934fb85539a2b); /* line */ 
        coverage_0x06d0f4ef(0xe536daf6aa2843dcd32272ccd3a2934ce7fa53125f9e237905238b80cbb56364); /* statement */ 
return
            ChallengeUtils
                .ExecutionAssertion(
                stepCount,
                gas,
                data.machineHashes[start],
                data.machineHashes[end],
                data.inboxAccs[start],
                data.inboxAccs[end],
                data.messageAccs[start],
                data.messageAccs[end],
                messageCount,
                data.logAccs[start],
                data.logAccs[end],
                logCount
            )
                .hash();
    }

    function _bisectAssertion(BisectAssertionData memory _data) private {coverage_0x06d0f4ef(0xd00ac0773f7c8d7e339dab425e59a625241d4338b060d548b680bddc9849655e); /* function */ 

coverage_0x06d0f4ef(0x1ce09f549ff7d22142cd4574858e89762da28d9b58da202ef94364c04f9aa93b); /* line */ 
        coverage_0x06d0f4ef(0x79ebd83adfd940eb482a9fdf71a549d4baf96686c0df090ca717fd10f4860856); /* statement */ 
uint256 bisectionCount = _data.machineHashes.length - 1;
coverage_0x06d0f4ef(0x76cef6f9b12055ddb92731003e5271c06a61076a27e52bc9b0bd510d1f812d91); /* line */ 
        coverage_0x06d0f4ef(0x8f529edbc06244b2ff1c926c92e70a981b461e91b45a28faa1958db0f7d28cf8); /* statement */ 
_checkBisectionPrecondition(_data);
coverage_0x06d0f4ef(0x033ff520a185b198ea6feeaeac95af53a49d90e9b6cd0c8f7cfbc9ede926b390); /* line */ 
        coverage_0x06d0f4ef(0x4a0ffd2cecb6d168f80ec328e6f5b1655f241e4521b297fa424f82f5386726ef); /* statement */ 
bytes32[] memory hashes = new bytes32[](bisectionCount);
coverage_0x06d0f4ef(0x694978b210a3538f583ea3d64bec7c974a140d7f526d548feed8b0d27c3d73cd); /* line */ 
        coverage_0x06d0f4ef(0x4c8a385225f75b173fe9d08beb5bd0a655bb800c66d44ece1767b6303cbe3359); /* statement */ 
hashes[0] = _generateBisectionHash(
            _data,
            uint64(firstSegmentSize(uint256(_data.totalSteps), bisectionCount)),
            bisectionCount,
            0
        );
coverage_0x06d0f4ef(0x83af8357c100e16a32efcbf517e5d0c651fcea4c84b44890f1927784acbd647c); /* line */ 
        coverage_0x06d0f4ef(0xdfadd1e75a9c6be7ba1bdff9ea664c1cbeda64b8bf50d1807316553452b8a876); /* statement */ 
for (uint256 i = 1; i < bisectionCount; i++) {
coverage_0x06d0f4ef(0x3c5456d31de1db652e6d256a43f0968db6200c3b3c0ddb6bb53bf14118f45e0a); /* line */ 
            coverage_0x06d0f4ef(0xfae1196a68081ee6b19269aef7e4411025982141c7d3eb45b346fdae39f0a71b); /* statement */ 
hashes[i] = _generateBisectionHash(
                _data,
                uint64(otherSegmentSize(uint256(_data.totalSteps), bisectionCount)),
                bisectionCount,
                i
            );
        }

coverage_0x06d0f4ef(0x46dedabc99df0fd8a12da6def9c97de3d6e329d106ec71466bfd3d93a1857804); /* line */ 
        coverage_0x06d0f4ef(0xd800d2a4750a8c702fd28f9381516b960bd0dbcdca428bbcc94193ce610ef524); /* statement */ 
commitToSegment(hashes);
coverage_0x06d0f4ef(0xe1e6daedc51b98161da0debd58ace723dfc2feff3803a0621278311bc8724848); /* line */ 
        coverage_0x06d0f4ef(0xfcdab17d75a48d82ad18650518c66235ed65262787588169991a4bfb462a7bf4); /* statement */ 
asserterResponded();

coverage_0x06d0f4ef(0xaf142c9f772aabc1892ef7a584fc61d6149ce451b17d0d1702cab2ccb2d4576b); /* line */ 
        coverage_0x06d0f4ef(0x09b5783f37e625e4b9b097b0f46b127deb3346d0822ce3e1bb6d10393a11264e); /* statement */ 
emit BisectedAssertion(hashes, deadlineTicks);
    }

    function oneStepProofWithMessage(
        bytes32 _firstInbox,
        bytes32 _firstMessage,
        bytes32 _firstLog,
        bytes memory _proof,
        uint8 _kind,
        uint256 _blockNumber,
        uint256 _timestamp,
        address _sender,
        uint256 _inboxSeqNum,
        bytes memory _msgData
    ) public asserterAction {coverage_0x06d0f4ef(0xc8680ab6333c1dfd4129f63485a2b47ba65023e566d32c51a84f0b49d23cb63d); /* function */ 

coverage_0x06d0f4ef(0x04fe7f20b021ad5bd1887dda212e845ba097f1da43276b2f339505cfb06e4d2d); /* line */ 
        coverage_0x06d0f4ef(0xcd73d9a29025e22c9d0b1850004327f5c10bd74365c351fc68b89fed5b9d9833); /* statement */ 
(uint64 gas, bytes32[5] memory fields) = executor.executeStepWithMessage(
            _firstInbox,
            _firstMessage,
            _firstLog,
            _proof,
            _kind,
            _blockNumber,
            _timestamp,
            _sender,
            _inboxSeqNum,
            _msgData
        );

coverage_0x06d0f4ef(0xe1395ca359e6e930549164b7c0eff384d8ad18858354be1b4b430ca847cb8545); /* line */ 
        coverage_0x06d0f4ef(0x10ce357119cbe9a756545d4833bc47f9500df3d7a721e4585cf6055aa3a0c570); /* statement */ 
checkProof(gas, _firstInbox, _firstMessage, _firstLog, fields);
    }

    function oneStepProof(
        bytes32 _firstInbox,
        bytes32 _firstMessage,
        bytes32 _firstLog,
        bytes memory _proof
    ) public asserterAction {coverage_0x06d0f4ef(0x3e17f94b929d52259b3774442d3d68c296e860e21b33c573058df4358ba8492d); /* function */ 

coverage_0x06d0f4ef(0xdc434330c77f7db42524dd04a46d124f653d50eb4f7608510d74f3df42244402); /* line */ 
        coverage_0x06d0f4ef(0xb323a8c6a9aba7f9773cba15cc9a25c472b989414462711a23e24795bc14476f); /* statement */ 
(uint64 gas, bytes32[5] memory fields) = executor.executeStep(
            _firstInbox,
            _firstMessage,
            _firstLog,
            _proof
        );

coverage_0x06d0f4ef(0x09683c5cd1ac45feb6263c7e5b688ff4a86cdfe0e5f3b23a45dd1c1156059907); /* line */ 
        coverage_0x06d0f4ef(0x99d90bdc94bc84771fb63e91cf3e6246516a10beaba9ffa8e722e0fc810cb340); /* statement */ 
checkProof(gas, _firstInbox, _firstMessage, _firstLog, fields);
    }

    function checkProof(
        uint64 gas,
        bytes32 firstInbox,
        bytes32 firstMessage,
        bytes32 firstLog,
        bytes32[5] memory fields
    ) private {coverage_0x06d0f4ef(0x2e98482a8149ea9ada306849a82ffadcd4745dc87e8e9680105add76f5a77577); /* function */ 

coverage_0x06d0f4ef(0x56f8977c32ae247dbc4db28edf4c3954d05d5c602b35fd627a381ddcbfede48c); /* line */ 
        coverage_0x06d0f4ef(0x4c7c4cd759a04f8cd52c94069f4638eff65451e22c769c72b5b1bdd9828aa7b4); /* statement */ 
bytes32 startMachineHash = fields[0];
coverage_0x06d0f4ef(0x715b9a87339654fc8914b93471678649158fd5258dce59601644dd5ecf5925e9); /* line */ 
        coverage_0x06d0f4ef(0xe784b6266c56493492da3d837c10282f20e9b26c16ff69e0fe80edae68e31c38); /* statement */ 
bytes32 endMachineHash = fields[1];
coverage_0x06d0f4ef(0xa9e04b09ae71063bfa4bfc67e4da4826bb9f426149a7770f8538b748dbc35b37); /* line */ 
        coverage_0x06d0f4ef(0x117c084dca7f196e0b81a141bbf3584504146640eea30752308ff3b90e8ed466); /* statement */ 
bytes32 afterInboxHash = fields[2];
coverage_0x06d0f4ef(0xeb3defcfc5c445c4b12280e7a23db50547de842c53cbb77733ed2f9712cf5523); /* line */ 
        coverage_0x06d0f4ef(0x8d96e5edf46acf9dfadf6fde414f4e259f2a65f8613077942fefec995a48ab36); /* statement */ 
bytes32 afterMessagesHash = fields[3];
coverage_0x06d0f4ef(0x80d6001b1ff79f3187c15583cbd902746f46bea2ba0fb3c4ad253c963908a2a1); /* line */ 
        coverage_0x06d0f4ef(0x4768fb50a322957dcbb2aa59f65814a974eaaf4544fddb2303274e65f7b4a467); /* statement */ 
bytes32 afterLogsHash = fields[4];
        // The one step proof already guarantees us that firstMessage and lastMessage
        // are either one or 0 messages apart and the same is true for logs. Therefore
        // we can infer the message count and log count based on whether the fields
        // are equal or not
coverage_0x06d0f4ef(0x7f0f53988f4a8e4d9b0542e8138b9b6de1c5b7fabc717be4a31331555424ac59); /* line */ 
        coverage_0x06d0f4ef(0x339d43a380ac05a1ab6ec009fc71d1c6acae57ed3bb860ff51f223fceaf53fec); /* statement */ 
ChallengeUtils.ExecutionAssertion memory assertion = ChallengeUtils.ExecutionAssertion(
            1,
            gas,
            startMachineHash,
            endMachineHash,
            firstInbox,
            afterInboxHash,
            firstMessage,
            afterMessagesHash,
            firstMessage == afterMessagesHash ? 0 : 1,
            firstLog,
            afterLogsHash,
            firstLog == afterLogsHash ? 0 : 1
        );
coverage_0x06d0f4ef(0xee0787550eadf032ddd8eea250df00ee59ea72b4deac48e2eb2e13bfbf728996); /* line */ 
        coverage_0x06d0f4ef(0x6df9490f64f7680717c225e59f7f543121599685172ad866d4d3af25d7efbfa6); /* statement */ 
requireMatchesPrevState(assertion.hash());

coverage_0x06d0f4ef(0x1e022f256ed1c975256ff6c324c78d95a649d04445ac1c7520b69888b690dcb1); /* line */ 
        coverage_0x06d0f4ef(0x9632de33e7cfeb66fa7fef95bd7bf703681716c087628d98eecaf36ffb4ab0af); /* statement */ 
emit OneStepProofCompleted();
coverage_0x06d0f4ef(0x0296fdfaa99da8c0ab000f00bcee6bd8c2289305ec2835465aee0af8333298c2); /* line */ 
        coverage_0x06d0f4ef(0xa70e57d203106e8010162b4f94f9a6d74f73625c441ca62865ea2e8dca4e685f); /* statement */ 
_asserterWin();
    }
}
