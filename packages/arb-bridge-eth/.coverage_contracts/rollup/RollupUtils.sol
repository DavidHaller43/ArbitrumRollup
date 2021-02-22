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

import "../arch/Marshaling.sol";
import "../libraries/RollupTime.sol";

import "../challenge/ChallengeUtils.sol";

library RollupUtils {
function coverage_0x63b290c9(bytes32 c__0x63b290c9) public pure {}

    using Hashing for Value.Data;

    string private constant CONF_INP = "CONF_INP";

    struct ConfirmData {
        bytes32 initalProtoStateHash;
        uint256 initialSendCount;
        uint256[] branches;
        uint256[] deadlineTicks;
        bytes32[] challengeNodeData;
        bytes32[] logsAcc;
        bytes32[] vmProtoStateHashes;
        uint256[] messageCounts;
        bytes messages;
    }

    struct NodeData {
        uint256 validNum;
        uint256 invalidNum;
        uint256 messagesOffset;
        bytes32 vmProtoStateHash;
        uint256 beforeSendCount;
        bytes32 nodeHash;
    }

    function getInitialNodeData(
        bytes32 vmProtoStateHash,
        uint256 beforeSendCount,
        bytes32 confNode
    ) private pure returns (NodeData memory) {coverage_0x63b290c9(0xd7e88230b56b3c9f841cf611f61bef7c693a3bb5d6302a56dfb4959c6fdbbff2); /* function */ 

coverage_0x63b290c9(0x63446d23bffb8d2c891cff20244a4f5864b69095e70c1c18857fb449b7852bd7); /* line */ 
        coverage_0x63b290c9(0x5c08900f29c809d7af070a7ddd79613b54698965ac7f1e4b5e7d45e73f121a8c); /* statement */ 
return NodeData(0, 0, 0, vmProtoStateHash, beforeSendCount, confNode);
    }

    function confirm(ConfirmData memory data, bytes32 confNode)
        internal
        pure
        returns (bytes32[] memory validNodeHashes, NodeData memory)
    {coverage_0x63b290c9(0xb9650161fda910054bfbd3c2f89ba1847f7c044285e9315d43209b3712f50631); /* function */ 

coverage_0x63b290c9(0x7249b106108278fb63549700361043d22ceb3f32aa348643a8c7ec857ef074de); /* line */ 
        coverage_0x63b290c9(0x45e252441bb7bf20402ffb8428d8d43957be211fcccb063e4b9e4e4ba256eac3); /* statement */ 
verifyDataLength(data);

coverage_0x63b290c9(0xadb1a1e0e499e742b8eb4de6cf652b90924dcc0510e1bf8ed6e59f30c2c93533); /* line */ 
        coverage_0x63b290c9(0xd6663aeb9dc8215b4a670d8e7da65a2eefc3cc2e2a8f5e7f1eee663cb53564f6); /* statement */ 
uint256 nodeCount = data.branches.length;
coverage_0x63b290c9(0x6bab0f86d52831cd01006fecdff6eb6c74f58b4354096df2c2820684a0838707); /* line */ 
        coverage_0x63b290c9(0xfd9c8e29864e0573bf9f6056f110a93e5e59628ed09974a26cb284e348499bf6); /* statement */ 
uint256 validNodeCount = data.messageCounts.length;
coverage_0x63b290c9(0xc6a174d9c05309a83f24abb55535f00b2acda6b5d0ea52cee15b046fee267431); /* line */ 
        coverage_0x63b290c9(0x5bbca21947ab118349448be8a70f6429d77ac206bf9e4f6a56cce82c5ccef955); /* statement */ 
validNodeHashes = new bytes32[](validNodeCount);
coverage_0x63b290c9(0x3490122b34708cd6874958c600d50d3812e50d8d948b5defda29a37ab0b2b2ce); /* line */ 
        coverage_0x63b290c9(0xb89f95dd722b20bb802061f919957451fdecc8d988ba7ee825d21719fe3c1f9c); /* statement */ 
NodeData memory currentNodeData = getInitialNodeData(
            data.initalProtoStateHash,
            data.initialSendCount,
            confNode
        );

coverage_0x63b290c9(0xc151d10d82434d5149d847c8760522d992d70c09bed154c07bfa6cb39a4645c0); /* line */ 
        coverage_0x63b290c9(0xef63a26ccbb925487af44786a1697150fd7bcb3485c70621e490d3d4c45f4986); /* statement */ 
for (uint256 nodeIndex = 0; nodeIndex < nodeCount; nodeIndex++) {
coverage_0x63b290c9(0x7283d6d9546c9ddaca9e012ad6e13050a60cd5d4f3da7425eb30aba96d68e805); /* line */ 
            coverage_0x63b290c9(0x74ddcc0634b45e9b4aa8fd4be894a436186e0db7c1f265a6c0f0649679804524); /* statement */ 
bool isValidChildType = processNode(data, currentNodeData, nodeIndex);

coverage_0x63b290c9(0xa66afd4d00b33453c8681cdef132ad8347a7756b8513c9258d1d77128e6b12b9); /* line */ 
            coverage_0x63b290c9(0xed82b153f7c968a9694c956ad892e987881ead6ed4e78cb9eb64ae13d280f213); /* statement */ 
if (isValidChildType) {coverage_0x63b290c9(0xb1f62885e7008ef34fce111da46703df4e2433a4d59625343c8df5e5e6a63f70); /* branch */ 

coverage_0x63b290c9(0x07d45dfeacdef8347bfd75d022c8563f0eb6a6de6c8f91919a6bcc88b14018cb); /* line */ 
                coverage_0x63b290c9(0x55f5ddf83fa40e9bad43135f8d714abd19c3003d75ab1627b1c99ef5ee931d58); /* statement */ 
validNodeHashes[currentNodeData.validNum - 1] = currentNodeData.nodeHash;
            }else { coverage_0x63b290c9(0xa01ca3d9cc23afd2954c8dcab16d14061bd1c1457d7ec4bae907fef43b321fc9); /* branch */ 
}
        }
coverage_0x63b290c9(0x7e08832f9978a39086a220dd2606cc82dc9d515f578e54b2e4dca642a44acb77); /* line */ 
        coverage_0x63b290c9(0x3fc0b323f869949ab936de9a2f610d310d2ac33316f10e16ee6505020b2005bd); /* statement */ 
return (validNodeHashes, currentNodeData);
    }

    function processNode(
        ConfirmData memory data,
        NodeData memory nodeData,
        uint256 nodeIndex
    ) private pure returns (bool) {coverage_0x63b290c9(0xc7e5fb2a5e738bc9fd41d94f000dc00672d71c18419ebc956d58328812b0378f); /* function */ 

coverage_0x63b290c9(0x76438496f0dec8a2604fd0ee69e3fc0cf6e3289ab538c688b81015c35aaaf97a); /* line */ 
        coverage_0x63b290c9(0xd1530c2b7206f5f347fb024f5b1c71a8e3a3d89e136bb97f1eff38bf1c32ae8b); /* statement */ 
uint256 branchType = data.branches[nodeIndex];
coverage_0x63b290c9(0xf5d5c77c98498772756b2782bdaa9b0b67c0ca289f68905d149b3ff7ac4fdb7d); /* line */ 
        coverage_0x63b290c9(0x4c0ee62e13131507183f760dc1b0fd953c5a607f836837edcb86e676fdd6c708); /* statement */ 
bool isValidChildType = (branchType == ChallengeUtils.getValidChildType());
coverage_0x63b290c9(0xa7d1691ed8afe4ada70eccc183fd232e1b99fa85f263b199072f8e4ec9bf125a); /* line */ 
        coverage_0x63b290c9(0x207c26bb5ed61266fed563684123acf9671452e66af007759918282804ec6363); /* statement */ 
bytes32 nodeDataHash;

coverage_0x63b290c9(0x4c2b9693b4d2d723626ada32593b7598f35950d093e4e258313eb63fe503b925); /* line */ 
        coverage_0x63b290c9(0xfe47b6c0bb80007b362718ee3de30a53c3a1b29487c4528960819fb8c159a0e6); /* statement */ 
if (isValidChildType) {coverage_0x63b290c9(0xa04bff0a471680f16c784f1ecb8a19cfe680475f243f29b536c508c6e43d5eec); /* branch */ 

coverage_0x63b290c9(0xe412e530751027327d1e8be536646ed418e8895ae8da4512a668c6c73b924c27); /* line */ 
            coverage_0x63b290c9(0x07b3b734e0668357f6c94b0940460653574bd9d86e9770d40e0b1d04b4e8c5d7); /* statement */ 
(
                nodeData.beforeSendCount,
                nodeData.messagesOffset,
                nodeDataHash,
                nodeData.vmProtoStateHash
            ) = processValidNode(
                data,
                nodeData.validNum,
                nodeData.beforeSendCount,
                nodeData.messagesOffset
            );
coverage_0x63b290c9(0xe0e04c47d7d4759195f978507cee808e1c89a22750eb5cc0e418cb9243ad67b8); /* line */ 
            nodeData.validNum++;
        } else {coverage_0x63b290c9(0x7e5cb4d37b76748df713048b9c22eff08747e7c43a34b276b9485f99b89b83ca); /* branch */ 

coverage_0x63b290c9(0x24a4acfa0e15afc4b9f0910ecf7088e17644354fc675d9d75fb1d057be7e19da); /* line */ 
            coverage_0x63b290c9(0x797466588f511a080677169d67ae21a1ba0fcc319def9dba7ad6538744a604b7); /* statement */ 
nodeDataHash = data.challengeNodeData[nodeData.invalidNum];
coverage_0x63b290c9(0xae53b4f5b6783ac8a78c42656bc2a466293930f40952db5530e5ed1237edfdc9); /* line */ 
            nodeData.invalidNum++;
        }

coverage_0x63b290c9(0xca5bb8c55d540cba49b846265100cb358f932595ea8370d239251c8e812b8391); /* line */ 
        coverage_0x63b290c9(0x1fc5d493659de523862acc9122b435003114e9f31fd6f402643ef8b8609656a0); /* statement */ 
nodeData.nodeHash = childNodeHash(
            nodeData.nodeHash,
            data.deadlineTicks[nodeIndex],
            nodeDataHash,
            branchType,
            nodeData.vmProtoStateHash
        );

coverage_0x63b290c9(0x521fb4e1a6c32d58135f26937774c02e80a1b5cc853d4bc728fa52a580da42e6); /* line */ 
        coverage_0x63b290c9(0xfd16ffc511bba69fdddc703dc2bbfe19bf55f2e09646610ac89a64cf19c42404); /* statement */ 
return isValidChildType;
    }

    function processValidNode(
        ConfirmData memory data,
        uint256 validNum,
        uint256 beforeSendCount,
        uint256 startOffset
    )
        internal
        pure
        returns (
            uint256,
            uint256,
            bytes32,
            bytes32
        )
    {coverage_0x63b290c9(0x97beb5588a4ef5b17182e7190a0a770e8729113ca8a5176beb00e195d4fc890a); /* function */ 

coverage_0x63b290c9(0xe12243f493945fa6a46b35634b1dea9f0e4d784b9b453c1d34837cda2774ffc0); /* line */ 
        coverage_0x63b290c9(0xb7f177dfe72e5c0aed1fc2644ea778bba805850266b0d6fc7caae82cca9d3a78); /* statement */ 
uint256 sendCount = data.messageCounts[validNum];
coverage_0x63b290c9(0x7442cf6d17fc93442a5d5f09f91f0195300a5cf3d7b16a8f00c42ffdd7f2cf58); /* line */ 
        coverage_0x63b290c9(0x7cee0a6e5edd6f787f15723f47f028b0c2cb95ba4a4b44bf779448ec5301c203); /* statement */ 
(bytes32 lastMsgHash, uint256 messagesOffset) = generateLastMessageHash(
            data.messages,
            startOffset,
            sendCount
        );
coverage_0x63b290c9(0x15f4e006af5637eaf7aba6afb6916827750c895f46ef1d671196c5dd1bfd644c); /* line */ 
        coverage_0x63b290c9(0x9bb7bcebc27b46fd374f6d1e38f7296cb1c7a966255ad25f36c57a8af91049a1); /* statement */ 
bytes32 nodeDataHash = validDataHash(beforeSendCount, lastMsgHash, data.logsAcc[validNum]);
coverage_0x63b290c9(0x1eaffe9fb486c9d084be228aaa83e7f2be19b68db69b66a156439ed900cb426f); /* line */ 
        coverage_0x63b290c9(0x7cd4246dcf99fac5325aee4a2a11e58aea43677072b5a76798206094e564e330); /* statement */ 
bytes32 vmProtoStateHash = data.vmProtoStateHashes[validNum];
coverage_0x63b290c9(0x66ae5ac1d1f3b571299671ca9d26de59f87b952d848570a8ecf0f5517d228b7f); /* line */ 
        coverage_0x63b290c9(0x2df0a16f0826a980711f8ad2c834bfb8a1572f790cf02e544f652e79ba99eebe); /* statement */ 
return (beforeSendCount + sendCount, messagesOffset, nodeDataHash, vmProtoStateHash);
    }

    function generateLastMessageHash(
        bytes memory messages,
        uint256 startOffset,
        uint256 count
    ) internal pure returns (bytes32, uint256) {coverage_0x63b290c9(0xaa14d2810cec2061a0895796abf1a8b7b6a84538f944fb5de0f53da1731272f8); /* function */ 

coverage_0x63b290c9(0x7753a3065c8f2836310b9b265280661ddfa5d5ff8cfe7bb5ec9193f0d373eae3); /* line */ 
        coverage_0x63b290c9(0xdd0901410cee03638f3e2591f23d909761aab93f188c514afeffff3f71b899c5); /* statement */ 
bytes32 hashVal = 0x00;
coverage_0x63b290c9(0x5bb1f2a1fdac791ae80067734d0267926e2149f57eec1334c3019ee028b89fe2); /* line */ 
        coverage_0x63b290c9(0xfe78a7113af519f114a5d5d47350e6cb695343089da6cbbc352b60672c91ee8c); /* statement */ 
Value.Data memory messageVal;
coverage_0x63b290c9(0x17b519c413e276fe34ac570c8a084d5d62a38b845b80239f08ae3c9524ac53a6); /* line */ 
        coverage_0x63b290c9(0x7dc9c233f11968af359f009d770481c5879db4b1974c9b06ceadd63bf392a1aa); /* statement */ 
uint256 offset = startOffset;
coverage_0x63b290c9(0x15e7f95c7e9222ca5b4662678bfd07b6539521758393fe34c0530366350453a8); /* line */ 
        coverage_0x63b290c9(0x5b429952dcc31a927546f3463a515b42a87952422d3721f8bba2b99c3c6c3ef4); /* statement */ 
for (uint256 i = 0; i < count; i++) {
coverage_0x63b290c9(0x1c40d805e299b9de64101b304ce389bb2c5c1cbe684a4399a1bd76c36cc5dfa3); /* line */ 
            coverage_0x63b290c9(0xbc44c1ce8521700b8f86f01e39b51cc4e917867e5e5112f4d9e1f5ddff341a06); /* statement */ 
(offset, messageVal) = Marshaling.deserialize(messages, offset);
coverage_0x63b290c9(0x23c3ad1ee6d302779465b366284d36db357b52bdd5fb9de446fac813ce370402); /* line */ 
            coverage_0x63b290c9(0x2a9d2189c2e5f5726cfc4b2a6807ca8b681fb56d44ea34e443945dd7b6e2f0d4); /* statement */ 
hashVal = keccak256(abi.encodePacked(hashVal, messageVal.hash()));
        }
coverage_0x63b290c9(0xfd21eb0026b6fa7f9d821b3c735ec2b3c8d7b176c7e56eb353710b391014551f); /* line */ 
        coverage_0x63b290c9(0x3759895b0ff3dbf0aa8b24eba86f1883018ed8db83926046b90fc8823d43ba86); /* statement */ 
return (hashVal, offset);
    }

    function verifyDataLength(RollupUtils.ConfirmData memory data) private pure {coverage_0x63b290c9(0x4b52df03e65caadb4370d1d20fcdf89e37d5b4e6497dfdd564701077d93b1274); /* function */ 

coverage_0x63b290c9(0x4e7d8a26b9c81c7e4f9e0088e65737e1a0f530fcdadcccc1f93351c1526e0032); /* line */ 
        coverage_0x63b290c9(0xbc9842b8ef61f6995f896e538e48d661ae1a25779017729911ee192b2203df8d); /* statement */ 
uint256 nodeCount = data.branches.length;
coverage_0x63b290c9(0xbba969f8639ae59cc183b22f3848e701f76dadd863514e9363cc9183cf648df4); /* line */ 
        coverage_0x63b290c9(0x3a3cda5a2e7cc9042a7962f4add797a3fcf17aeb066db15b398713c0b3c6019d); /* statement */ 
uint256 validNodeCount = data.messageCounts.length;
coverage_0x63b290c9(0x9f8096fe49f99098a4746831f0c7b52b2f94f97deacbfb8b0a5aa9ba259598a8); /* line */ 
        coverage_0x63b290c9(0x5022dd4ea7ca3b39b49ed67e31939b429e332f1965bb434cd4d3338e18b9f4ea); /* assertPre */ 
coverage_0x63b290c9(0x360687c5c97cfc75e08b1b58184c558da0e7dc04b41ee1877f5cd4e042380d4c); /* statement */ 
require(data.vmProtoStateHashes.length == validNodeCount, CONF_INP);coverage_0x63b290c9(0xe25c486ee4198c0364be4547f811da5008b34392e769902e25501c8ea6da58c2); /* assertPost */ 

coverage_0x63b290c9(0x7b9d2a320ac0809df51544338659887ef0ad83ef46440f4f7bb277a991d25d7c); /* line */ 
        coverage_0x63b290c9(0xdf80db418715ba6ab33ba80b2700fada95aa7ac10bb8c6cc80d6956a890df5b6); /* assertPre */ 
coverage_0x63b290c9(0xb7a0fcda511572108215a764d8d7e42adbde140cd5e95c6c62e7a3c1e5ef186e); /* statement */ 
require(data.logsAcc.length == validNodeCount, CONF_INP);coverage_0x63b290c9(0x1e9e18785a408ad533c63aada84616342e3fec608d89d025a56e541d9be6032e); /* assertPost */ 

coverage_0x63b290c9(0x2722f1faec55f1f8a902ecbba9395a5d0376d2466ff26fb306f8fdbc3cf7bfb9); /* line */ 
        coverage_0x63b290c9(0xcc5a438f42d1716b95f47a55ab47ed90523d9293b3566862a26d1f1c390aea76); /* assertPre */ 
coverage_0x63b290c9(0x839b7330ef1525c04d8f70597c811229fcf1e1833ec07699bc3d190e5bf468bd); /* statement */ 
require(data.deadlineTicks.length == nodeCount, CONF_INP);coverage_0x63b290c9(0x3866bd7428ca5aef87ba392f8d9676712a6192bf23c513009cfd4617a313e3b9); /* assertPost */ 

coverage_0x63b290c9(0xd9675a83b5e00bffbc2f958567c3190fca1de5833aa0a280640e3f69cab419f3); /* line */ 
        coverage_0x63b290c9(0xf12bafdc33c53353d8586c7c000d64807f36b8355747083e1e58f8a6e3cc51c8); /* assertPre */ 
coverage_0x63b290c9(0xc4f629aa962e11bc11ab2c052ab13d7bb295a488a41453d34acc6af8feef773f); /* statement */ 
require(data.challengeNodeData.length == nodeCount - validNodeCount, CONF_INP);coverage_0x63b290c9(0x1a08dd3e348d9990728d9e869e23cf1eee3f87fa11c7a5ed9c555b4a514480c3); /* assertPost */ 

    }

    function protoStateHash(
        bytes32 machineHash,
        bytes32 inboxTop,
        uint256 inboxCount,
        uint256 messageCount,
        uint256 logCount
    ) internal pure returns (bytes32) {coverage_0x63b290c9(0x5b753810d5df4004ffb6ac6d9047a36e62236ab6ed26ff9f8f2e5bd160f806e2); /* function */ 

coverage_0x63b290c9(0x47176693b81b5bd9f85bb578b7100f5a3a0dfbc8a9a016ce98d0411e235cfd24); /* line */ 
        coverage_0x63b290c9(0x55f8afcfef63aa1cd1d2502701f1c1b6f1c113198065dee54e8493303c2f0330); /* statement */ 
return
            keccak256(abi.encodePacked(machineHash, inboxTop, inboxCount, messageCount, logCount));
    }

    function validDataHash(
        uint256 beforeSendCount,
        bytes32 messagesAcc,
        bytes32 logsAcc
    ) internal pure returns (bytes32) {coverage_0x63b290c9(0x2e6698ac3afc65f15a237de70aa587a9963246dfb13da90bb8107c5c6eebf57c); /* function */ 

coverage_0x63b290c9(0x424b1c73b29e6db82efd2d1f52c176fbcfc51839d4750a4fe9eede480b42a682); /* line */ 
        coverage_0x63b290c9(0xf5448daec791ef8297815c6106dfe5a0294170a61ba6984b9d106d6cc61976a5); /* statement */ 
return keccak256(abi.encodePacked(beforeSendCount, messagesAcc, logsAcc));
    }

    function challengeDataHash(bytes32 challenge, uint256 challengePeriod)
        internal
        pure
        returns (bytes32)
    {coverage_0x63b290c9(0xab5bd313f8153487b73246f5c36055f1850f018a591ea7e2ab4b7898c068b56e); /* function */ 

coverage_0x63b290c9(0xf02ce2d6bea632ecc38c2ba96ef0e53337c1f7abe6f1cd23ae0c6e6ab8e6a70c); /* line */ 
        coverage_0x63b290c9(0x796dc60c5bdefc9fb7592de912e2284b9d3e95b00583e06e138aa22beab34a16); /* statement */ 
return keccak256(abi.encodePacked(challenge, challengePeriod));
    }

    function childNodeHash(
        bytes32 prevNodeHash,
        uint256 deadlineTicks,
        bytes32 nodeDataHash,
        uint256 childType,
        bytes32 vmProtoStateHash
    ) internal pure returns (bytes32) {coverage_0x63b290c9(0xf5874dd51727cb18d4cb126aa5209d0c88d3ae4ba89ab4fcfcdd0398c46370b9); /* function */ 

coverage_0x63b290c9(0x157cafd4c185215582a9bfec7f63ef0d719ebf168516c2d6216b7887ba946144); /* line */ 
        coverage_0x63b290c9(0xd5c2657251cafe2548da0e2cda96dd1400c4b0f675fe0f33a0153be9a7177145); /* statement */ 
return
            keccak256(
                abi.encodePacked(
                    prevNodeHash,
                    keccak256(
                        abi.encodePacked(vmProtoStateHash, deadlineTicks, nodeDataHash, childType)
                    )
                )
            );
    }

    function calculateLeafFromPath(bytes32 from, bytes32[] memory proof)
        internal
        pure
        returns (bytes32)
    {coverage_0x63b290c9(0x31c2602ffe5836d3e8d1b85aef7315f50f8cef4def275f6c6d646f21645e5c31); /* function */ 

coverage_0x63b290c9(0xe9c4ef0a382698cc069300432a1d05bebc8b88492154ff06878937f56ed09206); /* line */ 
        coverage_0x63b290c9(0xf1b1380d0322dc75ef614d20df00c14d8ea22448dd936b3e7f9587370535e77b); /* statement */ 
return calculateLeafFromPath(from, proof, 0, proof.length);
    }

    function calculateLeafFromPath(
        bytes32 from,
        bytes32[] memory proof,
        uint256 start,
        uint256 end
    ) internal pure returns (bytes32) {coverage_0x63b290c9(0x56bbfc43a8eedf22d69e8ceb98269337eace5c79eb9b64b868a03a6caaa9fb8e); /* function */ 

coverage_0x63b290c9(0xfd6bf20ea888de5a2b080aadb34dbf1c7ec942ac03d1f340323e4a8d8def53ef); /* line */ 
        coverage_0x63b290c9(0x8cb12367cf532f8f9e7f9a037fc3bb06ee5df7e59c8f92b6a6ac11190c991fc2); /* statement */ 
bytes32 node = from;
coverage_0x63b290c9(0xd318be12e30892e3daf94b0001e6afae818ced07c0706a9a5c296378cbed8d3e); /* line */ 
        coverage_0x63b290c9(0x6be5756ecc65f0a36e2f5f554d6221db7c0994fac2f4281e4e6d1a4e1acf01e2); /* statement */ 
for (uint256 i = start; i < end; i++) {
coverage_0x63b290c9(0x4ba0d163580cdabaa6094b2bbcdea6476d6337d82cb678bada43c6ae5fd7852a); /* line */ 
            coverage_0x63b290c9(0x6d886ac023f057400433769067fa459e029e3d9e41be7dfc7f22d2b1174fa437); /* statement */ 
node = keccak256(abi.encodePacked(node, proof[i]));
        }
coverage_0x63b290c9(0x8f3c9e6c9b5e7c31ebc2707a61d5e9d8be5e4ac82b14853e750cb2e579620f73); /* line */ 
        coverage_0x63b290c9(0xda38fbc860989fe4b0ec539fd276f0ca1f49331674c9716775eada3d90621e34); /* statement */ 
return node;
    }
}
