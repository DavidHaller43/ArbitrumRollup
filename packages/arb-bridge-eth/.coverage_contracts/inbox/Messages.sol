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

import "../arch/Value.sol";
import "../arch/Marshaling.sol";
import "../libraries/BytesLib.sol";

library Messages {
function coverage_0x112a22e7(bytes32 c__0x112a22e7) public pure {}

    using BytesLib for bytes;

    function messageHash(
        uint8 kind,
        address sender,
        uint256 blockNumber,
        uint256 timestamp,
        uint256 inboxSeqNum,
        bytes32 messageDataHash
    ) internal pure returns (bytes32) {coverage_0x112a22e7(0xb607609e01277c2faec014eb8c11d180f4e3d9d4fe2ee79c9cbf552b26081813); /* function */ 

coverage_0x112a22e7(0x52b037405632ae0aef47f6a6ecc54e660149b49b784c86665ecd4bfbfa414b9d); /* line */ 
        coverage_0x112a22e7(0x6efb7bb4374e48615f32e88854c3bd17f73f634bdbe14e57db02a570b6011745); /* statement */ 
return
            keccak256(
                abi.encodePacked(kind, sender, blockNumber, timestamp, inboxSeqNum, messageDataHash)
            );
    }

    function messageValue(
        uint8 kind,
        uint256 blockNumber,
        uint256 timestamp,
        address sender,
        uint256 inboxSeqNum,
        bytes memory messageData
    ) internal pure returns (Value.Data memory) {coverage_0x112a22e7(0x9fb600c428fa8a0c0bc82776412431a70c11d76cd440af36e33b685dc1cf5c90); /* function */ 

coverage_0x112a22e7(0xd3835091a09bd94edbeede6e0e3d2a254304dd2d62c77028072ab0ebc4cdfd75); /* line */ 
        coverage_0x112a22e7(0xafc79726164532298d69718c3491530dedbb9e4ecec492a7a41c88936a158314); /* statement */ 
Value.Data[] memory tupData = new Value.Data[](6);
coverage_0x112a22e7(0x0d011d3ee2851606c4ff8d97c411e910093955ac180b6acdba81aca2adfe8658); /* line */ 
        coverage_0x112a22e7(0x24f64a7c48e955e0da930355af525fd8d93840480a1d669ee3d635cc0ec47eaa); /* statement */ 
tupData[0] = Value.newInt(uint256(kind));
coverage_0x112a22e7(0xf43209c4d7e106d9a4fc2ae5a0aa207d13c47fb6f34abab793b7ba07786a897b); /* line */ 
        coverage_0x112a22e7(0xb06123880eff8a6b5672b44f21f2b97538947e98f8af39372b23b6680a1ba167); /* statement */ 
tupData[1] = Value.newInt(blockNumber);
coverage_0x112a22e7(0x9258ca6c00be54fdb3141388d26911422940d3b047141bcf9598182f6ad32e3f); /* line */ 
        coverage_0x112a22e7(0x8402a1f238a1022ad77e7876cef9164d6fa7f87e3ada1b2ccbbae445a51b3aa5); /* statement */ 
tupData[2] = Value.newInt(timestamp);
coverage_0x112a22e7(0xfa1fe75d17ca90c3dfeecfbb8ce4b9539331e46d3500609b51d9e208dc865a06); /* line */ 
        coverage_0x112a22e7(0x672a062c7d35299ab416d27fba4107dba6308eb530f5be976a5267074ed31cbf); /* statement */ 
tupData[3] = Value.newInt(uint256(sender));
coverage_0x112a22e7(0xe552c1b2ee96f6a9964ff04bfa844e2ecf399c7371007b1456d413054c1442b4); /* line */ 
        coverage_0x112a22e7(0xac2934997e942af3a82ad10f8b367ae88aa0a08955e634e093c8079562e03f17); /* statement */ 
tupData[4] = Value.newInt(inboxSeqNum);
coverage_0x112a22e7(0xa37f4d72dd51e8e90b9b61f089a9797231a2d3a77d2863525b505babe1cf2e1c); /* line */ 
        coverage_0x112a22e7(0x864f384719c58c296ca57467b1c4baa86761ef30d5781cae44c05879ad65531a); /* statement */ 
tupData[5] = Marshaling.bytesToBytestack(messageData, 0, messageData.length);
coverage_0x112a22e7(0x073c03061d7e1ec5a73e8d88a211109088b943125d5578f45b0a408b44d1b864); /* line */ 
        coverage_0x112a22e7(0x21a401a03778af30b785014c2e13f5c768b24b6247077c1871a04c6627189e32); /* statement */ 
return Value.newTuple(tupData);
    }

    function addMessageToInbox(bytes32 inbox, bytes32 message) internal pure returns (bytes32) {coverage_0x112a22e7(0x12a4114fe1d55e290387576d0c61f1347967cf6b90964e3b6af25ffa71a0f193); /* function */ 

coverage_0x112a22e7(0x7dc3c96def723e1209634366082d3e4963144b6568758a1e769f7d1beb3cb84a); /* line */ 
        coverage_0x112a22e7(0x7cc7854ba171c33cf5b157681c1264684338ef56b6847fb6b149ddc37d153a84); /* statement */ 
return keccak256(abi.encodePacked(inbox, message));
    }

    struct OutgoingMessage {
        uint8 kind;
        address sender;
        bytes data;
    }

    struct EthMessage {
        address dest;
        uint256 value;
    }

    struct ERC20Message {
        address token;
        address dest;
        uint256 value;
    }

    struct ERC721Message {
        address token;
        address dest;
        uint256 id;
    }

    uint256 private constant ETH_MESSAGE_LENGTH = 20 + 32;
    uint256 private constant ERC20_MESSAGE_LENGTH = 20 + 20 + 32;
    uint256 private constant ERC721_MESSAGE_LENGTH = 20 + 20 + 32;

    function unmarshalOutgoingMessage(bytes memory data, uint256 startOffset)
        internal
        pure
        returns (
            bool valid,
            uint256 offset,
            OutgoingMessage memory message
        )
    {coverage_0x112a22e7(0x77c47c949cbb3c44d9574fbc12d549e6c86da5c41b0710f931225a1378a02155); /* function */ 

coverage_0x112a22e7(0xd637b81d8d943fc610087ce80b165e5e1308ec9e5b2ec1d2a6353e9baa2f5952); /* line */ 
        coverage_0x112a22e7(0x1f066d60e1ddc882188264d215bb1fd6c637f1831d5d12f5f1bec249080f5dab); /* statement */ 
offset = startOffset;
coverage_0x112a22e7(0x99bfe6cfe978737b11ec21e223804f3482d7d641621786d6196f2ab99add9597); /* line */ 
        coverage_0x112a22e7(0xae98d114b7ecdfc5d6469dbd4e945813168d8792ead9c1ca91806fc1cfc60679); /* statement */ 
uint8 valType = uint8(data[offset]);
coverage_0x112a22e7(0x7ae6efd8fc2aa9dfc907ba97932b9d8a66f7818d8a68e3bc1c348d2c9496f747); /* line */ 
        offset++;

coverage_0x112a22e7(0x643bb8fd1b7a8c9e2ebfccc38c63c3b68f7b13e0491c7bcba18c84d27650f1a4); /* line */ 
        coverage_0x112a22e7(0xa010690752d2288f7497abe97d125f8e49a83bb6c0ab106604351c9c95934b63); /* statement */ 
if (valType != Value.tupleTypeCode() + 3) {coverage_0x112a22e7(0x6812f9f1c5c56e883605d61a624cac114d2d44afa1d6d1b4d036b13937a75b6d); /* branch */ 

coverage_0x112a22e7(0x6374fcda839b9d48d68f673efcb5ecb6f3f7953de02cb1ff52abd3b2b0fb2ea6); /* line */ 
            coverage_0x112a22e7(0x4be39e2b78a9b5001a74d608022ecd8c7ab56447def79aa979cd5a4ddb03556d); /* statement */ 
return (false, startOffset, message);
        }else { coverage_0x112a22e7(0x689e42564cc438624fce28e4eec749b67c2ddb49587f4de577856948821d588e); /* branch */ 
}

coverage_0x112a22e7(0x71536edd07cc27cdfd364f06d5dde322862fc08b806a89381b3fc7f6217f348d); /* line */ 
        coverage_0x112a22e7(0xccb693e7b3de5f9a2563572311407c1e640865e886d325f71580d5aaf147bae2); /* statement */ 
uint256 rawKind;
coverage_0x112a22e7(0x4b5e557a64669ed88ba888de4339133aea537d858b68cb265221427e8a36f63e); /* line */ 
        coverage_0x112a22e7(0x81ed17aed0ea8da10886cc30a8981889d5e63e3e633726b73ff1cd95a5ed5536); /* statement */ 
(valid, offset, rawKind) = Marshaling.deserializeCheckedInt(data, offset);
coverage_0x112a22e7(0xffa0fd141489053e7b115f8ca79332c9dae846a373fbdc5eea939975ef4a8b89); /* line */ 
        coverage_0x112a22e7(0x4f4ec06aae43855e3511d2fab83fa37fb3928eb33179f0c77a7bb356295fffcb); /* statement */ 
if (!valid) {coverage_0x112a22e7(0x1988a2ccb639fcc2377cc527740b7e2c753f66fb8471047f8f7c7a3615332cac); /* branch */ 

coverage_0x112a22e7(0xb9c268920d62e674464223412f123205c88c40d1520051780433dc3f8e920053); /* line */ 
            coverage_0x112a22e7(0x10e8ef8f14172a5aae51f6c42a095664822b7e9eec474923aa28e3cd5de21ec4); /* statement */ 
return (false, startOffset, message);
        }else { coverage_0x112a22e7(0xc70fe8a076c17f5f94c05479d42b3305c27a90d3354a0f2e27018765e1cdb743); /* branch */ 
}
coverage_0x112a22e7(0x3860c952aaeade8ab1aec9910b7a5d0f9f78978c4fa72a24c805248cfb692dd7); /* line */ 
        coverage_0x112a22e7(0xb69a14b90d14cefceca359bc1ef80eae3c06146d1c4ece0c0f35e5285dc0f061); /* statement */ 
message.kind = uint8(rawKind);

coverage_0x112a22e7(0x62abd32c1b22039813dc888eac20e3996162c44cbfc2a21b26c66aaa86df9a18); /* line */ 
        coverage_0x112a22e7(0xcfef1d0f475d70e79adab2ea094be314f30b78e079488d1c531f21ad5480a4d0); /* statement */ 
uint256 senderRaw;
coverage_0x112a22e7(0x52a6c21ebf1550da336583048c7c13c55850a137d4b57464ef4b829a032c0a3d); /* line */ 
        coverage_0x112a22e7(0x90eb2d782d8cbfeca324aa4bb38946b32e2a966dee2d6394050ac139adb802cb); /* statement */ 
(valid, offset, senderRaw) = Marshaling.deserializeCheckedInt(data, offset);
coverage_0x112a22e7(0x0ac9c288bce7eecc157267ea4e4db4c2509cd198975ca4a9d049f1d744dc1685); /* line */ 
        coverage_0x112a22e7(0x2b7ebd5562583159d38fbdb702830ec0507eff34ab30c81fb710523e9d6ea23c); /* statement */ 
if (!valid) {coverage_0x112a22e7(0x83f3a743f81adc67e8863844fed78d507201d8211548f8f0afc72cc4f641c717); /* branch */ 

coverage_0x112a22e7(0xb74f156c3d2e315e64716c11be652ff54578b23e3d8ae89e27e3df18fbfb8919); /* line */ 
            coverage_0x112a22e7(0x70a732c2832a86ea6b9afaf38cf03455652547bffe41cf6c241866112c62ed95); /* statement */ 
return (false, startOffset, message);
        }else { coverage_0x112a22e7(0x5c4e0568a469794407fdbfd7ced76389da3c19061d876b52e62ae1bba842f73d); /* branch */ 
}

coverage_0x112a22e7(0xb0863271e3248babcce39f09a12877fb258b60c657b299fdfeae42549ca0a2e5); /* line */ 
        coverage_0x112a22e7(0x42ce83a3b3adc33f6b9956e0a974af7c52d5d86783573d6adbd65b5697f3eb36); /* statement */ 
message.sender = address(uint160((senderRaw)));
coverage_0x112a22e7(0x7739f4c7eb3447db6ea91358b83f9d7770bf3a30452432ad0b2ca2e76d83d9fe); /* line */ 
        coverage_0x112a22e7(0x8948b870c85204d137a4640733adfc3ea8f7c43d413eaa57368ac9d4831378c5); /* statement */ 
(valid, offset, message.data) = Marshaling.bytestackToBytes(data, offset);
coverage_0x112a22e7(0x33970472b2305531b1da5cf74603e24b2a367ad7b37afb207034b375a1e33743); /* line */ 
        coverage_0x112a22e7(0x6196620eb2560ff9188d3bd020220156e308649608dd2d9e75e46d8cb01a3717); /* statement */ 
if (!valid) {coverage_0x112a22e7(0x9fc65918ff2050024bb7ec3e577c0348cdcd0607da3ba0b73caa42c7bf606ff0); /* branch */ 

coverage_0x112a22e7(0x3a514220cd4fc9b21b50bf3cd461a9bd3df863f5e89867eea0286abf367be7af); /* line */ 
            coverage_0x112a22e7(0x5825395947a13b8c8e42d6a0edd2ecde277a985af5992469979b3c01db10243d); /* statement */ 
return (false, startOffset, message);
        }else { coverage_0x112a22e7(0x7ab057674cd84ce57cb9fdcdea0100c097a10ca6b49f75f1f56c40e306908c5e); /* branch */ 
}

coverage_0x112a22e7(0xdd46f6c9aafba59cc504755844ee9fcd17d96434d013156b0dcb82f0b3e481f4); /* line */ 
        coverage_0x112a22e7(0x6c2b2a37ac185b5144c43cf65fcd7f90bcc4f485993b6675e18bb123071b87fe); /* statement */ 
return (true, offset, message);
    }

    function parseEthMessage(bytes memory data)
        internal
        pure
        returns (bool valid, Messages.EthMessage memory message)
    {coverage_0x112a22e7(0x411316f90f3ab92c587ef2f6653c12f13c700469278dcc816c830b012408fa5e); /* function */ 

coverage_0x112a22e7(0x3ec00ff9c1bb28cfbd551d32165e45376dd6df0bf1a790f44362bc73f91b16c2); /* line */ 
        coverage_0x112a22e7(0x3d714214b1cd315d2f343a7e82d31aa27f10895267890bd6273593d7a986ba4d); /* statement */ 
if (data.length < ETH_MESSAGE_LENGTH) {coverage_0x112a22e7(0x33875b472330cdb23d02dc78998be926423482b57cf4a03a087296e85a3a8689); /* branch */ 

coverage_0x112a22e7(0x8622cec6ef2fc4c97f438e2104e2350015b57ee0ae59c3661a39331476ec2c09); /* line */ 
            coverage_0x112a22e7(0xcbe4da50892bd37cd1437db683dad6c770932632a4e90f497b442e5a53e2a742); /* statement */ 
return (false, message);
        }else { coverage_0x112a22e7(0x490720cc76cc863e9b1caf59c4877e2c9a79fa27f0aba47363bfeaef93392fb3); /* branch */ 
}
coverage_0x112a22e7(0x4353c61071178e8e4fbb08de922c3ec92c745f7788da5120afc2102d5dbfb3a7); /* line */ 
        coverage_0x112a22e7(0xfe64833d4d21188a47e7658e0a73ee42670bc7dff2df6a6ba6904ee38c36d31d); /* statement */ 
uint256 offset = 0;
coverage_0x112a22e7(0x54d9f5303ede64b8fe1e05d61a3052c2095f6ca2ee7bdcddb3c8a015f870484d); /* line */ 
        coverage_0x112a22e7(0x10f52cf4ea9d2346fae0de95852d325d2f4d5d605940c5a369555d271e4c6bbb); /* statement */ 
offset += 12;
coverage_0x112a22e7(0xc09efe084c4624fd2fbf1ef08b9bd1246d9f7eba456f683604aa4e6bc1b7038a); /* line */ 
        coverage_0x112a22e7(0x77e6ff07b54310fe10e1fcee96aee76975fe71b7b139ac3d3555ce0c46bc11e5); /* statement */ 
message.dest = data.toAddress(offset);
coverage_0x112a22e7(0x2c5c5699d1e57472aa7b0470550f3d40ad664e396d7972d2c4a9891f37efe886); /* line */ 
        coverage_0x112a22e7(0x8b9bce5900c8bbc054ab011a75081515dd334206325fe68ccd9bcc95c00dad40); /* statement */ 
offset += 20;
coverage_0x112a22e7(0x65fa193be8b5ba5157834aab9c9346113f787ed3acd35c6b65584cba20eb35ab); /* line */ 
        coverage_0x112a22e7(0x987802c98db6776799b9a9b02f6adf53ce284d8baeaa64380fd80c1a46b4ed95); /* statement */ 
message.value = data.toUint(offset);
coverage_0x112a22e7(0xa6bc9d97a104c47788786b600177d6f55bf0b0532d691600a2a4fa66191450d3); /* line */ 
        coverage_0x112a22e7(0x6d7f5e27933cc0b39a58796853ebf325a5565f01d2c3c24be814c71c9634fe91); /* statement */ 
return (true, message);
    }

    function parseERC20Message(bytes memory data)
        internal
        pure
        returns (bool valid, Messages.ERC20Message memory message)
    {coverage_0x112a22e7(0x6cdb25e316195ae6b42ed7e1b9a98a70fe7f28b74ecfc47bba6cb981bfd844f4); /* function */ 

coverage_0x112a22e7(0xc7bf714f1febd0c6414d60839260b04637080ecf4150844e3cd9c5767a29a746); /* line */ 
        coverage_0x112a22e7(0x49053fba94949e7f7b590db6756adf859231dc81f7b289a2f2f2b636e99f7042); /* statement */ 
if (data.length < ERC20_MESSAGE_LENGTH) {coverage_0x112a22e7(0xd86b128a42aad0357b34ce98c8f473ef2aba220f465c7e85f23b44722a5cb1dc); /* branch */ 

coverage_0x112a22e7(0x3bde016ad86c8366d00645d8070d556ecbd8af2ae27b2091d60d2ae861f80bd6); /* line */ 
            coverage_0x112a22e7(0x80220a351dd2b7dc814591c94c069d062fec435afd5d986e9db37c4246928890); /* statement */ 
return (false, message);
        }else { coverage_0x112a22e7(0x750662111bff6700ef7bb723824d4301a1b6619ff04db2f51fdeb242472ffc45); /* branch */ 
}
coverage_0x112a22e7(0x7828c41f4a7b1da45254322baf98cafc519afd3cf570e3871127aa45df96f579); /* line */ 
        coverage_0x112a22e7(0xbcf5da5b050e5a8b936a30e3475c7728826aeed86d32fae01a0b60ccbcbe8135); /* statement */ 
uint256 offset = 0;
coverage_0x112a22e7(0x0bf6d2e9077ee229122c9df9f26b4d33c1aa184ee1a925fb7174f672dc0fd4e1); /* line */ 
        coverage_0x112a22e7(0x964f66abfe0ba9986b313b70b79bb004360a26a21a16204dee79292215d6beed); /* statement */ 
offset += 12;
coverage_0x112a22e7(0xdf8e3bfe6552a67ac665df52ec1c8d088941b0da30d7449cfa32aab0f2b4722c); /* line */ 
        coverage_0x112a22e7(0x39bf070c2a1ed1743fdccd0677cb1e0611013d8c13794773459f697e78933a85); /* statement */ 
message.token = data.toAddress(offset);
coverage_0x112a22e7(0xc4ef220e24a6af77f9a99ef14057c4ec83d965130bc80045e177d6b967997661); /* line */ 
        coverage_0x112a22e7(0xf5764abe2e34ddec154db63994e0d71f2465d35e4b0a036c15368f178bd97222); /* statement */ 
offset += 20;
coverage_0x112a22e7(0xf7f1a76e814cab9c3d9f18a4c4533e0c99658a5737d4d9c9937d4ef182d10b4e); /* line */ 
        coverage_0x112a22e7(0xe54aac95467be16794546ce845a8caf6ed2b06d4d309836b78924c6c3588d170); /* statement */ 
offset += 12;
coverage_0x112a22e7(0xd6080a995461dcc8862dcc4dec0a69cbcdc84fecf513e5fb101e6835ecbcc6f0); /* line */ 
        coverage_0x112a22e7(0xb07a130898f23090d58d60dae6b6473efbdc9d41c24dbd258232d162375b1d3f); /* statement */ 
message.dest = data.toAddress(offset);
coverage_0x112a22e7(0x3e65845acbf23d028e06753d735f8b7c7929244d5334e44e0a33d929df8ff8bd); /* line */ 
        coverage_0x112a22e7(0x9271f86c9c0615c7a993152917fcba2587322b943c8af877a2beb43c0e1930cb); /* statement */ 
offset += 20;
coverage_0x112a22e7(0x5631d36c5a7c4c6a996c93cd2c9bc60e5b4a7310580dbe2a4b02462418c683c0); /* line */ 
        coverage_0x112a22e7(0x014463f048755014d2db8a89dc939f3432ad17aa08fdd1d5c6ab3c02c5f963b7); /* statement */ 
message.value = data.toUint(offset);
coverage_0x112a22e7(0x8983e908f2c3cbda44cc5522c9f0de7057508c2dae56bb04a599f8d2e20bd6b3); /* line */ 
        coverage_0x112a22e7(0x037de4cd48bcfabe99a9580e65bfb90325f2e23353f21ce8ab17b99df5a4a81d); /* statement */ 
return (true, message);
    }

    function parseERC721Message(bytes memory data)
        internal
        pure
        returns (bool valid, Messages.ERC721Message memory message)
    {coverage_0x112a22e7(0x7c8b16c1bdf02f3e36f8d81be7685c664e50d251a8fde5571a86dcc6443d6181); /* function */ 

coverage_0x112a22e7(0xa3c978ba918f652d4f0fc0ee7db5d9bc7ee2a61e98835f46e15e556a4bfe348a); /* line */ 
        coverage_0x112a22e7(0xf75492cd7333b68369c134778a8e2e35ca3d912befa3c3628a53cf9e9143d54d); /* statement */ 
if (data.length < ERC721_MESSAGE_LENGTH) {coverage_0x112a22e7(0xac5e8583679dcd951f054dbd04f564d57e13755b4d545b3cd0dcc92ad1b50158); /* branch */ 

coverage_0x112a22e7(0x83523bc94b503cf74a94465fb8d812f05510b3396b1b9f2285aaa85018a97b22); /* line */ 
            coverage_0x112a22e7(0xe01b45a5f9cae01e9cae6813ff6bd87ed933deac06b743ce6f99962d515af252); /* statement */ 
return (false, message);
        }else { coverage_0x112a22e7(0x0fe8a7d8b86d22bee992f7f55c1832bdcdf93ffa090189331ebfd21dba3b8466); /* branch */ 
}
coverage_0x112a22e7(0x96543088e25ea94130bdafec6a64feca07ae52e28aef98df19562fc4c68ae803); /* line */ 
        coverage_0x112a22e7(0x8b6aed299a243490a53ce837803ee4f3424e49ff91ba084e8a3e10b0f85b8856); /* statement */ 
uint256 offset = 0;
coverage_0x112a22e7(0x78fba2dbaf3e56b9916ebfcb7e30c0d15ea296fbddabb7a1734549173e76b33b); /* line */ 
        coverage_0x112a22e7(0x1bd470d9fb20cac20010d7c12b1e2d4c2a15a2df8bbfcf8724ca16e10726430b); /* statement */ 
offset += 12;
coverage_0x112a22e7(0xd2b46cb2c0379554266a9b4752cfda2f3d95fbf6d4e455bc2456795b482d0759); /* line */ 
        coverage_0x112a22e7(0xe852985869ad66042173ee37a5cbf39af4c3e6ad27d2b0581108956750b2138e); /* statement */ 
message.token = data.toAddress(offset);
coverage_0x112a22e7(0xc2ea733e8914b5e7602854b6bc80401755000dbcfd5d2aebd3c8a4534ca0215b); /* line */ 
        coverage_0x112a22e7(0x8d335d7cb50d172d518f0baf040be9801da93851e08a5029c9050292ae244713); /* statement */ 
offset += 20;
coverage_0x112a22e7(0x4e9a61126df732184baa24485bb42006996b404d1aa3af3c89a6810d0bfea7b7); /* line */ 
        coverage_0x112a22e7(0x572e5a4eaf3167fdb9c27cb30270fd9cffc00f3759a31f44d0fcf3a480c5fe3b); /* statement */ 
offset += 12;
coverage_0x112a22e7(0xd08f94e0e7d3af355e8b3ba5a25aded4a2527260f23cbc625a219997f3ab0318); /* line */ 
        coverage_0x112a22e7(0x8ff824c96092ec71321af553f2caf346712cbc07b1f47e39c65a7362ca5eb531); /* statement */ 
message.dest = data.toAddress(offset);
coverage_0x112a22e7(0x182aa1afdfeb226821d59f91f7b9679efa2dce75db5dd7570510696b3e9e7a9a); /* line */ 
        coverage_0x112a22e7(0x415053379961642ab8250381bb79b8df1657c262bc4db82625722a41ad75abf9); /* statement */ 
offset += 20;
coverage_0x112a22e7(0x8ec352ba8ed14f1391b101c7afeb3a7763351bc8972611fc292c835cf34ada4c); /* line */ 
        coverage_0x112a22e7(0x8e7a5a92797bb1d0476cf079e9c4a13af803f7c1a72ea107faf411bf489ff276); /* statement */ 
message.id = data.toUint(offset);
coverage_0x112a22e7(0x7e77d7695ff3d34412911767c7d23a9103152c54a9c538de798dd0389e6c82d6); /* line */ 
        coverage_0x112a22e7(0xe6f0a8a89401818fb3684cce56711e6a83b9f7afe3223f580dd2a04bd99e76d6); /* statement */ 
return (true, message);
    }
}
