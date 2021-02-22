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

import "./Value.sol";
import "./Hashing.sol";

import "../libraries/BytesLib.sol";

library Marshaling {
function coverage_0x914c86c7(bytes32 c__0x914c86c7) public pure {}

    using BytesLib for bytes;
    using Value for Value.Data;

    function deserializeHashPreImage(bytes memory data, uint256 startOffset)
        internal
        pure
        returns (uint256 offset, Value.Data memory value)
    {coverage_0x914c86c7(0x5d2b4ee3ffa2910c97d4f898bb59994098cefbdc0e928a1f656a7c0c466f0bf4); /* function */ 

coverage_0x914c86c7(0xfecbf0d01e97079d10547f71f2a6540ceb8fb2b1d86cef71d9cd89fba973dbd8); /* line */ 
        coverage_0x914c86c7(0x4440a6de63f11c694dde7743c9d9fc3d3d322103985ab3ccdf163b4650069491); /* assertPre */ 
coverage_0x914c86c7(0xeb7996433ed4e54ac06211af7a74c8bb65d5b8bad52694242545a591c2a57362); /* statement */ 
require(data.length >= startOffset && data.length - startOffset >= 64, "to short");coverage_0x914c86c7(0xa747a04c2c8bc4b340839e92a00de1416c5c789d70294ca37cb564059fb94506); /* assertPost */ 

coverage_0x914c86c7(0x87ccf8df13c41d509479c850580d4a43860e882558a41f30786fbd80186c8c67); /* line */ 
        coverage_0x914c86c7(0xf497e3a48441fc2cbf81b696cd9ad1b2111227f59b81faf4cf4b0ad705c8bd50); /* statement */ 
bytes32 hashData;
coverage_0x914c86c7(0x55d8c92a38a0ba828cfe172593a3faba96c382c8ea3403a964573ac7661e7044); /* line */ 
        coverage_0x914c86c7(0x3293eca8ae075719d9d0dbefe3c1942de0bb6febb1dee97b15e28563e70787f4); /* statement */ 
uint256 size;
coverage_0x914c86c7(0x882840d9a24888ea8f6aab253d4b97a2c6df1c9a6cc599f06f1bd6e302c0a490); /* line */ 
        coverage_0x914c86c7(0x188a42b8656d09c2296c63dd551d65f75b6986dcafba2276271fbd224d5cbc6c); /* statement */ 
(offset, hashData) = extractBytes32(data, startOffset);
coverage_0x914c86c7(0xfd515a169f98a83e4398b2f32c91ed11b6c152ce6082d1e50f8ef3030df24190); /* line */ 
        coverage_0x914c86c7(0x28187d7dc6483bbfc142469178202d6f0c3aa0aea9d54cb2c8679f49a5cc174b); /* statement */ 
(offset, size) = deserializeInt(data, offset);
coverage_0x914c86c7(0x9a14bbd1f86787abde7ac8451780fbc73b235f4c0575b47dd27aad1b89b568b4); /* line */ 
        coverage_0x914c86c7(0x9ae85667b30e01c60a45422ef876b6cbe7896995ecf33121d98241620b9179f7); /* statement */ 
return (offset, Value.newTuplePreImage(hashData, size));
    }

    function deserializeInt(bytes memory data, uint256 startOffset)
        internal
        pure
        returns (
            uint256, // offset
            uint256 // val
        )
    {coverage_0x914c86c7(0xbddfafaf8b9ba7e36e7e38ed84eafff38a47473c391a1eebc40b24c81f8b2a0c); /* function */ 

coverage_0x914c86c7(0x6440d0ec2673687d6c31e766b50a44e8e9171086d939ebcb77c90860c0184ae6); /* line */ 
        coverage_0x914c86c7(0x53d7444c453f3f1a1cf1ea992ba73a743773e82c7e3e93802a9c1b4f68227121); /* assertPre */ 
coverage_0x914c86c7(0xa07fe0bfff175e27fd3a2157ff3ff78041c65fc7393a5ced6dc3b0244e6bc597); /* statement */ 
require(data.length >= startOffset && data.length - startOffset >= 32, "too short");coverage_0x914c86c7(0x6a86693408847729d8c1b5f8e288fc3f1f47204aad669e043dcc145f53bc4da5); /* assertPost */ 

coverage_0x914c86c7(0xe88f82c3f2048bcd6e1e57f98ae4d601f15e101efbcbe00b0db9d75e5ba130fb); /* line */ 
        coverage_0x914c86c7(0xc6b343785a0e7441a24650c9d1df18b19841ded4b3c2e61ca886a4577fb11272); /* statement */ 
return (startOffset + 32, data.toUint(startOffset));
    }

    function deserializeCheckedInt(bytes memory data, uint256 startOffset)
        internal
        pure
        returns (
            bool, // valid
            uint256, // offset
            uint256 // val
        )
    {coverage_0x914c86c7(0x3a2e04e44ebd5381d44efa26046a84323484515eefd8e4dbcfbece9743b0ab2a); /* function */ 

coverage_0x914c86c7(0xe5ee89f1997df038efa0d29fa75de07c023334084b2258cee1cc20319d31f6f1); /* line */ 
        coverage_0x914c86c7(0x64f46d8ddada96259de3354a307dceb15340fd8efcd4789cf95dea4712bbe518); /* statement */ 
uint256 totalLength = data.length;
coverage_0x914c86c7(0xf9c870e293bdd7c791d29c26dce9f5095474a6f5436c010d50005041e45f3012); /* line */ 
        coverage_0x914c86c7(0xe974ef8a687baaf61a1e015c949b75eb0aa92377fdd27c0ff93656ccdde046b2); /* statement */ 
if (
            totalLength < startOffset ||
            totalLength - startOffset < 33 ||
            uint8(data[startOffset]) != Value.intTypeCode()
        ) {coverage_0x914c86c7(0x5a2e361b574a80a8daa482d749a9684e66084a4e70a28982de853e65ca18d00a); /* branch */ 

coverage_0x914c86c7(0x8967a9262ded1143b0a587d5e74deeeb4340a8c32dc5cf2237c79ec9f7ffd223); /* line */ 
            coverage_0x914c86c7(0x99541a524f32f1645e818c931858245f74a8156a8e23f873fd85216e12fa7b69); /* statement */ 
return (false, startOffset, 0);
        }else { coverage_0x914c86c7(0xcd7231e2081806b7527c90abb313e9f444808b93a75e9d0410ac7c55d73a87b1); /* branch */ 
}
coverage_0x914c86c7(0x4568ff41dec9482b0fa9e135d73909d8edbaad0899682591d5660e9b97b00cd6); /* line */ 
        coverage_0x914c86c7(0x12a00c449da6d140834499ee332ef7e5d3df4cffb83209109bf476039858feab); /* statement */ 
return (true, startOffset + 33, data.toUint(startOffset + 1));
    }

    function deserializeCodePoint(bytes memory data, uint256 startOffset)
        internal
        pure
        returns (
            uint256, // offset
            Value.Data memory // val
        )
    {coverage_0x914c86c7(0x4f76f0cfe3adfb4c8b606bfa768ea390f90bbee8167148d17d966c2161b10865); /* function */ 

coverage_0x914c86c7(0x9233d5c464e8de56b89126e83d7ef6db44f3dc0d21571cbc70e1a98f99608f9a); /* line */ 
        coverage_0x914c86c7(0x5c51710627e1c0a19058eb37d007a6dacbe1e0fbd616f1858019c77a82152704); /* statement */ 
uint256 offset = startOffset;
coverage_0x914c86c7(0xcb91e95fffa39ccb2fd21af9c66bad115690ed3de4d3622e784daada53198c3b); /* line */ 
        coverage_0x914c86c7(0xc7f7a5005eeb086875fde8cec191cddef3387b6131cb3efb1fd4c414bc74e53c); /* statement */ 
uint8 immediateType;
coverage_0x914c86c7(0x6f7cb935f8aeac79f5969dcdd18e07b149104bc31b7aa10ca9ba337942babc56); /* line */ 
        coverage_0x914c86c7(0x9a3bf9a5ed448b45fd182c78a87fd56774753a9fc803b261bd9b3efec4c52804); /* statement */ 
uint8 opCode;
coverage_0x914c86c7(0x7696000bbcc6e74fa7cff1ba773e9b4a9ecc06ed567f43807766401136770c4c); /* line */ 
        coverage_0x914c86c7(0x7447526b3822e42dc64edf9afdef775545f8f131e22fec0efcd1c3dd044619f5); /* statement */ 
Value.Data memory immediate;
coverage_0x914c86c7(0x6512b83c5fa7437f3c9f37c331e568faa932ebe35aed13879b199b69d2797dfa); /* line */ 
        coverage_0x914c86c7(0x78355ca423d26b259237ffe28092f2d2871ac480fe5b70a728f2c4cc07882aef); /* statement */ 
bytes32 nextHash;

coverage_0x914c86c7(0x3c7c61c25c1ec166f81918622efebd33d8ab803434431f8ee7c12df3ca0d16fb); /* line */ 
        coverage_0x914c86c7(0xcdd5b89c5303765b706ba66f2462d74c36a2147b5d8f0eae201cef6817999e61); /* statement */ 
(offset, immediateType) = extractUint8(data, offset);
coverage_0x914c86c7(0xfd8ed237acba414bbe8689c3f9045bf1629b716ce801b17b4b1ebda196d27e04); /* line */ 
        coverage_0x914c86c7(0xe02080fd71b61364e8f291b4486c9e395cce17f6c6c44fd0e847f69007e27aa8); /* statement */ 
(offset, opCode) = extractUint8(data, offset);
coverage_0x914c86c7(0xdf50ceef217f9fd84529724a48591eb2f6e4cb442bc761f1240ee284f0f6b485); /* line */ 
        coverage_0x914c86c7(0xdc8adc19219c47ed2fddae6e8b9ef5a557a43769f24489487253abd06b92da93); /* statement */ 
if (immediateType == 1) {coverage_0x914c86c7(0x2226b245ab689f50f9e9a8fe7a873ad22e7be41f627b0dfd17eb1b69c9597766); /* branch */ 

coverage_0x914c86c7(0x6026c1297b4159ecc523d590f5c35495a0b085d7ca4ea5d55e8b6aa98079613b); /* line */ 
            coverage_0x914c86c7(0x6c05f31b70c36c58cdb715c22e226b7623e9f5bdb13c6970972fc43ff5ceed08); /* statement */ 
(offset, immediate) = deserialize(data, offset);
        }else { coverage_0x914c86c7(0x7ee0b8238b3090f2e551b9fa95d37efbc7f5c05bbfb8b2e50096137984543f2a); /* branch */ 
}
coverage_0x914c86c7(0x26eb012445f60e9379695b1dd16ca7f2480b809e32dfec6f737d78bf47415abc); /* line */ 
        coverage_0x914c86c7(0xe609241b1d6ea1bfdbf1b9bd858c08f6df302ccc95103168dd9ab2063b02d5f9); /* statement */ 
(offset, nextHash) = extractBytes32(data, offset);
coverage_0x914c86c7(0xda02fd8a8913d187998aaf395af8dd42bb167c915921f403d2b07cd2e1956244); /* line */ 
        coverage_0x914c86c7(0x04a68661db18a7e841052693b1b57af3f266c0010cf4f3f3491dba35a4928652); /* statement */ 
if (immediateType == 1) {coverage_0x914c86c7(0xb7f522b51d9528ad04984bd1514298c8db192f17f669a16fe5a619243dc20eaf); /* branch */ 

coverage_0x914c86c7(0x5a4c801b845882db7cd7eefc99408b84b08885470cda3c897b0a9c43ccb5de2a); /* line */ 
            coverage_0x914c86c7(0x320f3fe264e7f14462be98b1f4c8a7c7ee539ab21fc529514bd4c93253b55e6d); /* statement */ 
return (offset, Value.newCodePoint(opCode, nextHash, immediate));
        }else { coverage_0x914c86c7(0xa5cd5213e69844f9a169a09ab2b8180749f3344d9c2aede8f913879c505cdb4b); /* branch */ 
}
coverage_0x914c86c7(0x5cc0f7738dfe45c85185d2d4af185946e482dbf821b71237e03a191c4031e532); /* line */ 
        coverage_0x914c86c7(0x1da9f07a9c6e59428afba9321b9fedb4771aecc41da7ad0f27eb743e2af8a8c1); /* statement */ 
return (offset, Value.newCodePoint(opCode, nextHash));
    }

    function deserializeTuple(
        uint8 memberCount,
        bytes memory data,
        uint256 startOffset
    )
        internal
        pure
        returns (
            uint256, // offset
            Value.Data[] memory // val
        )
    {coverage_0x914c86c7(0xda107d784de9d15d215de3e719758fae5c8dc092adfa2612e00b389fa9cc2fbf); /* function */ 

coverage_0x914c86c7(0x27c73ddbffd6edf5cee79195dc04bf44c1d079e04041dfbb494b7da6c95c6535); /* line */ 
        coverage_0x914c86c7(0x5559a3c974acecd48a121832b7d422916a11ce344653597630dd9b52028fd933); /* statement */ 
uint256 offset = startOffset;
coverage_0x914c86c7(0x8158719e781040ba0e50b9e13a8add9c21e8dcb8ae72de829d519f47e6fdc85c); /* line */ 
        coverage_0x914c86c7(0x647bff00bbe1a122287ac1a91e86f69d8b199bc82866662414279e6ab78028fe); /* statement */ 
Value.Data[] memory members = new Value.Data[](memberCount);
coverage_0x914c86c7(0xc8894b19b3eade0157ef9eaefd4e4d2082f571162aa09c2350f14523f3eb217d); /* line */ 
        coverage_0x914c86c7(0x82db8aa567ec5c86994eb4365ec775d069398610f92e0e1e71eb7e591b61c30e); /* statement */ 
for (uint8 i = 0; i < memberCount; i++) {
coverage_0x914c86c7(0x5136485d3dc29af555c628020cfda3f735c4d6bf256aa3c2124816fb40221207); /* line */ 
            coverage_0x914c86c7(0xe090720a41ce9477ac3051d8844225f53ad68749f28d0012ba32b8adf34bdad3); /* statement */ 
(offset, members[i]) = deserialize(data, offset);
        }
coverage_0x914c86c7(0xe7233e32da4178664547e94da3cc1ed3f4881eeec353ecedd3c76034188f08f6); /* line */ 
        coverage_0x914c86c7(0x1ba6e9069e847ec9b793e8edcbbd1170095925e72a649569f0dd973f9841122a); /* statement */ 
return (offset, members);
    }

    function deserialize(bytes memory data, uint256 startOffset)
        internal
        pure
        returns (
            uint256, // offset
            Value.Data memory // val
        )
    {coverage_0x914c86c7(0x96134c7e48ce3e62c435668d8ad04c23130780df705d7ed4519278f3c811c48e); /* function */ 

coverage_0x914c86c7(0x2f4c3ae9e69092d0ba7b9b72bdef744b9002161c486a5a7a2571d034279233a5); /* line */ 
        coverage_0x914c86c7(0x3632d3e92e0c4daba33345c014aa7c1de8fa88ec6dbcaf5be9dad453741ef88c); /* assertPre */ 
coverage_0x914c86c7(0xb7dc5602341d0b1e0c6cf69f2bceb0f9d2d86552590eded3469b7dafed51b166); /* statement */ 
require(startOffset < data.length, "invalid offset");coverage_0x914c86c7(0x88cc66f035214764f9cab3dab4aaf7f3304d158aaf3635ab0e4f26fb3454f498); /* assertPost */ 

coverage_0x914c86c7(0x44c7b43ff3ee090b190951671b2b8fc4efb601f13b3f8c3d33ec9472fc00069d); /* line */ 
        coverage_0x914c86c7(0xe2871aa626289f44da1d3d453e93e0dd2217ec19e87f28f10112f8a26183bd09); /* statement */ 
(uint256 offset, uint8 valType) = extractUint8(data, startOffset);
coverage_0x914c86c7(0x00266620a02615cdf87ee31f5e2eaa702024233e571a25f4f7a8b54918480d11); /* line */ 
        coverage_0x914c86c7(0xee8bb414d21551777d8fcd9f79d59d2506f5be91173ea20526257dbd863d1162); /* statement */ 
if (valType == Value.intTypeCode()) {coverage_0x914c86c7(0x32456a43f97fef296b15df6c07520fcd7223a6b6bdf0914a8f37725c7224c3ee); /* branch */ 

coverage_0x914c86c7(0x97f4f19f0042d6ac91e2987e29c8b23c8293bf908b285b9b1c9ff99877d72892); /* line */ 
            coverage_0x914c86c7(0x5942264c1ae37f53dd213de79ebebaf83af850c285df2316543d1e36d321f4b8); /* statement */ 
uint256 intVal;
coverage_0x914c86c7(0xdcf62e0b14dbd4363c258ec28b109e47d85b48811f9402a31b7fb593863d8fe9); /* line */ 
            coverage_0x914c86c7(0x22484701a188885193b18847e67eb46f6dfcf5b2793a178fecad7813b3369a58); /* statement */ 
(offset, intVal) = deserializeInt(data, offset);
coverage_0x914c86c7(0x2bd59c3a29d3915183d9dc9e255038fe5eb8e3d77b3f9c95b40f64a7c26262a3); /* line */ 
            coverage_0x914c86c7(0x90f179ed815978084dfe0f11c1c8ca0ecc5c4f9434ce17b7072959ff947abb9e); /* statement */ 
return (offset, Value.newInt(intVal));
        } else {coverage_0x914c86c7(0xc1b6ccbc7322174004014c758230cfc27129483efb6ce446c3af4ddb72fd9a22); /* statement */ 
coverage_0x914c86c7(0x863cc60f50964caa3e71112e5683b9dd38d357175ae44eda9c56b0c4cb2cf689); /* branch */ 
if (valType == Value.codePointTypeCode()) {coverage_0x914c86c7(0x9b978f53ef27ed6178059b3c57a7211c9829f93d60315d75e99ca620aab1ef14); /* branch */ 

coverage_0x914c86c7(0xe23a319cc6ad18807e7d1070c3ad871c76d74fb19e570ae8fa385260e2bd60e6); /* line */ 
            coverage_0x914c86c7(0xff41ff8605d22a4d3172367b0b0bdc44581adf60984ed7087eba9a2d09d56e6f); /* statement */ 
return deserializeCodePoint(data, offset);
        } else {coverage_0x914c86c7(0x6b7456e63eb69c165305ddfdb88d81518921490bb3ccf248fb64dea2f0cb1ce5); /* statement */ 
coverage_0x914c86c7(0x75dbfaf76c3c86fb6055eae337a27734e4e1d963089b354fde80bb7509b07094); /* branch */ 
if (valType == Value.tuplePreImageTypeCode()) {coverage_0x914c86c7(0x4ba8fae7d31e1f02e5a5de6ac30c1bff57a6633ca9a31c01db05c94012248fa2); /* branch */ 

coverage_0x914c86c7(0x3f43aee141443da4fcf87f57548df3464b95f5f6322662fb15bb9b85c174b13d); /* line */ 
            coverage_0x914c86c7(0xda7d6c62e6360993f19ccce1f0ccbed0e773b1e61e20d76f5ba6d6ad6f44a367); /* statement */ 
return deserializeHashPreImage(data, offset);
        } else {coverage_0x914c86c7(0x7738528c42cc68a0fe0a4533f2a5bf236c9018e697dcf8aa5c473ca099d19f39); /* statement */ 
coverage_0x914c86c7(0x0be2b9275d74ef2a482fbf40ad4f001bf19ef22e9f669be2fbdef911e8d51f22); /* branch */ 
if (valType >= Value.tupleTypeCode() && valType < Value.valueTypeCode()) {coverage_0x914c86c7(0x7228cdf958d6261cf7e806fae9b5f1b53d57482024e045ee6974f18e0cb34173); /* branch */ 

coverage_0x914c86c7(0xeb6198b1baad5b63b6a3592eeb0e32263dad3ba9da894c1f8ef225691d0fc663); /* line */ 
            coverage_0x914c86c7(0x87329f988ae80c5afe4cb4967e5d09313d455da4efc0eb69e063c7478fd259d2); /* statement */ 
uint8 tupLength = uint8(valType - Value.tupleTypeCode());
coverage_0x914c86c7(0xc2753279413e3636ff623524c8d36fde806150db1d1ed1f32f95a91a4eb3205d); /* line */ 
            coverage_0x914c86c7(0xd0e00a606c2a56ededf8f38579e2a99be518b17d2cc13e95165fcf72d1cf428e); /* statement */ 
Value.Data[] memory tupleVal;
coverage_0x914c86c7(0x0894e72758509fb01570e4f21c9a9facc30309a2810534444ffe4ca370cf0423); /* line */ 
            coverage_0x914c86c7(0x117512ba6ce556a71f73ffe9e3f92b3064e0e317525a064dd3e7154d0569c02a); /* statement */ 
(offset, tupleVal) = deserializeTuple(tupLength, data, offset);
coverage_0x914c86c7(0xc23cdfc31692117b6861d0f0c3244eda6067d6eb71e9116de1607b4be267d580); /* line */ 
            coverage_0x914c86c7(0x3c98aae324b94155b70f5737b57faa5d85deae3f24cc6b48f07906d6e67b19a9); /* statement */ 
return (offset, Value.newTuple(tupleVal));
        }else { coverage_0x914c86c7(0xed57e7898d8e68d2bdbf8e7a5d84cafdf4235e6d002853c971cb394225b11d83); /* branch */ 
}}}}
coverage_0x914c86c7(0xe259fc2b8fbd128dcef61a5121b90191e61f5f53ee9e52b55715c583345ca1a1); /* line */ 
        coverage_0x914c86c7(0x77c9781fe1dab40ed666cc7f95e008707372702458dc0188e806026303ce060a); /* assertPre */ 
coverage_0x914c86c7(0xa3b99741d5c22702a382eee1c03bc84f542f6b9718b5d1efe98b6e0bdcf04172); /* statement */ 
require(false, "invalid typecode");coverage_0x914c86c7(0xbe5008904313c5608b52765e817ce854a336004d725f1575dfb8e5a3cde473e8); /* assertPost */ 

    }

    /**
     * @notice Convert data[startOffset:startOffset + dataLength] into an Arbitrum bytestack value
     * @dev The bytestack object is a series of nested 2 tuples terminating in an empty tuple, ex. (size, (data1, (data2, (data3, ()))))
     * @param data Data object containing a superset of the data we want to serialize
     * @param startOffset Offset in data where the data we want to convert beings
     * @param dataLength Number of bytes that we want to include in the bytestack result
     */
    function bytesToBytestack(
        bytes memory data,
        uint256 startOffset,
        uint256 dataLength
    ) internal pure returns (Value.Data memory) {coverage_0x914c86c7(0x8a8f52173bd5286763ea1bbfc1fd6fea99255d81e5e580e8520c220b6bde1039); /* function */ 

coverage_0x914c86c7(0x1ca4c5811e487718c0b6caf71b2fcf81fc507640be26dd3453194b6a56adc2fc); /* line */ 
        coverage_0x914c86c7(0x47a492c13c30dc610f672d4a4ce5270723d076a01baf0520d5016f519815e27c); /* statement */ 
uint256 wholeChunkCount = dataLength / 32;

        // tuple code + size + (for each chunk tuple code + chunk val) + empty tuple code
coverage_0x914c86c7(0xd9a46018e14e854fe1f2dc9587058e935780bca0d1a686459221b6b5d7126fc6); /* line */ 
        coverage_0x914c86c7(0xbcc364b127f7b13da2548ccdf67998de73cdc87ab814efcfe4f7856384b93ab4); /* statement */ 
Value.Data memory stack = Value.newEmptyTuple();
coverage_0x914c86c7(0x56ecbcc8e1f5f1662bdfdae78945baa2b556ef88e009e2e7777ac7b6860212e9); /* line */ 
        coverage_0x914c86c7(0x5fd3af32da396b159ead7e1a64307d73e3c708da1a7c155e20c8a7786299f357); /* statement */ 
Value.Data[] memory vals = new Value.Data[](2);

        // Break each full chunk of the data into 32 byte ints an interatively construct nested tuples including the data
coverage_0x914c86c7(0x554b87eb98ecf13e58c1328b483532aa28cd1aafdeb45529e8394eba23905a0d); /* line */ 
        coverage_0x914c86c7(0xbbfe6fbd98e22d5baa41459fdf7998ac3ca8e2a8e06e948f56b1c5c651d08b1f); /* statement */ 
for (uint256 i = 0; i < wholeChunkCount; i++) {
coverage_0x914c86c7(0xfd081966bf4a5fa8495791ffe5abd0035be07228fd442d44bf364c318c21acca); /* line */ 
            coverage_0x914c86c7(0x34762dd3a83daef68870cfc639aaa91123e66538f391f99efe457dbc71713e7b); /* statement */ 
vals[0] = Value.newInt(data.toUint(startOffset + i * 32));
coverage_0x914c86c7(0x7f92c2d5498e7f526d1870e1df130de3a31f8601cded2c4fa8fa2b946c9a0d28); /* line */ 
            coverage_0x914c86c7(0x5b8628f3c8183a99b7acb1083fc8fe999b7b25921c61c73c4811487f4f28fc50); /* statement */ 
vals[1] = stack;
coverage_0x914c86c7(0x480d1cf33e398dbb448e5ae2ed1169598876061a83affdfd34b332fbf28c6399); /* line */ 
            coverage_0x914c86c7(0x3b6d8b0784e6bcd0b7f77e7c81aa0ea36f4f9a10d56adb820bc024996cc96644); /* statement */ 
stack = Hashing.getTuplePreImage(vals);
        }

        // If the data didn't evenly divide into chunks. We take the remaining data and add it to the bytestack
coverage_0x914c86c7(0x3fbb456d2ac508b4da378bb36faa06860344a6ccf33b8afad804e8bbe9730ff5); /* line */ 
        coverage_0x914c86c7(0x70bb6ae5dce72beb52b3eb5ebac6d3f4acf01443d55d422ce20db04f5e64ec49); /* statement */ 
if (dataLength % 32 != 0) {coverage_0x914c86c7(0x3d9d5ac85efa45a7646041366fb147ae759401e0de864432fd57032a84c4f2b4); /* branch */ 

            // Grab the last 32 byte of the data and then shift it over to get only the relevent value. This way we avoid reading beyond the end of the data
coverage_0x914c86c7(0x3484a58f1f40e0cd9396acf92a9c287ac19eb132c461e447e8ce51a29ce9bb91); /* line */ 
            coverage_0x914c86c7(0x31f7d1c0518a23f7f85894bd46f4d488ca2cb1f2512bbad3f2e762376ebc3c4a); /* statement */ 
uint256 lastVal = data.toUint(startOffset + dataLength - 32);
coverage_0x914c86c7(0x09bff45ac2296d38991d9e4974db77e79b4f3dc86b831d41d2f8357d4d6a5737); /* line */ 
            coverage_0x914c86c7(0x1d21019858fd2c09602b2554d523289b1b742452b8e6a0535c0cd696b90eeea9); /* statement */ 
lastVal <<= (32 - (dataLength % 32)) * 8;
coverage_0x914c86c7(0x2fc6242d82424df453cf4690934b5570e2c8dd11dde5025c838e1dcac4d6aaa0); /* line */ 
            coverage_0x914c86c7(0xccba459313d7dcc1de39c63051a681a2bf918be77e622fa3c1a496c7b0c47684); /* statement */ 
vals[0] = Value.newInt(lastVal);
coverage_0x914c86c7(0x450e428c695d48fc476b333db373723ac636b81d0775c1e84daea42b6a5d8001); /* line */ 
            coverage_0x914c86c7(0xd6f816daea48d1ef91031b88d9ec06167373096722cbc5f8e323de536fc9bab6); /* statement */ 
vals[1] = stack;
coverage_0x914c86c7(0x31e31a2a562172811f1665647333ea0059783a28d939813a1c4312fd69cd00ec); /* line */ 
            coverage_0x914c86c7(0x8be0c9c78b5e3e75826560015375ec25c22bd6570ad054511eb2844fd45a97c5); /* statement */ 
stack = Hashing.getTuplePreImage(vals);
        }else { coverage_0x914c86c7(0x4dbe327ecd0c5ddf553e03d6fd6e8a51b6f4fc71b13d1f878256b1741706253d); /* branch */ 
}

        // Include the length of the included data at the top level of the tuple stack
coverage_0x914c86c7(0x4323539f93064befefd45b018060f72479aa592353f3839b4725edb49896df4b); /* line */ 
        coverage_0x914c86c7(0x0bd0f53f94c8714654bb3f1a13dcf001f689f0f1f186a92e19ef75a1d27c6797); /* statement */ 
vals[0] = Value.newInt(dataLength);
coverage_0x914c86c7(0xfd22cd6ebbe91d49f13564943e788f99a82a1d1ae30155bbefc7a74d2f8c6875); /* line */ 
        coverage_0x914c86c7(0xd664a05eaf72cd425f6f46d8efb70dfda3d064fdce29987bf95b109a63452482); /* statement */ 
vals[1] = stack;

coverage_0x914c86c7(0x6864c0fd2a1bdaaad8e9ec5c09e50aa1f30ff2182ea073541e0e0f4c7794cd28); /* line */ 
        coverage_0x914c86c7(0x2bd956a019c07ae7fafda8c1ce4e0fecaa0bdc4503c1e652004646dc5d621afc); /* statement */ 
return Hashing.getTuplePreImage(vals);
    }

    /**
     * @notice If the data passed to this function is a valid bytestack object, return the convertion of it to raw bytes form. Otherwise return that it was invalid.
     * @dev The bytestack format is described in the documentation of bytesToBytestack
     * @param data Data object containing the potential serialized bytestack value
     * @param startOffset Offset in data where the bytestack is claimed to begin
     */
    function bytestackToBytes(bytes memory data, uint256 startOffset)
        internal
        pure
        returns (
            bool valid,
            uint256 offset,
            bytes memory byteData
        )
    {coverage_0x914c86c7(0x446a35cb973ee13e8e9da4c4df8a3078cba8c839aa5e7a38418f7f9d9457dba0); /* function */ 

        // Bytestack should start with the size in bytes of the contained data
coverage_0x914c86c7(0x320e5e5c29ec8ddc674865dc9edc205fab85bdda34f259ef42e68ad57fe7a1fd); /* line */ 
        coverage_0x914c86c7(0xb5bb903a3d2dc8bd3b0b24ee94c1f964fe1fd852c2932bbfcd95b0b1f635d70b); /* statement */ 
uint256 byteCount;
coverage_0x914c86c7(0xbf679a482c0555fddaebfc6e34745ec53a5059f9b9d3c0acfe35582ee04bcc52); /* line */ 
        coverage_0x914c86c7(0x466ed379ca91e99f3dd5040349c67bee56f0af497392a9afc2f22c1b7d2ba20b); /* statement */ 
(valid, offset, byteCount) = parseBytestackChunk(data, startOffset);
coverage_0x914c86c7(0xf271ea38159d953d13fc8b45126269ec180384823433787c59bbebad92b0c200); /* line */ 
        coverage_0x914c86c7(0x6356035e08bbf452827774ffb372e0c23a6b21901682eabde54f505307651847); /* statement */ 
if (!valid) {coverage_0x914c86c7(0x9766869db33814532115439f5e6804d005c4acd0d56aafc3f3b876b55847499a); /* branch */ 

coverage_0x914c86c7(0x08c256ab5c09ce782572e5363284bcc7d60be792df1cd50e3f5f002084cc73d6); /* line */ 
            coverage_0x914c86c7(0x9ffb3227530d0f9e2cffdeff0b688f9026585ade120eb689e661a735f8e86e9b); /* statement */ 
return (false, offset, byteData);
        }else { coverage_0x914c86c7(0x9558c808202f86f594f927628d3dc4f7e2a3c0955f677a38b1600d837739ffc1); /* branch */ 
}

        // If byteCount % 32 != 0, the last chunk will have byteCount % 32 bytes of data in it and the rest should be ignored
coverage_0x914c86c7(0xc4e21e51265e7fb36b5f9c43d8956748145e417afa9a4564b75293b40bce1dde); /* line */ 
        coverage_0x914c86c7(0x5418ed47ec8b64fef558b363c03ccd558119590e667cfd799ab25485256afcce); /* statement */ 
uint256 fullChunkCount = byteCount / 32;
coverage_0x914c86c7(0x023aee3983e9afeb633fb338b359ef3e973d76659b0eca6f46f10de1256c1e08); /* line */ 
        coverage_0x914c86c7(0x732a88efc9f40e121c9f2b51ada43411a24a843935696b970938f47ead416250); /* statement */ 
uint256 partialChunkSize = byteCount % 32;
coverage_0x914c86c7(0x6a1c44aee00f31dadb0ef1188f1529d32d0e6e30da1c97387448f98dd7eb0302); /* line */ 
        coverage_0x914c86c7(0x61ce050fb157069fe4d5164dcf7420c1c977dc5eaeeacafb50e18e33cd7c93a9); /* statement */ 
uint256 totalChunkCount = fullChunkCount + (partialChunkSize > 0 ? 1 : 0);

coverage_0x914c86c7(0x4f78c352e49fa6da928dd2c38ae6e5b8e8f88682186b47242bdecaabbf9c2ad3); /* line */ 
        coverage_0x914c86c7(0x4a8d3c0aba2e358ef3e03c79ee208026032897d870adfcc555d621b43d1e9c84); /* statement */ 
bytes32[] memory fullChunks = new bytes32[](fullChunkCount);
coverage_0x914c86c7(0x3400a61b98eaa7dc9e2ed1622b648817e4b27e1b01ea33d24cdeeff95ab77f52); /* line */ 
        coverage_0x914c86c7(0xa17cb98530c128495c8746e8e5f23626010d84069ee36fd7fe30ad622ec4f826); /* statement */ 
bytes memory partialChunk = new bytes(partialChunkSize);

coverage_0x914c86c7(0x4a502904ae990fd666ea7b8e1bcf55c94f18cc1734a81d60a071fdcb2c13a3fd); /* line */ 
        coverage_0x914c86c7(0xad76729bd251bcade7943f6bdf9f0b3f12c6778c65139085e38165f41e4ebc5c); /* statement */ 
uint256 fullChunkIndex = 0;

coverage_0x914c86c7(0xd0f9274ffb22cad95e74fc32aba86cfc0e3ca49268847426ab4bfe7081708317); /* line */ 
        coverage_0x914c86c7(0x21338df0c5d7c2a91a1505d17308d65fa936e584e6c40c3b4165ee85a10200ce); /* statement */ 
for (uint256 i = 0; i < totalChunkCount; i++) {
coverage_0x914c86c7(0xbb4e3c25833bf14b77fc0d957dfa63d44c26c7d51603c96e20978ee1551cb722); /* line */ 
            coverage_0x914c86c7(0x7bac88f71347a4f7e174bd679a0a3ccd7f34e53ca537b4798b38ccb60710e2cb); /* statement */ 
uint256 nextChunk;
coverage_0x914c86c7(0x80451e4dd6df2bd32fe8fbcfd566acce70906d2344678f26f87730b4bfeb60c4); /* line */ 
            coverage_0x914c86c7(0x071ba8ba09a19ad8344814640e9c9e90839401a3a41a71c5521c20221b9674cd); /* statement */ 
(valid, offset, nextChunk) = parseBytestackChunk(data, offset);
coverage_0x914c86c7(0xbd821dcb4d416fd010b90dd620d4ab4d5abc1727b8da18ad0c7ea1be61e57163); /* line */ 
            coverage_0x914c86c7(0x784b0ab7605600e65581d59a043f6a3da14190ed5e5e43ebcfa77fefecb4ea70); /* statement */ 
if (!valid) {coverage_0x914c86c7(0xfa3f90ebc7cfcea4577ec941ef20970afe8fc09b373b0aa90055b23e7d929c56); /* branch */ 

coverage_0x914c86c7(0xa782220c673db4612b96407e08a2b209e75d6f3465e23664d4b53b714bc545da); /* line */ 
                coverage_0x914c86c7(0xf8b3811fb2bc5aa24833d3a4db04a0ea7eea0153b9ebfdabe8e61a21912e7894); /* statement */ 
return (false, offset, byteData);
            }else { coverage_0x914c86c7(0xf5f96ec8332e581f364513ecad11da23872e4851f6df67e06d6ae7fba8df4de3); /* branch */ 
}

            // The chunks appear backwards in the serialization so we reverse their order there
            // Therefore the first chunk is the one which may be partial
coverage_0x914c86c7(0x19be18fb8ba70dd2f770a20e35cf83f108850ffcb4d6c2e385278f4a792ea3b7); /* line */ 
            coverage_0x914c86c7(0x1cfc72bffbba889c8005ccd0b6c51f3adea92f675df0a25d9f8f6fe1b694a0ae); /* statement */ 
if (i == 0 && partialChunkSize > 0) {coverage_0x914c86c7(0x1f247c5a82a2ad2079166bd16d33d1cc18ad65eff6dad34704a222d12491319e); /* branch */ 

                // Copy only partialChunkSize bytes over into partialChunk
coverage_0x914c86c7(0x45c716c08f8d3a5d9bc625b9d4a50cd1a8019c2e8764125e700ccf91f3f4e9ab); /* line */ 
                coverage_0x914c86c7(0xf1097f2e6cc50429605f89edeec91a6b9708cfcf4d511f594e6ba45827b2fc73); /* statement */ 
bytes32 chunkBytes = bytes32(nextChunk);
coverage_0x914c86c7(0xb5214d85ff947def7ff0e20d430bd09f8a2bcf1d13d233ff2026d59f0f212dc5); /* line */ 
                coverage_0x914c86c7(0xfa869fe8bd88293c2bc828ff451b74cb0e638ce489b49565cc4c5faf60214b85); /* statement */ 
for (uint256 j = 0; j < partialChunkSize; j++) {
coverage_0x914c86c7(0xa80d4c06479a24f857b51ff0ded248a333be6d6ccd97dba3ca0a898d67c9e86f); /* line */ 
                    coverage_0x914c86c7(0xa2c3f0f4ee7a6ebbd10300edb6fcdb309896f84dda31ed0d9233a0dfdb94765a); /* statement */ 
partialChunk[j] = chunkBytes[j];
                }
            } else {coverage_0x914c86c7(0xb83e7c9bc4ede863b7624b4852e8d69e696320afc68dd900f6df4852eb0741df); /* branch */ 

                // Put the chunks into fullChunks in reverse order
                // We use a separate index fullChunkIndex since we may or may not have included a partial chunk
coverage_0x914c86c7(0xf09dcc2b7597529e5c273c8eaf568a8f1d96fffa490fd4eb95eae9ea0d8b2e57); /* line */ 
                coverage_0x914c86c7(0x4f89c82066db2de0a665c524a20e2a1ca083b2996bd38aeb5bd92be421f18eaa); /* statement */ 
fullChunks[fullChunkCount - 1 - fullChunkIndex] = bytes32(nextChunk);
coverage_0x914c86c7(0xdf19bbd93f88a634c8f428df951b081520907f4e605813e232a65760460fceeb); /* line */ 
                fullChunkIndex++;
            }
        }
        // The bytestack should end with an empty tuple
coverage_0x914c86c7(0x84f62a638ea694558eea07b99a2d1ce42694f7511a1dd1959eae4c29aff52bcd); /* line */ 
        coverage_0x914c86c7(0xdced77cc2730bea1c74a667f5cab0cb26509800a9d2a6ec04c683df7f77d8f98); /* statement */ 
uint8 valType;
coverage_0x914c86c7(0xca0fb62c8ec1e0718545b6c766b2eaedddeeca33a853991199a36ffb92e9932e); /* line */ 
        coverage_0x914c86c7(0xaa611e6367fbaf33002bc5e7a03525662fec886d9129e547d8cb7a1fa2785b1f); /* statement */ 
(offset, valType) = extractUint8(data, offset);
coverage_0x914c86c7(0x26c7072c060111f2d72677b604d0c997e4b9d1d684885267002ca9c1063455e5); /* line */ 
        coverage_0x914c86c7(0x349f072d31198af6f4fc88c14b65809b7cfbe0066ddb8a7528bdac2a007c7044); /* statement */ 
if (valType != Value.tupleTypeCode()) {coverage_0x914c86c7(0xd9e4a50b5f10df7947b7f22ab93da3883438398b267c3df8243d052048abae7f); /* branch */ 

coverage_0x914c86c7(0x858f8d9a3227da846ab9076389b7ee020197188fc8bad71ca3b5474627e91bba); /* line */ 
            coverage_0x914c86c7(0xd0fd28fd2f4f36184d5cb8bbb516eb4e9d7f5542e7fcce78b22869e55deb9bc2); /* statement */ 
return (false, offset, byteData);
        }else { coverage_0x914c86c7(0xfc7a14b0113b6419307343a2616cfaa8b90ba44063e285b1fdbed7ed25d70a50); /* branch */ 
}
coverage_0x914c86c7(0x7231c479d503ec2a06798f665da8fabd95c0639430d4ff1b9389c76d04558c73); /* line */ 
        coverage_0x914c86c7(0x3c30cebfc7396b15d757cdf5c6feb1472ccdea31f28faba1e83264b233aca9e7); /* statement */ 
return (true, offset, abi.encodePacked(fullChunks, partialChunk));
    }

    function parseBytestackChunk(bytes memory data, uint256 startOffset)
        private
        pure
        returns (
            bool valid,
            uint256 offset,
            uint256 nextChunk
        )
    {coverage_0x914c86c7(0x29a199c23361094c0d9a7db10105bece747dabb9e0c287d84eb30179e7171184); /* function */ 

coverage_0x914c86c7(0xf967f144e77856ca065961aee9b590f16e453b214ac5875c7160121d47cff126); /* line */ 
        coverage_0x914c86c7(0x247673fa0992320c8669e59cd1ecccc9bdaa2fb2123926c011a00ced2e3d49da); /* statement */ 
uint8 valType;
coverage_0x914c86c7(0x1c50e007493f5939e85d28583d025d0dbe5e466a724e2f030fca5f857c9e9844); /* line */ 
        coverage_0x914c86c7(0xcde4647ee7ccf0b5245b3ab661b141f316fc21af861b30fea1d86c044418cdd2); /* statement */ 
(offset, valType) = extractUint8(data, startOffset);
coverage_0x914c86c7(0xc49daeef6de7b715076722bef15f55f133c4079a6e50ccdd2806636ab8ed7303); /* line */ 
        coverage_0x914c86c7(0x4caf68f2d164e2996a1399d5a5c3d5de8223bec2a759ce499a641331bc4087a2); /* statement */ 
if (valType != Value.tupleTypeCode() + 2) {coverage_0x914c86c7(0x12c7bdd26dda371a0c0da95a5fa3c97881250531877119a24ae7e3432878bdf5); /* branch */ 

coverage_0x914c86c7(0xd68fff9bc7c6725da35251c418e650463b083da485ac0fe2980224b3904f1c3e); /* line */ 
            coverage_0x914c86c7(0x476d19c9fccd74742087f5516a0acf5d4e7a1f86118c37db3be1755be9b218dd); /* statement */ 
return (false, offset, nextChunk);
        }else { coverage_0x914c86c7(0xb2931caa1199829377846ef5852c2c2400cfb27dbe704222c9bfd36d71d49077); /* branch */ 
}
coverage_0x914c86c7(0x20aa835e1092f1bebdb0e7b16a86ef898b22c8f9a996b914c45ca0e71bd53609); /* line */ 
        coverage_0x914c86c7(0xf68c1132c40cb2058f4f83f60454d05fd3219567e68047b1a5d608aa1989e7f8); /* statement */ 
(valid, offset, nextChunk) = deserializeCheckedInt(data, offset);
coverage_0x914c86c7(0x5331519f46e970dc60eb91c0e40fa4117b79799c076f48677395cf9ab37fcdd8); /* line */ 
        coverage_0x914c86c7(0xf5a5212eb175cd6737a4c845b27869dd85a843419175fd4c98fb4b6d01491d37); /* statement */ 
if (!valid) {coverage_0x914c86c7(0x5df98389ee4c4013fa304e2194e8983e8c243f0490034b7d88652a6adc0e3b23); /* branch */ 

coverage_0x914c86c7(0xfeed337b78cbe9a38184bf7747b7cdc571ca83b38d3af0833643d33637a63f48); /* line */ 
            coverage_0x914c86c7(0x3f9dce3f5e1b55f665260f7f9e6f1a57057b7a924be5872640383e25e31fa1b6); /* statement */ 
return (false, offset, nextChunk);
        }else { coverage_0x914c86c7(0x52cc2b2063ba9a04eae6112581cf298f5cc8e3e12ca44a930967700d93539864); /* branch */ 
}
coverage_0x914c86c7(0x79bbfecf6ebea556f280d580091d1bdce34102eed477409e06d0fd150dba3270); /* line */ 
        coverage_0x914c86c7(0x41549cf2bbe2c91320ede0a06d654dacdb8cbb0d1bdb80004a7969c5fa609671); /* statement */ 
return (true, offset, nextChunk);
    }

    function extractUint8(bytes memory data, uint256 startOffset)
        private
        pure
        returns (
            uint256, // offset
            uint8 // val
        )
    {coverage_0x914c86c7(0xe81f12877fa810f5f0c864b3325b9aa43c844990ae512821aa9bbbfb6b4d948d); /* function */ 

coverage_0x914c86c7(0x54c5a2a6b333612238cb29378a8a3f6ebe4cbd56b84fe33a0232461811837ffe); /* line */ 
        coverage_0x914c86c7(0x8ece4ccd8f66ab0d8578effd9dd70578c364966762138a904865ea8ea037f50f); /* statement */ 
return (startOffset + 1, uint8(data[startOffset]));
    }

    function extractBytes32(bytes memory data, uint256 startOffset)
        private
        pure
        returns (
            uint256, // offset
            bytes32 // val
        )
    {coverage_0x914c86c7(0x9aaa030a0e5a76958835e37cd508259973ba0026703648644c3d4637a8283f54); /* function */ 

coverage_0x914c86c7(0x5fdfb1a1091c3bac5a57f7531a1dbdbc9cc921f4da4aa27bb132608eeb2ce5aa); /* line */ 
        coverage_0x914c86c7(0x10f796229050ac9daa3bba409760e78304e8111b20bc1c5094d9cecf6019b0f3); /* statement */ 
return (startOffset + 32, data.toBytes32(startOffset));
    }
}
