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

library Hashing {
function coverage_0x7724f559(bytes32 c__0x7724f559) public pure {}

    using Hashing for Value.Data;
    using Value for Value.CodePoint;

    function hashInt(uint256 val) internal pure returns (bytes32) {coverage_0x7724f559(0x9eaf3c10121ec2ad900a5ed7b8bdd34a5c958c342389b771e17c434a1ac77e3c); /* function */ 

coverage_0x7724f559(0x3f4b0079d0abe39628827497a5787e4d7dfa0b15ee9f4b8d55839318a5440adb); /* line */ 
        coverage_0x7724f559(0x13ba17733fd21a6b9bd2f022881571c1c9ec5b18840b09c1be3108f335af9e75); /* statement */ 
return keccak256(abi.encodePacked(val));
    }

    function hashCodePoint(Value.CodePoint memory cp) internal pure returns (bytes32) {coverage_0x7724f559(0x7c1bc8a3ec822222df570cead1f77b7ab198c4b8af4c18529f140928d916142d); /* function */ 

coverage_0x7724f559(0x7e913d0678f72ea9e67eabab3edee606a09f518ca623ded4e21fb55f5f33d8cf); /* line */ 
        coverage_0x7724f559(0xc3b10d992543c1e822ac11f1190ddb389b2fb298a9f01c0e8b7e7eff140af748); /* assertPre */ 
coverage_0x7724f559(0x02a91c7d5d802f7db54c53d8e1e0563c01caa83ac9a0ccc76337b4bc45a362a7); /* statement */ 
assert(cp.immediate.length < 2);coverage_0x7724f559(0x36adea37782994cf88fbcd2bb5c0b82e1288546688623f7e51ee76cbccd0a1dc); /* assertPost */ 

coverage_0x7724f559(0x37ef9297fbae8dd4ff7f4998ec7563481217e9805fe2b8236b9022f0fbb092b2); /* line */ 
        coverage_0x7724f559(0x6c521419fe6d60ad5e20bcae197257b63aa36ac93eec2d1c0faa5686ceb4fcd4); /* statement */ 
if (cp.immediate.length == 0) {coverage_0x7724f559(0x6d1ecdf237b0ddf3168f6bf74d90e3f5e3b6e63f0ef837ee42f71b642b29aac3); /* branch */ 

coverage_0x7724f559(0x08776042cda6cc0de12d099adb095c909930c75eb976136c2168d950b411026c); /* line */ 
            coverage_0x7724f559(0x4afdaa3c514233f45f7846ff306a823f473985782902cd6c98f9176dd9be0508); /* statement */ 
return
                keccak256(abi.encodePacked(Value.codePointTypeCode(), cp.opcode, cp.nextCodePoint));
        }else { coverage_0x7724f559(0x3d4b4c3b188845d7b102be3970c69a0a024cb0d4ff959112adb8b86ba426af03); /* branch */ 
}
coverage_0x7724f559(0xe99e779e94a7297ad48654f6e20f54f17103e47753e40470061b31748100057f); /* line */ 
        coverage_0x7724f559(0x6c0d400e9ad1d95cdfd156d3272f1253594865301d7b8c49f2266abdafb022fb); /* statement */ 
return
            keccak256(
                abi.encodePacked(
                    Value.codePointTypeCode(),
                    cp.opcode,
                    cp.immediate[0].hash(),
                    cp.nextCodePoint
                )
            );
    }

    function hashTuplePreImage(bytes32 innerHash, uint256 valueSize)
        internal
        pure
        returns (bytes32)
    {coverage_0x7724f559(0x71f5e827fb19072731fcdf08abbcac1e05af848d4f5170ffc1c1abbf63dcd2d8); /* function */ 

coverage_0x7724f559(0xfb3db81ac1b57658d8a50e225a2106d85853a535d3b32facf2f56b30191e1116); /* line */ 
        coverage_0x7724f559(0x06c45123bb49303a1c821bfae299f7484804f9ebfe0e970d7688f9ca7a02a9f4); /* statement */ 
return keccak256(abi.encodePacked(uint8(Value.tupleTypeCode()), innerHash, valueSize));
    }

    function hash(Value.Data memory val) internal pure returns (bytes32) {coverage_0x7724f559(0xeecbf3b43e174bfa9d3dc05243ca8f4e02c7fcfcd1ece9679182e0651e0cab55); /* function */ 

coverage_0x7724f559(0x052e4464f740c6502cf0fd229fdf67e45f209fb1cbfb19d1c14c5d1a29c07e6a); /* line */ 
        coverage_0x7724f559(0x9f2ec5cb74c85b3dda79d02129b4497f194f44f5c60580708bdaac4f7d19de12); /* statement */ 
if (val.typeCode == Value.intTypeCode()) {coverage_0x7724f559(0x24d3525e18528b0e7b5a22ab780a539f29f70d811ff40d99badfbaaa5b39fd3b); /* branch */ 

coverage_0x7724f559(0xa7a7839ed32d6cf00fc1865d538e5e1a402b87a2c4f7b227e0b7b36b888f5808); /* line */ 
            coverage_0x7724f559(0x593ac5c2c5288c1dbb203d27dacac00cede5fcdb7fc9d10a5c305fbb4c73c562); /* statement */ 
return hashInt(val.intVal);
        } else {coverage_0x7724f559(0xa30c6083d4e6df3807e31c2442739d4ab4e5647ddecf2480b794193b92413911); /* statement */ 
coverage_0x7724f559(0x1e36abb78feb0bacc7fe90795af878ba23f3ca1aa0dc9f88b422f9dda0c8ff61); /* branch */ 
if (val.typeCode == Value.codePointTypeCode()) {coverage_0x7724f559(0x77e4c526c606c4e9f5d43cce2740ec9671fd6fb354963233bcb5d7af2a69fd1d); /* branch */ 

coverage_0x7724f559(0x2124e9c3abdf6745aaa436519fdfd6c1740fec7208eb945cc032adcb1ab90676); /* line */ 
            coverage_0x7724f559(0x55da3fb306d7c8a9ebef352a4737e112d908e61af1757d65bbcaf5d0393c021d); /* statement */ 
return hashCodePoint(val.cpVal);
        } else {coverage_0x7724f559(0xf08847433bfbd8a6e2ee9bc8d78ec986014f36ce065c1d1707a5dd5218f1481b); /* statement */ 
coverage_0x7724f559(0x04a288f8aad1aeb8c303d69df7789ed0ef77851572b7777fdf1dab24a63d23d4); /* branch */ 
if (val.typeCode == Value.tuplePreImageTypeCode()) {coverage_0x7724f559(0x053f2fc07c5e68d07944c4d8f49a051d37cab82655e08bdbc8116aa04ab3d9d1); /* branch */ 

coverage_0x7724f559(0x58b76dc10646fbb4a572d993371ad30d350ad181d2494b5ed7e482ec78d0aa5d); /* line */ 
            coverage_0x7724f559(0x27311cc9a8003541aa5824b056dc38db6ebdd89963517e6bde81efa5f9e07dac); /* statement */ 
return hashTuplePreImage(bytes32(val.intVal), val.size);
        } else {coverage_0x7724f559(0xd701feb7b54094b4cd44090f9b08f44fb9674096a49308a022977bb10b2248d2); /* statement */ 
coverage_0x7724f559(0x7d48c6f363478e43f51853eac0bfda719dee000b51f1104e887e589a8d515bb4); /* branch */ 
if (val.typeCode == Value.tupleTypeCode()) {coverage_0x7724f559(0x29dbd803792a5d60aafc327fd5b8da7a08bdddc61d11c31f31faf731592100a9); /* branch */ 

coverage_0x7724f559(0x25a1fb259b08d27dcb8ec8d5727d0254fb27d0c4a1ebdc88a72ea0eb02142018); /* line */ 
            coverage_0x7724f559(0x5315fcf275934a9f39028957597cb1acdfcfe4454039f7332b47785b10dae963); /* statement */ 
Value.Data memory preImage = getTuplePreImage(val.tupleVal);
coverage_0x7724f559(0x3dcea2332b134590dce160c112e9926fb764b57ca3ae2b4ae3f2e0963976cc00); /* line */ 
            coverage_0x7724f559(0x5ce3440dc0f5e535c12d9f0346a83362afb7f8664e6759090e16c4944983a14e); /* statement */ 
return preImage.hash();
        } else {coverage_0x7724f559(0x474026bd48f6a8df713d01eba551deecd2d324a7033ebd72d2d078475cece8a4); /* statement */ 
coverage_0x7724f559(0x2f7b5184646ba6972b2771a2ffbb63f41896ba7e144e6e3282150132f0d26ee6); /* branch */ 
if (val.typeCode == Value.hashOnlyTypeCode()) {coverage_0x7724f559(0x8319669813af7147de721c4ea1a90094d6746faf17dd26ec0fabb73c4a1e4e61); /* branch */ 

coverage_0x7724f559(0x1e8d3ca058b777afa4850a144099cca89bc39e02a6fc113aff71001da0ed371e); /* line */ 
            coverage_0x7724f559(0xd34f13064256441d80ce18e14c0ab4a6a7699701186482696dfb0436a109f022); /* statement */ 
return bytes32(val.intVal);
        } else {coverage_0x7724f559(0xe31fedf5f88680c2b66c331607361e5d6bb6291d34bbe9d78071c3210c12e0ab); /* branch */ 

coverage_0x7724f559(0x31ef4d60adf5e34c8082ee11956b5b0c4064cd688f44c7df407ff965f4ef98bd); /* line */ 
            coverage_0x7724f559(0x1b483e362aae0ea9f85961ce9c0910441d98844d0d2f53d5878aa0af1aa70a4f); /* assertPre */ 
coverage_0x7724f559(0x52033be6f627dd77e0a393449591813fa7c413a8929d666a6b76afac2812e435); /* statement */ 
require(false, "Invalid type code");coverage_0x7724f559(0x39825640e6d04eb7ac2f09ccaba5ae506855553a1c0a499b97fb2b98e50d4172); /* assertPost */ 

        }}}}}
    }

    function getTuplePreImage(Value.Data[] memory vals) internal pure returns (Value.Data memory) {coverage_0x7724f559(0xcb96678d2beb82c5c066a67efd2a4113e1426f6e76b5f9659e494939d8d733b5); /* function */ 

coverage_0x7724f559(0x5040153078cd839495bdae2c2c6a57d5feac7d74ed6af390135983fd93ef4b1d); /* line */ 
        coverage_0x7724f559(0xc3c879137465a9213cd9c5def168b9f6c3a4bb87c09e49697b0f9d20ca0f1979); /* assertPre */ 
coverage_0x7724f559(0xdcbf84ff2516663821430592a54b97b8cd5a3fdfc8a4429078e92da78273c535); /* statement */ 
require(vals.length <= 8, "Invalid tuple length");coverage_0x7724f559(0x11bf2898862dd866510d68dbb932a61c50ee08db75f4a8e14e658132e99192b2); /* assertPost */ 

coverage_0x7724f559(0xad48dc3f9c61718bc228450e153b448d7537cf61aeb6e345f4edf0ca8dd2a38a); /* line */ 
        coverage_0x7724f559(0x121addf4891a997bc2f865cda516368a280d038ed199e5bc7b568db34e34fd0e); /* statement */ 
bytes32[] memory hashes = new bytes32[](vals.length);
coverage_0x7724f559(0xb636cc31c2e1e3f0bd321d5bc435398a3afb7ff145cc2f47006e3241430fc48a); /* line */ 
        coverage_0x7724f559(0x8a946f4539748a3a77b86d2f1c6393e9d590bbaec93f5cd01893159f4162181e); /* statement */ 
uint256 hashCount = hashes.length;
coverage_0x7724f559(0xe3c7ca3baf9947f243b40507ff9b05fa216259571a10651e6ff528238dbc69d3); /* line */ 
        coverage_0x7724f559(0xee431f5b655a5d26b8ae288fccac479b236e3f73d469ba9ab63434cde1b6803d); /* statement */ 
uint256 size = 1;
coverage_0x7724f559(0xe5741e295e6ebe6c5854bcc0b96bd1c0c2e6070de202f111beb2afb00a4898a9); /* line */ 
        coverage_0x7724f559(0x3fdcc2b763fa50b1cf3d9876cdc59650334948ab2df2f202e917a2ee5e70f38d); /* statement */ 
for (uint256 i = 0; i < hashCount; i++) {
coverage_0x7724f559(0x917c302a6a2e0d5fbb5b0ad650a7a62ff3d0941c51a8ca2d02d0d44072171671); /* line */ 
            coverage_0x7724f559(0xd96e2ac714e529fd9e8d5f735b357523f82d453489609feb389872a25e0ad5ea); /* statement */ 
hashes[i] = vals[i].hash();
coverage_0x7724f559(0x725bfbdb0b12c58e7c05aa7373c5229818cfe172dee9b6f9e84f0f8bd270f15a); /* line */ 
            coverage_0x7724f559(0x4e337f3ed10df128a8b16d6afbeded8c72ff5b0fbca78cf18073119b4dc93443); /* statement */ 
size += vals[i].size;
        }
coverage_0x7724f559(0x093d8b45a8fa77da5c13c708f0bfecfb52e60ad3f3e310a1b62e89bc1c6e67c9); /* line */ 
        coverage_0x7724f559(0x64c51795f86fb95a92461a7498e310d85ef4cc3bba3ea08f5a9d8947d46c7efc); /* statement */ 
bytes32 firstHash = keccak256(abi.encodePacked(uint8(hashes.length), hashes));
coverage_0x7724f559(0x91d12e7f689f45ac73dd071fb67ca90d18eeb9568c4fe8fa21cd22d8606457e4); /* line */ 
        coverage_0x7724f559(0x16754757e0de1bf52e6e06a59aa2235f0e18edb6290beb7b906735a5943ccfa4); /* statement */ 
return Value.newTuplePreImage(firstHash, size);
    }
}
