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

library DebugPrint {
function coverage_0x125558b5(bytes32 c__0x125558b5) public pure {}

    function char(bytes1 b) private pure returns (bytes1 c) {coverage_0x125558b5(0xefb7cd841344530d2d14ae604e70c4e5b60aff30a986881246a8ea4e80d34032); /* function */ 

coverage_0x125558b5(0x7157d7327bdbbcce7b46ebda31ca5336cf781355695f89336805064409a4475d); /* line */ 
        coverage_0x125558b5(0x93e73a1cb9065115e5017d5b6aa928a82fa9f9b02cbe6d354678fafb6d6acf97); /* statement */ 
if (uint8(b) < 10) {coverage_0x125558b5(0xd79abfc7d18e3ff387c808263c5f2fd6ecb10e77fc9c0d1330bb5c067cc77cfc); /* branch */ 

coverage_0x125558b5(0xc8577162ec8ed8cfb1b4de3d7798f5adc738314aea5157c6e3112a45584176b9); /* line */ 
            coverage_0x125558b5(0x76a8208d45d03e8e18874069f11982d52c7790a08b4acadb8431855d1573079f); /* statement */ 
return bytes1(uint8(b) + 0x30);
        } else {coverage_0x125558b5(0xc4107c4520460490809767012ee01148959bbd7af4b6b4357fe06688e7fa2945); /* branch */ 

coverage_0x125558b5(0x34efd54bdeac07fe75d54ad52429c09ee848602dcfc4448948ca7ace507ed6b5); /* line */ 
            coverage_0x125558b5(0x790ce4d2604612fb35e8b20a3633886708a0c7cad7c79c3b577567a4824ffa20); /* statement */ 
return bytes1(uint8(b) + 0x57);
        }
    }

    function bytes32string(bytes32 b32) internal pure returns (string memory out) {coverage_0x125558b5(0x8d6cc271d500c808558ae06c760b213f4b96593452f22cebbb7cef36d8adf480); /* function */ 

coverage_0x125558b5(0x40f53aca1f1feedd4c5c13c36fb204113e92c359857f90088f5437e0a21dbbd6); /* line */ 
        coverage_0x125558b5(0x7a5928e8f6d4982bba8eaa9ef4fafd7ef7009e72cce61f4b8e1608e8359c1cf0); /* statement */ 
bytes memory s = new bytes(64);

coverage_0x125558b5(0x3cad5efa882af82ce809660370333d814f263e4160e0de879816dd19169c5614); /* line */ 
        coverage_0x125558b5(0xe3e937c1366fff4c17b11bccbcd87dd9e7031afa2c2e7424b65ffa5f72ebc66b); /* statement */ 
for (uint256 i = 0; i < 32; i++) {
coverage_0x125558b5(0x135292a3a595d1af4fc9f0a3c14345029556ccf858f5762667fb95cbda89aac1); /* line */ 
            coverage_0x125558b5(0x731a22088130cecd1e53a7324e90b143580e99c0029ae60698dd8442cabdcde1); /* statement */ 
bytes1 b = bytes1(b32[i]);
coverage_0x125558b5(0x9f2224868e8e0becaa91f3a8dbff572b1c6435dafb202364b269dce586ce592b); /* line */ 
            coverage_0x125558b5(0xd780a5632ac3e9bf25c99e056109ecac06b60dc284cfb41ed375d6e31b74f8f8); /* statement */ 
bytes1 hi = bytes1(uint8(b) / 16);
coverage_0x125558b5(0xc376b5826ece8c8450382a8d0347d6f1b262c39d86c010679031ddafbccc6973); /* line */ 
            coverage_0x125558b5(0x98e7c7b29e032c7183a29528228685a88b217ef5427665fc7e1365ed5319fed5); /* statement */ 
bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
coverage_0x125558b5(0xe3c8dd93c1f206b86e52efc7b598d2eddb46378fb9c09b7adfa773fbaf456fb5); /* line */ 
            coverage_0x125558b5(0xbba0a308e0beacdea37485d2b93b324746ca7f5a1ff3b1605c7a199a9228d0a9); /* statement */ 
s[i * 2] = char(hi);
coverage_0x125558b5(0x9f0a432f1f1c0ae34df3a74c643df63f337d99384244672f5aebf522e9832319); /* line */ 
            coverage_0x125558b5(0x0bed7aa4943b63771923fdc06560a87c5f436b00484965d6a66b4fd921062c78); /* statement */ 
s[i * 2 + 1] = char(lo);
        }

coverage_0x125558b5(0x79a572636abfe04b7d3d84d5661887b605bb119309f853e878bdb5327014da6a); /* line */ 
        coverage_0x125558b5(0x6bdf7f5542cf55c1d99c7d61cdb42e9e2d27b025e506efd4be429c4f95460079); /* statement */ 
out = string(s);
    }

    // Taken from https://github.com/oraclize/ethereum-api/blob/master/oraclizeAPI_0.5.sol
    function uint2str(uint256 _iParam) internal pure returns (string memory _uintAsString) {coverage_0x125558b5(0xa7cecabfdcc67d38a25c06d1698e21c0b6a438a07a31657a2deb9611a5cb935e); /* function */ 

coverage_0x125558b5(0xaf7e987c2a05022e2e2bbbe30aa65a706fd67c04574c620378cd00ac4d6ebb78); /* line */ 
        coverage_0x125558b5(0xf9c9bc27fe2c48d601fc2127a2e632bbfde901c945154423f42cb918544f1f0b); /* statement */ 
uint256 _i = _iParam;
coverage_0x125558b5(0x8e0949e290cd3e89877e2d8125f54bb7a67ce44e14da13ca182a75dabfe6249f); /* line */ 
        coverage_0x125558b5(0xda5d673f3f4b00319df92ecce52ecf033c5dda02907d27f9cc6ca7cf1a867971); /* statement */ 
if (_i == 0) {coverage_0x125558b5(0x7335a94c818701e65af637e56507323d6e0cbc74ae965d4f31a157b1fabd69f7); /* branch */ 

coverage_0x125558b5(0x9f3388e17ae168d113ae12edeaa5e3ef8b96aae76441827990f4275091d660a4); /* line */ 
            coverage_0x125558b5(0xa5223583b00007aca0fbfa156f0283ff19066fba9704f6181eeca2fe88aaa91f); /* statement */ 
return "0";
        }else { coverage_0x125558b5(0x9d8303396b6a6b900bbe78b9b1c1f20c05e6ab7392969afd945b55dbe89fca72); /* branch */ 
}
coverage_0x125558b5(0x1a47e25ea0b014c11ba4f63491a828c36384cde4f5875eeb1d2ce71147de6f58); /* line */ 
        coverage_0x125558b5(0x29f5435d8ad5360d4d319ff426bc636f61ad1b1d307f2449ef4365705510555d); /* statement */ 
uint256 j = _i;
coverage_0x125558b5(0x4e5a28a7d57f9d434d31b02c67332f106fbf56e1cd92847110d7f42be281a41b); /* line */ 
        coverage_0x125558b5(0x2b93a77d0f07c30df0575f896fd6c502211a1177bf93da9584c994a318b3c562); /* statement */ 
uint256 len;
coverage_0x125558b5(0x83e9b6465fb9bfa08346fa7ba7204152a28125b64bd10d7d25b4f7f7befe8d23); /* line */ 
        coverage_0x125558b5(0x00482a211a499ad9398315529f3b13d3fc73d960ce57ff7d86835890154de120); /* statement */ 
while (j != 0) {
coverage_0x125558b5(0x98ad8df7f4b1ad1f80b572b0ea60c765d851696fd3451fa36b1d5717681271c6); /* line */ 
            len++;
coverage_0x125558b5(0xb2265e561769cf179e7a32fc07c3b4dd1a74f2ae4ee04934dc41da15be4aa820); /* line */ 
            coverage_0x125558b5(0x44c438fc5d832e9ee9d0a10e242ac2f4e681b471f21b9c9f7d1077b4561d97bc); /* statement */ 
j /= 10;
        }
coverage_0x125558b5(0x847cbf2edd6619c047c0e79f6befbeff044ee01d507ea0232b299a0278d541c0); /* line */ 
        coverage_0x125558b5(0x0cb205529ff13bf7a3f4e4570462a0d46c1c7d61194a0dc55e9b4904d5864019); /* statement */ 
bytes memory bstr = new bytes(len);
coverage_0x125558b5(0xf03546a2f2d563b637daa1658d747ba3caac5c95b90cc9220969c5e60313010b); /* line */ 
        coverage_0x125558b5(0x6a952cfb6d28471b1b07dbe9fc2d7595420abac2f12791cdd681b85080716adf); /* statement */ 
uint256 k = len - 1;
coverage_0x125558b5(0x56f22121e3588db93894d7c356d003f5ea8dfb2d4e61b39797a01ae4b1d727ac); /* line */ 
        coverage_0x125558b5(0x980df055f29ba1e59d79bfeca8119c7426bdba6ceeedac18dbefb2aa2e8d735b); /* statement */ 
while (_i != 0) {
coverage_0x125558b5(0xafa12ccd62eab621a6961112d7e9233a2d9b5c72f3f1d2c640043482d519c649); /* line */ 
            coverage_0x125558b5(0xc05058b3cd522764b9e62ba13f94428476cc12a710388ae89135ab5d16279a5e); /* statement */ 
bstr[k--] = bytes1(uint8(48 + (_i % 10)));
coverage_0x125558b5(0x77d254764cabb2a017063ee97ee6b35ec7070bbbf96095131cfa3c3bb666b4d5); /* line */ 
            coverage_0x125558b5(0xd7b4dbf24359e701eda1fb0776caeb452cd5b9cbaeac0378029e8efd4008e8a4); /* statement */ 
_i /= 10;
        }
coverage_0x125558b5(0xf75ffa67ea7b07748294b247757be91e9ae458cf785f607038df9d9b836dafb0); /* line */ 
        coverage_0x125558b5(0x48a85cde9ee07a5a302ad6b839c097b9bf8839466bfbd057f562f6d358efe6a8); /* statement */ 
return string(bstr);
    }
}
