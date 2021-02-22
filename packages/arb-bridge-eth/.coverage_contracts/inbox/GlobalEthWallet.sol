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

contract GlobalEthWallet {
function coverage_0xb74b7b42(bytes32 c__0xb74b7b42) public pure {}

    mapping(address => uint256) private ethWallets;

    function withdrawEth() external {coverage_0xb74b7b42(0x468437bf976016aa78cf7364a60538a352b6133f39a9f7101cc605f09b55ee1c); /* function */ 

coverage_0xb74b7b42(0xcf232a7a1775e93d8713829e8a92d1d0f2c9a5f327d108b7afee50d08ac5f555); /* line */ 
        coverage_0xb74b7b42(0x49094d7b92cfc146daf0ce0aca23005082915dcb0e5484731294c521e9c19206); /* statement */ 
uint256 value = getEthBalance(msg.sender);
coverage_0xb74b7b42(0x4b38721146d8f0792e0553c70d90049db25818e68a0be4d142c49c284faac4f5); /* line */ 
        delete ethWallets[msg.sender];
coverage_0xb74b7b42(0x2fbca625a741ab7e5663028f3d1b752efc9cdb269f7e7e54bc787c5877544522); /* line */ 
        coverage_0xb74b7b42(0x528cfa1ab7c03e516fe652b9916a1cd3daff856a54046590541b9cd4f6b37dfa); /* statement */ 
msg.sender.transfer(value);
    }

    function getEthBalance(address _owner) public view returns (uint256) {coverage_0xb74b7b42(0x1ed8f1707686dbaff4085fcedc90ae5b353f363266dd8e499192fec3fb30262c); /* function */ 

coverage_0xb74b7b42(0xe36e342c722f71427fd8f802d4d6de35eea4bcf9165e85f3375d7208e089f4b3); /* line */ 
        coverage_0xb74b7b42(0x782c284d0ab97a3e91d4c953f082db2bb63c408d2dba5cb96df379b4d58b2df7); /* statement */ 
return ethWallets[_owner];
    }

    function depositEth(address _destination) internal {coverage_0xb74b7b42(0xc6336d0f90caea39d6325c8839c075d467b95743311463b3adb79c51c60642e7); /* function */ 

coverage_0xb74b7b42(0x2841b1e35505b43c7cb789636965b5d0896c3c5af9453ddcb0a43713bafaf1f0); /* line */ 
        coverage_0xb74b7b42(0x7713bd0e756cac7d8c5523795f463682edfb5317856e1eafd752a595525f8420); /* statement */ 
ethWallets[_destination] += msg.value;
    }

    function transferEth(
        address _from,
        address _to,
        uint256 _value
    ) internal returns (bool) {coverage_0xb74b7b42(0xeab2678bfa9910c73b0f159db45e48f7d3845501567a4576162a78c93650bd1c); /* function */ 

coverage_0xb74b7b42(0xa31ac6134525bac07e6ee0d82ed3c4544e5460f700d92d594d98009073d05743); /* line */ 
        coverage_0xb74b7b42(0x82b6c85efd45aa9828e920826c67686cbf60c0ce7cd87f2753ae9f02170023d3); /* statement */ 
if (_value > ethWallets[_from]) {coverage_0xb74b7b42(0x04e55eba64f727b7ce0a93527dc108af5454ff788e943212978b458641d5ed57); /* branch */ 

coverage_0xb74b7b42(0x397704462d9dc816ee437944d5ab145d9249eeb515d0c89299821e7b693a3685); /* line */ 
            coverage_0xb74b7b42(0x66e1a181e068f341fa32deab25d969807f3a8bc880eaa7ed94549db405fd9c24); /* statement */ 
return false;
        }else { coverage_0xb74b7b42(0x7336b037e0331fedbd43d8558d10a8028bb5aab4cf1394db18c3857aadb785fa); /* branch */ 
}
coverage_0xb74b7b42(0x7a0a4dcb279040a6713a4c61c6a99e347a4bf4fe42760e5e36b4d607b8a39f20); /* line */ 
        coverage_0xb74b7b42(0xd17c9c506aeaf1d08d1067b7667e3c4720f4fdaf7c8d6cd5d480e748bb403f9f); /* statement */ 
ethWallets[_from] -= _value;
coverage_0xb74b7b42(0x79f11d81ce423ad289d2b782ec5b049cecbe21455c77fdc0f7bc8e436f1a6211); /* line */ 
        coverage_0xb74b7b42(0xafd4a0ae9101df55f30140f5e310b4685036feba6102a040993367fcc859cb30); /* statement */ 
ethWallets[_to] += _value;
coverage_0xb74b7b42(0xa194ce373207024e4e354f8968cc7f212e3890d94b66983e94a4ed503ea93c4e); /* line */ 
        coverage_0xb74b7b42(0xf736484964fec20ee6310bb196117c4f4c994cb264cef7369795971ce982ddcf); /* statement */ 
return true;
    }
}
