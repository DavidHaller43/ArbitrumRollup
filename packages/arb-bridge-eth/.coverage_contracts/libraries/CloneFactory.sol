// SPDX-License-Identifier: MIT

// Taken from https://github.com/optionality/clone-factory/blob/master/contracts/CloneFactory.sol

pragma solidity ^0.5.11;

/*
The MIT License (MIT)
Copyright (c) 2018 Murray Software, LLC.
Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:
The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//solhint-disable max-line-length
//solhint-disable no-inline-assembly

import "./ICloneable.sol";

contract CloneFactory {
function coverage_0x1c465d00(bytes32 c__0x1c465d00) public pure {}

    string private constant CLONE_MASTER = "CLONE_MASTER";

    function createClone(ICloneable target) internal returns (address result) {coverage_0x1c465d00(0x957e71d89ca73c93e8f445ee81774d3516cb72a2d24c3ef8c68d5ea95e8f8986); /* function */ 

coverage_0x1c465d00(0x8a2b34f4d7cfafcf8b1b56af5c425ac15c504bb2aa0b5bf6e9cd8ab7caef6ce8); /* line */ 
        coverage_0x1c465d00(0xe6c5316e33723fd66c4c2698a58f0f9c5e69eae08fbab9fbafd651ecb2ba74ee); /* assertPre */ 
coverage_0x1c465d00(0x537256a85cb7a02ddfdc6997d3bcd1e31d689e9a47e1aba78c5f2cb04557b867); /* statement */ 
require(target.isMaster(), CLONE_MASTER);coverage_0x1c465d00(0x0615383ee871f40de35de4354026fc5fd71e1a3803ff5ae1afb7fbdd0510c85c); /* assertPost */ 

coverage_0x1c465d00(0x9c857e62c3242ef34bbc2e981437300f97cf9f678e174c756c66c04af76c438b); /* line */ 
        coverage_0x1c465d00(0xccdec83cf1dd88004a78653f414e07e8b67275b06f503a16393e88b4b8f3118f); /* statement */ 
bytes20 targetBytes = bytes20(address(target));
coverage_0x1c465d00(0x6dfc997c60b70ced87da2eb379d4a06078e2e4a42ec224e43de3208655248d63); /* line */ 
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(
                add(clone, 0x28),
                0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000
            )
            result := create(0, clone, 0x37)
        }
    }

    function create2Clone(ICloneable target, bytes32 salt) internal returns (address result) {coverage_0x1c465d00(0x63860ed830c9e6d677294a1ca50c6564583e42bfb92fac5408c2534b34c87729); /* function */ 

coverage_0x1c465d00(0x1e8a0504e681fdb214568137c46c689b8be3df7acaa3aa05bfac3ae5f14948d3); /* line */ 
        coverage_0x1c465d00(0x39f757416ed67e95aa45e444448e74e65d21d6f3460e5d16443aa208f465acbb); /* assertPre */ 
coverage_0x1c465d00(0x536ff565c37bbab71e9d4a89e02a739cdbd425277d7147f728741fb43ea6dfe0); /* statement */ 
require(target.isMaster(), CLONE_MASTER);coverage_0x1c465d00(0x6aded29a877f48895f56234e59b659d5f0d3a7d12343df18447d7368e2d323cb); /* assertPost */ 

coverage_0x1c465d00(0x7355885c3eb17f76e11b4635df909957cf7771779938e60b2811755b39de14b0); /* line */ 
        coverage_0x1c465d00(0x9c5bcda7b6d94823875fa4954b28addc8820d06dbaecd6186968826552b3ef9f); /* statement */ 
bytes20 targetBytes = bytes20(address(target));
coverage_0x1c465d00(0xced5b5f9c92408e5140afaf95967c42d428a950884c7913065463482cef34899); /* line */ 
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(
                add(clone, 0x28),
                0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000
            )
            result := create2(0, clone, 0x37, salt)
        }
    }

    function isClone(ICloneable target, address query) internal view returns (bool result) {coverage_0x1c465d00(0xf99697daafe74a232ad7aaa0e91bf2a2b04b7a227ea04f376c1b9d4a2bc45765); /* function */ 

coverage_0x1c465d00(0x9c41d33766ae81cf135ed8ba1da6ceea189349321a882ab276fb3ec5de21dc89); /* line */ 
        coverage_0x1c465d00(0x986856db34794308dc15b924dc7ae84aa643864e6ab0a5a89dc27b7d328596d3); /* statement */ 
bytes20 targetBytes = bytes20(address(target));
coverage_0x1c465d00(0xa656c3f627f8fd7569aa8383e8b2b6bef09bace983dc80bbf7e7a91876b42992); /* line */ 
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x363d3d373d3d3d363d7300000000000000000000000000000000000000000000)
            mstore(add(clone, 0xa), targetBytes)
            mstore(
                add(clone, 0x1e),
                0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000
            )

            let other := add(clone, 0x40)
            extcodecopy(query, other, 0, 0x2d)
            result := and(
                eq(mload(clone), mload(other)),
                eq(mload(add(clone, 0xd)), mload(add(other, 0xd)))
            )
        }
    }

    function cloneCodeHash(ICloneable target) internal pure returns (bytes32 result) {coverage_0x1c465d00(0xf2ead90fb2d45940e0b733ded7b39425606309aeb6131a4d4bb5a1e666c410f2); /* function */ 

coverage_0x1c465d00(0x36e99b9bf009e82dbb6e8fa3bc6819e5ad66b95fb9dd5a2a34caf6bb6f87606c); /* line */ 
        coverage_0x1c465d00(0x476314c952853fb1984e52455e3117d764101f472c554f5dd8e34ccbc76d8e1c); /* statement */ 
bytes20 targetBytes = bytes20(address(target));
coverage_0x1c465d00(0xcf0e91cbda9d59f6ec3bc21db0acb4b7f5628bb2d03df73765e4f6d559da74f1); /* line */ 
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(
                add(clone, 0x28),
                0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000
            )
            result := keccak256(clone, 0x37)
        }
    }
}
