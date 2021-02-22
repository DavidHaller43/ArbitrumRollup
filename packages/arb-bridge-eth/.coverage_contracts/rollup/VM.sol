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

import "../arch/Value.sol";
import "../libraries/SafeMath.sol";

library VM {
function coverage_0xc626c09e(bytes32 c__0xc626c09e) public pure {}

    using SafeMath for uint256;

    bytes32 private constant MACHINE_HALT_HASH = bytes32(0);
    bytes32 private constant MACHINE_ERROR_HASH = bytes32(uint256(1));

    struct Params {
        // these are defined just once for each vM
        uint256 gracePeriodTicks;
        uint256 arbGasSpeedLimitPerTick;
        uint64 maxExecutionSteps;
    }

    function isErrored(bytes32 vmStateHash) internal pure returns (bool) {coverage_0xc626c09e(0x27f747c9a64b4e76853001893d0f821cc9602efe79191a4c88dc1854c2e71ca1); /* function */ 

coverage_0xc626c09e(0xba0516ed44ea8af053f998a65d842d23caba0bb12d659312afac6773633c78eb); /* line */ 
        coverage_0xc626c09e(0x223734d41d2f8c56888cc25c30a15e9cd7191d9bbe4b88691b6bab88ad845287); /* statement */ 
return vmStateHash == MACHINE_ERROR_HASH;
    }

    function isHalted(bytes32 vmStateHash) internal pure returns (bool) {coverage_0xc626c09e(0x040c6d14e59b250ec1352a90007dd78ebd0881243e78b29969b44ce5a41558af); /* function */ 

coverage_0xc626c09e(0x2a35a1ec93a9b4a2d1a089eb5725af5e3d40c11446120becb00afe5e07d14125); /* line */ 
        coverage_0xc626c09e(0x7c38be7fe044d5a703b4138f8ae855568eb6f86ddb7841806bafc4686c2f7650); /* statement */ 
return vmStateHash == MACHINE_HALT_HASH;
    }
}
