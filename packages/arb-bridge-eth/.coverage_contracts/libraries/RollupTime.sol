// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2020, Offchain Labs, Inc.
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

library RollupTime {
function coverage_0xce4be7f5(bytes32 c__0xce4be7f5) public pure {}

    uint256 private constant TICKS_PER_BLOCK = 1000; // 1 tick == 1 milliblock

    function ticksToBlocks(uint256 ticks) internal pure returns (uint128) {coverage_0xce4be7f5(0xb23bdd60d90744c75c5abd9561c79b753e62d145fda00ad6b807011b1751a68a); /* function */ 

coverage_0xce4be7f5(0x8be42158f7b8267a82895bf462dc579ec4b19ba41f8e4de24df169f4e3583bc4); /* line */ 
        coverage_0xce4be7f5(0x1bdecfcec32dd6a01a1f71a651d4f3672c9298ae66d93daa0d1cb33cc6e734f7); /* statement */ 
return uint128(ticks / TICKS_PER_BLOCK);
    }

    function blocksToTicks(uint256 blockNum) internal pure returns (uint256) {coverage_0xce4be7f5(0x4d2453f533f007d13e85277051a4d4b1880c87c4fc2d61ee6c7d4512bf6d7a9a); /* function */ 

coverage_0xce4be7f5(0xea54fa7687f3c475222c56fc2e7f53884737459099d53ec6013570a58829966a); /* line */ 
        coverage_0xce4be7f5(0xa0cf63d6c9505f8b38a2d019c4f8dcee66bb02df290ac379dcb80bb522d6c690); /* statement */ 
return uint256(blockNum) * TICKS_PER_BLOCK;
    }
}
