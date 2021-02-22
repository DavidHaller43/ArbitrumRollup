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

import "./ICloneable.sol";

contract Cloneable is ICloneable {
function coverage_0xa4cceb08(bytes32 c__0xa4cceb08) public pure {}

    string private constant NOT_CLONE = "NOT_CLONE";

    bool private isMasterCopy;

    constructor() public {coverage_0xa4cceb08(0x7f06c7f27b956d6cb0eca807cf096a993464679913cd678b30b173aac50e079b); /* function */ 

coverage_0xa4cceb08(0x5aef7f0f10cb58021ec31d9246b9e96bfcee2c67419803fbe37932587c170ba6); /* line */ 
        coverage_0xa4cceb08(0xb2ed7cd8bf1d6897586819f7a7e7e072fc3517faea07e3c1469bc03476422d10); /* statement */ 
isMasterCopy = true;
    }

    function isMaster() external view returns (bool) {coverage_0xa4cceb08(0xee2e99190279b0d1519fd5eda5732201e786a5a79000b3e76c6570aa4d82a971); /* function */ 

coverage_0xa4cceb08(0xb277b4265ed49ebcb908f4d613b23806e820efad2be64bd84c84d54bf65b43f1); /* line */ 
        coverage_0xa4cceb08(0x7e93f21ccd4ccd97d1e7b2f12fe982e33890ef757ab8eeb3aedaf30915e1b5f0); /* statement */ 
return isMasterCopy;
    }

    function safeSelfDestruct(address payable dest) internal {coverage_0xa4cceb08(0x071318d2858a8fdd71e34781ea4fac667b66f646223c2b1fc6c2802c10edae8d); /* function */ 

coverage_0xa4cceb08(0x27bb68b4de882b395efad7fc3348c7598630c55a01eeff2f9a2f1a51f7ad092e); /* line */ 
        coverage_0xa4cceb08(0x3cd6b29a693149baca2518439c7e6121330e1e480f4bc8dc5887255017400fc3); /* assertPre */ 
coverage_0xa4cceb08(0x54cb7281941c38ecfe5a1cad45afc6d6d5f6ac264822109794f077bbc7138f47); /* statement */ 
require(!isMasterCopy, NOT_CLONE);coverage_0xa4cceb08(0x30cf640ec6853e0b374ba39a47f74b37c3cbcdbafba234489c099eb05b090f9b); /* assertPost */ 

coverage_0xa4cceb08(0x312d6a59e83c3b6beb1e777ad6c4ad2bf877b5680d94d0a1d9a5fbd0528e916e); /* line */ 
        coverage_0xa4cceb08(0x24e02ff370120c594d6456aa69314fd3e012a3004b977b72111b962170fdfb52); /* statement */ 
selfdestruct(dest);
    }
}
