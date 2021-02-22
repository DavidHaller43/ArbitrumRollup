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

contract PaymentRecords {
function coverage_0x191d35ef(bytes32 c__0x191d35ef) public pure {}

    mapping(bytes32 => address) private payments;

    event PaymentTransfer(
        uint256 messageIndex,
        address originalOwner,
        address prevOwner,
        address newOwner
    );

    function transferPayment(
        address originalOwner,
        address newOwner,
        uint256 messageIndex
    ) external {coverage_0x191d35ef(0x21bb660192f19948f0685ba8e5ba15208defb3daeccba00dd9cc435a90bc60c5); /* function */ 

coverage_0x191d35ef(0xb4094752c13dd6a1b806e2712b2a0263f82ad38a69ba4800dad4cab46b16640f); /* line */ 
        coverage_0x191d35ef(0x6323de9457b9e26fcb12db860da7f928d6d4a3cd4e898db2c37bf4a684cacd21); /* statement */ 
address currentOwner = getPaymentOwner(originalOwner, messageIndex);
coverage_0x191d35ef(0xedabf3aa3bef4b74084409509aba5b28a82743aadffa941430679068709b281c); /* line */ 
        coverage_0x191d35ef(0xb0b94c3171ccb515f3315190d6ad3ce01c7f852bee04636b6ab5cceeb955870c); /* assertPre */ 
coverage_0x191d35ef(0xbca07b3d087d787fbac1fb65103d0eb46f6342282cd999b0a187ae550bfb4a74); /* statement */ 
require(msg.sender == currentOwner, "Must be payment owner.");coverage_0x191d35ef(0xbf0dd88f8e1e3a062294dda2c7c581c78384c53d6dbf96a72d1b4ca205f3965a); /* assertPost */ 


coverage_0x191d35ef(0xccc8bb879d6abf221231bac60c4c1e013e2e96f43b21595b8392ffad0e3ece27); /* line */ 
        coverage_0x191d35ef(0x2bf193cd3dc18b7866e30f8c3bc7f39e9f46c5390927ef479f81a17f2b5af498); /* statement */ 
payments[keccak256(abi.encodePacked(messageIndex, originalOwner))] = newOwner;

coverage_0x191d35ef(0xe8a3a8350d96029b91a255a481e2d30fd91763d861a1a22b7745b104e04ddb83); /* line */ 
        coverage_0x191d35ef(0xff5dc87a205475fa0b2ca93c7de542020f34123f8a9d72d363afde5b984a8044); /* statement */ 
emit PaymentTransfer(messageIndex, originalOwner, currentOwner, newOwner);
    }

    function getPaymentOwner(address originalOwner, uint256 messageIndex)
        public
        view
        returns (address)
    {coverage_0x191d35ef(0x6aa07c66a678aaba1688d0ddf4c38385ae410ec015d12172bd8bb0bdfa42be95); /* function */ 

coverage_0x191d35ef(0xb705055f356d588ef5f97e2810ef341fc2cf060784055bd4192430b209e5bcaf); /* line */ 
        coverage_0x191d35ef(0xb4ea0c879d4e37977ac5b18d2f5c7c5f09b1693ae73a696ddbfa0f78b39bdc96); /* statement */ 
address currentOwner = payments[keccak256(abi.encodePacked(messageIndex, originalOwner))];

coverage_0x191d35ef(0x740298411e316e442097f67a9ccaef0a1a5c21c972b917596c90fd4bb1178461); /* line */ 
        coverage_0x191d35ef(0x9d08fce3ab58aaff22aa62842284eca437942ae6a228b3191243e48a08dfd193); /* statement */ 
if (currentOwner == address(0)) {coverage_0x191d35ef(0xe1cb3b4972bf5b707e75cf63816e96c5fae8ec5df73f4bce0c88f4c9604d52a0); /* branch */ 

coverage_0x191d35ef(0x455ff247108dd7705a094f3b4618d1dd5a528b271788316a11bb9480f0f251a2); /* line */ 
            coverage_0x191d35ef(0x0903c49f6ebecda565e4be97b46a047b7fa0dc30a9a64786ccb6732321d8f970); /* statement */ 
return originalOwner;
        } else {coverage_0x191d35ef(0x7db109f0da8768380c43043c1eefa03be75dbb3b4fe8d08e6257da1e6f235c8c); /* branch */ 

coverage_0x191d35ef(0xd4d368c9f50db618128b793fd6ce3cee0bf5af54ca3c0fddbe6568e2e6257667); /* line */ 
            coverage_0x191d35ef(0x7b635dab241d3bc074a0e3f8d663300ef5fc88a33486f97a570c522641605221); /* statement */ 
return currentOwner;
        }
    }

    function deletePayment(address originalOwner, uint256 messageIndex) internal {coverage_0x191d35ef(0xc00ef994c13a9f36f9c126258a0e0756229b1aee1d271505aba02e95a72cf408); /* function */ 

coverage_0x191d35ef(0xf9017849e933bae145de67287a7553ea2598d09a54a9090ad15c38fd1eef264f); /* line */ 
        delete payments[keccak256(abi.encodePacked(messageIndex, originalOwner))];
    }
}
