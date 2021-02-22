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

import "../libraries/CloneFactory.sol";

import "./IArbRollup.sol";

contract ArbFactory is CloneFactory {
function coverage_0xbc6dcfaf(bytes32 c__0xbc6dcfaf) public pure {}

    event RollupCreated(address rollupAddress);

    ICloneable public rollupTemplate;
    address public globalInboxAddress;
    address public challengeFactoryAddress;

    constructor(
        ICloneable _rollupTemplate,
        address _globalInboxAddress,
        address _challengeFactoryAddress
    ) public {coverage_0xbc6dcfaf(0xe7d27b88284950eb8a11e422997524da13ce889910dd2182e8591a7480c5de1e); /* function */ 

coverage_0xbc6dcfaf(0x407d3bac64f8a5e2ef96c6613ad59027be8c6fe7970b27444b3f6ef0ea3360cf); /* line */ 
        coverage_0xbc6dcfaf(0xdbd6bacaa571b0f5829de8a8cc45cf92a4c1c98b58272ed71365991ec44ec35d); /* statement */ 
rollupTemplate = _rollupTemplate;
coverage_0xbc6dcfaf(0x227a4bfe788dbfebb023ae1ba64bb365dd7181de1bb70ef6a0fd389c52035437); /* line */ 
        coverage_0xbc6dcfaf(0x2f191098bef9a59a750e76913f527755b65fc7648b64a5f3275ca120510e8b90); /* statement */ 
globalInboxAddress = _globalInboxAddress;
coverage_0xbc6dcfaf(0x454f576c25f60fb7f28a715c56ee8b8dbfbbe4cd7f53f6530d59609be920ec2c); /* line */ 
        coverage_0xbc6dcfaf(0x2fd8ce1a924b7eb350486150787fd2c6a87516113356d4a477a45b31a69186de); /* statement */ 
challengeFactoryAddress = _challengeFactoryAddress;
    }

    function createRollup(
        bytes32 _vmState,
        uint128 _gracePeriodTicks,
        uint128 _arbGasSpeedLimitPerTick,
        uint64 _maxExecutionSteps,
        uint128 _stakeRequirement,
        address _stakeToken,
        address payable _owner,
        bytes calldata _extraConfig
    ) external {coverage_0xbc6dcfaf(0x7c1c3471c43cf92f4222193681f2c63048c8c2733a82a40f22adbb2aad6f18c9); /* function */ 

coverage_0xbc6dcfaf(0x84292c50854735a64b26b49232901efbb727afd1a63dd8b8adb3c8be3377d826); /* line */ 
        coverage_0xbc6dcfaf(0xa3ee42b5ee1f2259bd93861192d52556defa07585684ab4f14028ac4b6623d8a); /* statement */ 
address clone = createClone(rollupTemplate);
coverage_0xbc6dcfaf(0xe94e38f7701b5340046118cdefbae82abcbfc909a85d1acf4fbec6aedb78975c); /* line */ 
        coverage_0xbc6dcfaf(0xeeec4725cef6168b714004550b36c70c31655fdbf67bde70b1ddcd4ea60692c9); /* statement */ 
IArbRollup(clone).init(
            _vmState,
            _gracePeriodTicks,
            _arbGasSpeedLimitPerTick,
            _maxExecutionSteps,
            _stakeRequirement,
            _stakeToken,
            _owner,
            challengeFactoryAddress,
            globalInboxAddress,
            _extraConfig
        );
coverage_0xbc6dcfaf(0x6a3fc88586857c390aaa50da18262bb0c4affa9757ec6864d25bb84a8e87cea7); /* line */ 
        coverage_0xbc6dcfaf(0xcdbc0cce224257a5ef4ec304790a39209b14aa12db152e6c02e0da1d61755f21); /* statement */ 
emit RollupCreated(clone);
    }
}
