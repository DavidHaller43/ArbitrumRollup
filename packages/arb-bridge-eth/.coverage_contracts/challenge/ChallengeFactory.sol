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

import "./IChallengeFactory.sol";
import "./IBisectionChallenge.sol";
import "./IExecutionChallenge.sol";
import "./ChallengeUtils.sol";

contract ChallengeFactory is CloneFactory, IChallengeFactory {
function coverage_0x42c12958(bytes32 c__0x42c12958) public pure {}

    // Invalid challenge type
    string public constant INVALID_TYPE_STR = "INVALID_TYPE";

    ICloneable public inboxTopChallengeTemplate;
    ICloneable public executionChallengeTemplate;
    address public oneStepProofAddress;

    constructor(
        address _inboxTopChallengeTemplate,
        address _executionChallengeTemplate,
        address _oneStepProofAddress
    ) public {coverage_0x42c12958(0x7f6fd6d1d02e8885105b1501ed4cd9151391df9c42002fa3018174954eec408a); /* function */ 

coverage_0x42c12958(0x4f2ca1386668bc483cd8227805dd3c016136b8f573e8ea6a5fe17d865c30f0c8); /* line */ 
        coverage_0x42c12958(0x366029d4730b46f6287758f81da00944b26098f0359e7496e681d08dd7d78be7); /* statement */ 
inboxTopChallengeTemplate = ICloneable(_inboxTopChallengeTemplate);
coverage_0x42c12958(0xfc7a55fca1e25d73618068012ec855de71cca2d64af80b32b3188c233f1de5d7); /* line */ 
        coverage_0x42c12958(0xf1f4352925e5b9efc2e36afa63b8b1cf3c8bb539dd2f4ca0531146ba11c01582); /* statement */ 
executionChallengeTemplate = ICloneable(_executionChallengeTemplate);
coverage_0x42c12958(0x7fefc5480c744c05d5757ae81c92e683763b165b6e3d9f397cba4d03bb4d982a); /* line */ 
        coverage_0x42c12958(0x10d44a7d8d3f4aea202ab3f1f5c2f045072630efbc175f8d64582beb7ca0dbd5); /* statement */ 
oneStepProofAddress = _oneStepProofAddress;
    }

    function generateCloneAddress(
        address asserter,
        address challenger,
        uint256 challengeType
    ) public view returns (address) {coverage_0x42c12958(0x5de4de8172b5cc7c19f696e33984c162f4c7ca918eca86e3e1e5b69af5450b4c); /* function */ 

coverage_0x42c12958(0xa60f7978a524fb9194cb4c13f87db4bc631dd4ac7f122ae525b2c7745e5ad9c0); /* line */ 
        coverage_0x42c12958(0xc84d2a3f5db0db92fa6dad54365b83069e9fc776a7ebd25e73dada3ab1bdd8ff); /* statement */ 
return
            address(
                uint160(
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                bytes1(0xff),
                                address(this),
                                generateNonce(asserter, challenger),
                                cloneCodeHash(getChallengeTemplate(challengeType))
                            )
                        )
                    )
                )
            );
    }

    function createChallenge(
        address payable _asserter,
        address payable _challenger,
        uint256 _challengePeriodTicks,
        bytes32 _challengeHash,
        uint256 challengeType
    ) external returns (address) {coverage_0x42c12958(0xdb3ed5c6a38aa895260a6bc6d57054dc5369ff1f1f75deb855fc833626efd870); /* function */ 

coverage_0x42c12958(0x133d8029704b493bcf4de3339958bc4cafe5d2a67890f4a6ddafe908def89450); /* line */ 
        coverage_0x42c12958(0x6761ebbc6eae908eaddf86e84ba6fd074006f2104b4f949facb9543be6fcf029); /* statement */ 
ICloneable challengeTemplate = getChallengeTemplate(challengeType);
coverage_0x42c12958(0xe7374abef977655ad2228fc1c918ab313197b31b4b41facc8fdf90354c8e9427); /* line */ 
        coverage_0x42c12958(0xc5819f8049d7aec4045c8ce52ab5c5abb7080dc9d6b60d4bf2eab2107d3dad23); /* statement */ 
address clone = createClone(challengeTemplate);
coverage_0x42c12958(0x43dbeb3b58a59c761afa2c4c124046ceb04ada6acabd9d529c2e6c0dcd12d282); /* line */ 
        coverage_0x42c12958(0x453bea87b305c12c15bf47eac804e9ba3b6d80cf0b1ec1830bd6e5119d62ee40); /* statement */ 
IBisectionChallenge(clone).initializeBisection(
            msg.sender,
            _asserter,
            _challenger,
            _challengePeriodTicks,
            _challengeHash
        );

coverage_0x42c12958(0xd8cdd808a8c7038a9fe0af3038aca17404ba24b255475e05c04b41c7fe1c947f); /* line */ 
        coverage_0x42c12958(0x34c30396085e7daa8bc61bd769ed62fa2fc3924ff359fda49f0cab092cf5cca2); /* statement */ 
if (challengeType == ChallengeUtils.getInvalidExType()) {coverage_0x42c12958(0xe238e7d10dba3eac67b29e724f678798019ca31389d880934814e5df07610cdf); /* branch */ 

coverage_0x42c12958(0x0a1caad2a4f8c780a1aea107501dc2c85f9348ed7dca9a21b72bb695bcd322a6); /* line */ 
            coverage_0x42c12958(0xf91a32be7301d67f8f13691e3c2088e6f5bfc3c6a037aa4ccde2c0f6ab50b728); /* statement */ 
IExecutionChallenge(clone).connectOneStepProof(oneStepProofAddress);
        }else { coverage_0x42c12958(0x7e6df2deabf6c93562b7b493b12eece2a6bc8ec6c8e215d72d858530e57a678c); /* branch */ 
}
coverage_0x42c12958(0xca8c382fec76c01b9c08cbd45d0562ca72ff8ef46867efeb1e6d0ffa81432c82); /* line */ 
        coverage_0x42c12958(0x6276935d90494ec3489d046595a8fbc6ab300698f84f9783c8eb875eda1a84f8); /* statement */ 
return address(clone);
    }

    function generateNonce(address asserter, address challenger) private view returns (uint256) {coverage_0x42c12958(0x49928dca2b92225666318f3b4d0d6c3bad64198b849b159f778097714b208f30); /* function */ 

coverage_0x42c12958(0xd233bf48f4ae8665f4816ab92fd9394b330550a5d53fb7596e91915542b05f47); /* line */ 
        coverage_0x42c12958(0x5ed7252ce4dd59d36dd8a113fb091dc7507ae0f9387480f1a5bb0a8c0761e2f8); /* statement */ 
return uint256(keccak256(abi.encodePacked(asserter, challenger, msg.sender)));
    }

    function getChallengeTemplate(uint256 challengeType) private view returns (ICloneable) {coverage_0x42c12958(0xc52d5e2b5bee25f56ae05453945afb21c2534d32367b3fa7f5c83ac46544d37f); /* function */ 

coverage_0x42c12958(0xe76c969ce55c1e10e595deb0fa9df48448c267c86aaff398e8a74608c3365ec4); /* line */ 
        coverage_0x42c12958(0x41c9b57fee5ada00caa84dc9cc95163c1d609ab3de2c958b7474a0af2260f4c2); /* statement */ 
if (challengeType == ChallengeUtils.getInvalidInboxType()) {coverage_0x42c12958(0xf9e11f3655f8f00d0cf99e966a4acec0554fa23c188fcfac9593e43a25278c9a); /* branch */ 

coverage_0x42c12958(0x627ff51335a517502ccd38111eea5cd8d32940183329c136444acaf498cf99c8); /* line */ 
            coverage_0x42c12958(0xeeab48c55fec1db1806d86cf05c07ede9a2ab0959308a7edf66b66d4dbf1e7f1); /* statement */ 
return inboxTopChallengeTemplate;
        } else {coverage_0x42c12958(0xe8a2990c2dee6d8f608d44c76c32056dfbca535e0d203b4d43aeb57f72fda37f); /* statement */ 
coverage_0x42c12958(0xdaf01872af4623664cc34d57b9266c2fa81e1baf80e38fee5ccc27c611da178a); /* branch */ 
if (challengeType == ChallengeUtils.getInvalidExType()) {coverage_0x42c12958(0x058e1840fb3d57a7c2d3fd8daf7cea4d04668f697617496b6e91633df72d19a9); /* branch */ 

coverage_0x42c12958(0xf9abb32577ef9474650cc93ea4a4659e43ac3056ee5ba7d6dd22ed42c23547a1); /* line */ 
            coverage_0x42c12958(0xdff102452e0dc649caf9f96a1abad8a0e4cfdbab2a7b29c9736faf2620c63ffd); /* statement */ 
return executionChallengeTemplate;
        } else {coverage_0x42c12958(0xbbcd17c85a6faa2cf1d4ed4eab5294fd241dff7c07bbe7678552a08370740b85); /* branch */ 

coverage_0x42c12958(0xf08e74666c9db74417fd60515043f746b660d4912987e67689f7f84bda8f7833); /* line */ 
            coverage_0x42c12958(0x79cca702cc35c23aba8d163dc07ed018719a700e7805719d677d4979f319f6cd); /* assertPre */ 
coverage_0x42c12958(0xf47d9fef41e3f3638b97c52afb2a7b53934f3821abb26e552926e77676794710); /* statement */ 
require(false, INVALID_TYPE_STR);coverage_0x42c12958(0xfe55df12a186dad1ad857e7e9bbe4088caa772ff87f2638f6fba800b3416d0c8); /* assertPost */ 

        }}
    }
}
