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

import "../interfaces/IERC20.sol";
import "../interfaces/IPairedErc20.sol";

contract GlobalFTWallet {
function coverage_0xb3fcc7e2(bytes32 c__0xb3fcc7e2) public pure {}

    string public constant FAILED_TRANSFER = "FAILED_TRANSFER";

    struct FTWallet {
        address contractAddress;
        uint256 balance;
    }

    struct UserFTWallet {
        mapping(address => uint256) ftIndex;
        FTWallet[] ftList;
    }

    mapping(address => UserFTWallet) private ftWallets;

    // Uninitialized paired contracts default to Unpaired
    enum PairingStatus { Unpaired, Requested, Paired }

    struct PairedContract {
        bool paired;
        mapping(address => PairingStatus) connectedRollups;
    }

    mapping(address => PairedContract) private pairedContracts;

    function ownedERC20s(address _owner) external view returns (address[] memory) {coverage_0xb3fcc7e2(0xce3fc4b99d06e6e3c589d5e8cdd7766928313e354d9664813f67e93a03ac85ba); /* function */ 

coverage_0xb3fcc7e2(0x71cd4a65ab736a3d9a46adc370244c73f7834400f6004e9edaa64f57b00a7cd7); /* line */ 
        coverage_0xb3fcc7e2(0xe4d960033272b351f83a792cd6f723ae3ad0f35f9f30c38a4d700e82848bfdbe); /* statement */ 
UserFTWallet storage wallet = ftWallets[_owner];
coverage_0xb3fcc7e2(0x924bcb61c77431e3eee01cedf19501cb6f33f96ee004b2236c20d30be1c51d49); /* line */ 
        coverage_0xb3fcc7e2(0x50d3ec268f3a08bca62a594e809c0fed1799c42493a320d5fa826197672e7da1); /* statement */ 
address[] memory addresses = new address[](wallet.ftList.length);
coverage_0xb3fcc7e2(0x08910eb6bfa023e9ad6e77b9269b3137691b559a3c6649c41f72ac5969634ff8); /* line */ 
        coverage_0xb3fcc7e2(0x2c01f36c4465a08293e82172f82ec1db13bb4f241105c22234e1e37fe64a05b4); /* statement */ 
uint256 addressCount = addresses.length;
coverage_0xb3fcc7e2(0x15a63dee7f8c1ad42128b8f328d6afc52e75507fcf6e939849776f4772fd0ad6); /* line */ 
        coverage_0xb3fcc7e2(0xa5ec5c0d60d55d08d5744b404e92d692477ab7a8aad360c2b96480e3766aa0fa); /* statement */ 
for (uint256 i = 0; i < addressCount; i++) {
coverage_0xb3fcc7e2(0x64a9b2ab2b9523418f0f3ac7ff3e27fd577880f960d46740964438b3beb0f5a6); /* line */ 
            coverage_0xb3fcc7e2(0xed21cce643fc1588afa398c1e6f0c0899b27d2037e51bf3c83c037e77706b0db); /* statement */ 
addresses[i] = wallet.ftList[i].contractAddress;
        }
coverage_0xb3fcc7e2(0x16fe7e3e2ac2eff0204374b710650ff5d51ae916f39b9ca1e5b49d54faacc078); /* line */ 
        coverage_0xb3fcc7e2(0x9d66d10728cabdd48417a168e0d330851ed97b3bdae872f070ee3ab1fe8dc112); /* statement */ 
return addresses;
    }

    function withdrawERC20(address _tokenContract) external {coverage_0xb3fcc7e2(0x66a259a1acc9ae81c0a6d449ab718ca36e8369fb125f7a2112a0959d0b64ecdc); /* function */ 

coverage_0xb3fcc7e2(0x93136b6da9a624247249c1412cdf3acfdd9345bb297582ee16a0ae24d79fa483); /* line */ 
        coverage_0xb3fcc7e2(0xfc4bfaeed64ce62ac2e435f3615a0c15a63accb1052a5fe282d41a3ebc323bf1); /* statement */ 
uint256 value = getERC20Balance(_tokenContract, msg.sender);
coverage_0xb3fcc7e2(0xa9bb3f744f82ef21f3633e325bd177b7e987076050729bf3a238a971c6d2b4b0); /* line */ 
        coverage_0xb3fcc7e2(0xb417f04d07141867d81781c2bc71f81976ec3e946154ee8bdb3f785ebb57b489); /* assertPre */ 
coverage_0xb3fcc7e2(0x1d0a245cc900571532898cfe6bc2b571a0d534324451acea5517d44d5789ffd0); /* statement */ 
require(removeToken(msg.sender, _tokenContract, value), "insufficient balance");coverage_0xb3fcc7e2(0x73673640f05d6c7dc39a865944faa67eab66a94743a82a0e440a71c28a67a6fe); /* assertPost */ 

coverage_0xb3fcc7e2(0x7e0d9e857d83238aca8bee09bcf44eb306fa7bc4b7f70041799f368d4a1a5bee); /* line */ 
        coverage_0xb3fcc7e2(0xc15fb4b6aa428fe01ddeb645c77b56a630a4c86106cd61842fdf60884ddf1336); /* statement */ 
if (pairedContracts[_tokenContract].paired) {coverage_0xb3fcc7e2(0x5d0b86db4a054b021396abfdd6d0295a7009c2c035117645bbe64bed0239eec7); /* branch */ 

coverage_0xb3fcc7e2(0x1a238fce2c79331807f1f9500b4075f03eecf41a55dccf23de83aec3395f0607); /* line */ 
            coverage_0xb3fcc7e2(0x31b248ff4938a901e7dc0303924b2233b0cc6a2e533243f8b23cf670b01cfb49); /* statement */ 
IPairedErc20(_tokenContract).mint(msg.sender, value);
        } else {coverage_0xb3fcc7e2(0xc2122d9dd5a355b5d0118e43e41d3b2b20bdea0d52ccb3922e386dfd72408eef); /* branch */ 

coverage_0xb3fcc7e2(0x9d978c9fdeb00fbb06b695444a9d3a7059055b7615cc72ccbb44851b448adf76); /* line */ 
            coverage_0xb3fcc7e2(0xbf51d7ffceb9cfda0888643287230bc8ffe3002ec8b4c0b849b6ea18b6b7783d); /* assertPre */ 
coverage_0xb3fcc7e2(0xcdb2cc6e41624574569ce97d234873d8e05dc704f8d542cc5faa77758c1cc684); /* statement */ 
require(IERC20(_tokenContract).transfer(msg.sender, value), FAILED_TRANSFER);coverage_0xb3fcc7e2(0x714466397cca1db0522565fd20060ed2511b11f01f57ea2320bf0c2c262c6641); /* assertPost */ 

        }
    }

    function getERC20Balance(address _tokenContract, address _owner) public view returns (uint256) {coverage_0xb3fcc7e2(0x064cf701c0c122282592cd7ffefa6b1a6a9b8b367be10c6bcff3efa784a8eef9); /* function */ 

coverage_0xb3fcc7e2(0x439fd89c55f525a032dea7acb155f69c5357e0fbc7544d0ebd539ab21a67561d); /* line */ 
        coverage_0xb3fcc7e2(0xf4ec59b52fc44e211f6827cdb9f22d2718e8e8a23065e27d9cd58e6504cbde01); /* statement */ 
UserFTWallet storage wallet = ftWallets[_owner];
coverage_0xb3fcc7e2(0xa504d075e389286eadda65797772ac862faa77cc68fffaa6bac2f99de1347ea8); /* line */ 
        coverage_0xb3fcc7e2(0x7df54b1666057184db1c3edc8ab2896e662c2510f7f8ecbb3f5206e6300daa2d); /* statement */ 
uint256 index = wallet.ftIndex[_tokenContract];
coverage_0xb3fcc7e2(0x39480fae7f15b44d7587bab28c1d682ce71b9cffdf4c3ad54b3492585fe206ca); /* line */ 
        coverage_0xb3fcc7e2(0x35d455713b80bb9136d3b494c4fd0c6a2742c65ef2c05bb38693c98278706b09); /* statement */ 
if (index == 0) {coverage_0xb3fcc7e2(0x9f41200696e8207c3d3d2b41c8b510607d29b884b63d97eeafb33d6015a12daf); /* branch */ 

coverage_0xb3fcc7e2(0xa385ed25071e9ad1ac36d15af07c1d46661313750c4c3caba466228ddbe75abd); /* line */ 
            coverage_0xb3fcc7e2(0xc3b5952a8855bf9750af62e0e8b8ab3a3ca2bc2ee9b89f819358aebaf410f27a); /* statement */ 
return 0;
        }else { coverage_0xb3fcc7e2(0x6fee53b096886645d25d7a8fa3abf612a597032d85348aa6819fe1e355d94335); /* branch */ 
}
coverage_0xb3fcc7e2(0x361a4decc356eabf8af020dfefc752ab40766587c74e18e5444a5ce8545d8c23); /* line */ 
        coverage_0xb3fcc7e2(0x80d0dd078695cb88316483b2ba967eeb3520fbdcfea9c9b777ed7f28a6ee5933); /* statement */ 
return wallet.ftList[index - 1].balance;
    }

    function isPairedContract(address _tokenContract, address _chain)
        external
        view
        returns (PairingStatus)
    {coverage_0xb3fcc7e2(0xe641407264991d8fc2101eaa13ae7e477fab561359752db1eaa3ea584d747ccb); /* function */ 

coverage_0xb3fcc7e2(0xbadec3bcf91b3a4f5e6aaf8774c990466b6fb17e0696e0d6b1c06e054fdb33d4); /* line */ 
        coverage_0xb3fcc7e2(0x54a00a9612d198ecf14d7aae1ecbd581d8b0fbae3cba6955287b78b0a74f8bbd); /* statement */ 
return pairedContracts[_tokenContract].connectedRollups[_chain];
    }

    function requestPairing(address _tokenContract, address _chain) internal {coverage_0xb3fcc7e2(0xcf1278c133a3c36ae1b007c89aad4b9ec17146421049f1e77d6a81e220535033); /* function */ 

coverage_0xb3fcc7e2(0xec33d6ca8b62351850c7bcbae4a68bed30f1d7b8d97b3ae3c74259a3b79d00f8); /* line */ 
        coverage_0xb3fcc7e2(0xca4816a1af2fe924b43d41fa8b322786b423a9ef1eb82d0a503b5705206407d1); /* statement */ 
PairedContract storage pairedContract = pairedContracts[_tokenContract];
coverage_0xb3fcc7e2(0xddd2af4a5164af74773cb06a7af2317ac85eada93661205ba02a09b71dad64ba); /* line */ 
        coverage_0xb3fcc7e2(0x6d241913e1cd7131ed0e1d8935065287b68c7cb03d1407e48060090d9194dd3c); /* assertPre */ 
coverage_0xb3fcc7e2(0xf250785871c9408124032b92676ca9ce4e6f5ec097c0b9d5db20f30207810b1f); /* statement */ 
require(
            pairedContract.connectedRollups[_chain] == PairingStatus.Unpaired,
            "must be unpaired"
        );coverage_0xb3fcc7e2(0x514346cb81ad670a4e1f569433ed7e8b5f81df7d26e176e80f3ab3e47fa86462); /* assertPost */ 

coverage_0xb3fcc7e2(0x62710e2e8c46eb967b039eec27fdd2d6dc91d7cec8a511fa60aa09706f3e4be5); /* line */ 
        coverage_0xb3fcc7e2(0x2989ffc767aae40691d75a17fa1c860d07c5f1302f5017d9e745d3f88d21ca17); /* statement */ 
if (!pairedContract.paired) {coverage_0xb3fcc7e2(0x561c0b2a6d12ff9eeb82242306c59b4d92605eb2a2035ab3676b6e321e2f3a1d); /* branch */ 

            // This is the first time pairing with a chain
coverage_0xb3fcc7e2(0x263d3ca7b5d10a7f3335ae13a36119f07b37abf1534864603e4cce5b0228f1ed); /* line */ 
            coverage_0xb3fcc7e2(0x9fc6e907777605f516e3f96e933a434eaf72d1f510e86870146bf9eb1f6fabed); /* statement */ 
pairedContract.paired = true;

            // Burn existing balance since we will switch over to minting on withdrawal
coverage_0xb3fcc7e2(0x2f1fc159a4dd28f6e348549f77a3e96de7a9eec33c3a563e571ee7422ec80ac3); /* line */ 
            coverage_0xb3fcc7e2(0xc5ca0913521a36936c3643bc3501261cb2a92e8f3c59da4489668e81be11bb48); /* statement */ 
IPairedErc20 tokenContract = IPairedErc20(_tokenContract);
coverage_0xb3fcc7e2(0x312d2bf7b1fd000547c557c36ef7eaf1d7aa4ab890d4368e0004130f2c3fe458); /* line */ 
            coverage_0xb3fcc7e2(0x120d8587de285d95b9674a221087eec2b04337163f8d7d570d5f3d895d2947d3); /* statement */ 
tokenContract.burn(address(this), tokenContract.balanceOf(address(this)));
        }else { coverage_0xb3fcc7e2(0x1e6ad4c6c8f4f98336893bc3ae8ff4502b38c35303cc9f95abed380d2a466a22); /* branch */ 
}
coverage_0xb3fcc7e2(0xa869fc781d0baacfc34b79684d3b18926e33f40dbd5156ae15753839943d7b8b); /* line */ 
        coverage_0xb3fcc7e2(0x2e593143f8da5268c8b1fac586c64cec2e1249eddad3486552c3379a91ab3602); /* statement */ 
pairedContract.connectedRollups[_chain] = PairingStatus.Requested;
    }

    function updatePairing(
        address _tokenContract,
        address _chain,
        bool success
    ) internal {coverage_0xb3fcc7e2(0x416404b12869720deff3f85996686cd4c1b05e24fc6b65b4dd31d0799ae4fff1); /* function */ 

coverage_0xb3fcc7e2(0x339e0088006df2d55bc91c83dc474b3a7d93f2ce0bfd9e35335abfb8f83ecf6a); /* line */ 
        coverage_0xb3fcc7e2(0x247c37e4d45c1f315d830c86dee8c29ed58149053f7cc481050bc96716d52f24); /* statement */ 
PairedContract storage pairedContract = pairedContracts[_tokenContract];
coverage_0xb3fcc7e2(0xed5950ae28efb0b33de4f9eb211151e8e1a4a6f0cabe84ad92a76a396bdc4c40); /* line */ 
        coverage_0xb3fcc7e2(0x28756b86dd56be91bbbbd951e9b938795fed3ac686003c68c20e97fadcb179ba); /* statement */ 
if (pairedContract.connectedRollups[_chain] != PairingStatus.Requested) {coverage_0xb3fcc7e2(0x3b32723bfee70b50ac10fd5556d993655a5f35a2a97d36c26097238f626bc516); /* branch */ 

            // If the pairing hasn't been requested, ignore this
coverage_0xb3fcc7e2(0x3315f6a28c0438481bb924f6488616b1fcacce6983f2846eea47234df431f98f); /* line */ 
            coverage_0xb3fcc7e2(0x1723d407d45504d3e1a1d8a5728c51c8bc5acb6f0c97f4fec105c5e2021f7a34); /* statement */ 
return;
        }else { coverage_0xb3fcc7e2(0xca30c5126e16d828b500adc32a7a4943bb9ebf392ff8aa6132eb9e0a48ee58dc); /* branch */ 
}
coverage_0xb3fcc7e2(0xca365e619d4604351e12071464287a99b9a2a8121af9e83764ff8f9cd882702b); /* line */ 
        coverage_0xb3fcc7e2(0x547d06c76fb79d2c0bf4fbb28a070b2cefc5402d6c15a87bfc8275c79528b79e); /* statement */ 
if (success) {coverage_0xb3fcc7e2(0x7aed53e76d998734ef9190d4cfae90ac7ddded70563c94a19a53e86578cebe8d); /* branch */ 

coverage_0xb3fcc7e2(0x3a8cac7a4825d8ca95499673df5675823a60f64e41bc493b83c176f5dd719b53); /* line */ 
            coverage_0xb3fcc7e2(0xcdda5a512456aa633f4816225eb525979bacda832a71cd0608469750d373aad3); /* statement */ 
pairedContract.connectedRollups[_chain] = PairingStatus.Paired;
        } else {coverage_0xb3fcc7e2(0x7a5ebce26495055ba29778d029488c1b92bc29c9c5577bd010c01db2e1300f39); /* branch */ 

coverage_0xb3fcc7e2(0x63ecdc631b326b59e133ad65eb907014e6e1c54ce3aed67a81bf71f9c910b311); /* line */ 
            coverage_0xb3fcc7e2(0xa48306236e73542754d31e8225b43079b4bd1d2ba881c0f9cf788a96b7db2e9f); /* statement */ 
pairedContract.connectedRollups[_chain] = PairingStatus.Unpaired;
        }
    }

    function depositERC20(
        address _tokenContract,
        address _destination,
        uint256 _value
    ) internal {coverage_0xb3fcc7e2(0xcee3bcc71466a8874b77f2566afa430560cd3aea714ba2864396701838cad5d8); /* function */ 

coverage_0xb3fcc7e2(0xdf1fe0ff64a965e26f3d85bb4fa6e0e22e9bd392f1d314afdf26fb3d0facdc17); /* line */ 
        coverage_0xb3fcc7e2(0x5595d69d3f4cb786e405e782b33ec858e61280fd67827deac188e3cba9869bd4); /* statement */ 
PairedContract storage pairedContract = pairedContracts[_tokenContract];
coverage_0xb3fcc7e2(0x4c533eae9aa171c8b18a067e4cfbd5a424c9d714733699bc8c52119bfc37c099); /* line */ 
        coverage_0xb3fcc7e2(0xa2dce9aeb85d87270ca57a1b8094ff9fae1b3793e04c1af3e6aabfdadcd517cb); /* statement */ 
bool isPaired = pairedContract.paired;

coverage_0xb3fcc7e2(0x2e68ec25ce8b4d44c0d8f5aeba86ffac8c0f708e44d8709a6f74b0b22cb821d0); /* line */ 
        coverage_0xb3fcc7e2(0x8f6209b3d9b5d7bc643fed1fadb6ac696f88580746a6d0d9e1547fce7c5d1e1e); /* statement */ 
bool recipientMintNewTokens = isPaired &&
            pairedContract.connectedRollups[_destination] == PairingStatus.Paired;
coverage_0xb3fcc7e2(0xb26c1495bdc29e993fd83096418015468152d227da68bde7a45704387c65a57a); /* line */ 
        coverage_0xb3fcc7e2(0xacf269112033832c1b76ee80aa307bccc2763d5ac403bd0fb3f042f3a395f003); /* statement */ 
if (!recipientMintNewTokens) {coverage_0xb3fcc7e2(0xa709a15b09eca5a7e739670589f13b5ee7048a698ea0feecdb06e916d9870cee); /* branch */ 

coverage_0xb3fcc7e2(0xebf8cb518c5f82a9b8b76a6798d6a018009d34c0751d0bf862e90ca938bd413d); /* line */ 
            coverage_0xb3fcc7e2(0xe1224996943c6bcb649420a2a52cb105bfecae283213f3dfefd87a061f5b58a4); /* statement */ 
addToken(_destination, _tokenContract, _value);
        }else { coverage_0xb3fcc7e2(0xc65f1f1862bffa2e9664716de05643dbf0883763666d5cc76d437472649631b5); /* branch */ 
}

coverage_0xb3fcc7e2(0x0c3983d242afe6db9cc316913a8b8f1876d03d842932df478f1b1708b42ca358); /* line */ 
        coverage_0xb3fcc7e2(0xbc67a01402434151b4da6896d41371f79d79663c1e68f25410a920b55b664c81); /* statement */ 
if (isPaired) {coverage_0xb3fcc7e2(0x2ffb7c7b810b19b18170657bd6e76b55e20ebcd5907c6687cf06880b49b11554); /* branch */ 

coverage_0xb3fcc7e2(0x874d64f8e90757a9819557fbbe3510dcb19ba616c92f2d3c7368fb80bfa7d81c); /* line */ 
            coverage_0xb3fcc7e2(0xeed8bcb8b4c53d0b0c62d93137f80d39abd4c99008c23519d5503b9bb27b49df); /* statement */ 
IPairedErc20(_tokenContract).burn(msg.sender, _value);
        } else {coverage_0xb3fcc7e2(0x13642c7212bca045cabf26a8523cd5738a8e1f36c0ec1f1a117b717612df3f1d); /* branch */ 

coverage_0xb3fcc7e2(0x97aba4bb6dd2bd910bd666aaa5f6cb7ac80d42a2688278ae4b8c9ff6fe1f4de6); /* line */ 
            coverage_0xb3fcc7e2(0x2c4d2db91d39da5e280c487dca1a89ff3071185a1d470f57a8560482f53e3daa); /* assertPre */ 
coverage_0xb3fcc7e2(0xcac1614914d7670eb241ef73a2ffc169bb8393591468cb9f5735e185ee63ebab); /* statement */ 
require(
                IERC20(_tokenContract).transferFrom(msg.sender, address(this), _value),
                FAILED_TRANSFER
            );coverage_0xb3fcc7e2(0x05a1c4943994b701ad4d16a7ec449aea6416990dfd7e54338489d91963c05aae); /* assertPost */ 

        }
    }

    function transferERC20(
        address _from,
        address _to,
        address _tokenContract,
        uint256 _value
    ) internal returns (bool) {coverage_0xb3fcc7e2(0x574431183fd40d69457a3518819bce620448e2958ca686a88c34b4892bd26209); /* function */ 

        // Skip removing or adding tokens for a pair contract with one of its connected rollups
coverage_0xb3fcc7e2(0xd8e9ad0ae438149157dfc32567f2a2b832744fdf3a7285389dde73d2e1c3f63f); /* line */ 
        coverage_0xb3fcc7e2(0x572146dfee566f05d8776e760be351a0420c5615a8634e2a4a9d5328caddf911); /* statement */ 
PairedContract storage pairedContract = pairedContracts[_tokenContract];
coverage_0xb3fcc7e2(0x01ff958ddd1047807366bde19bb540abe05ceae7e5658ea43a01567203d8df0a); /* line */ 
        coverage_0xb3fcc7e2(0x76b32a1510f7a802eaa024cfe0961d346cb6cf15b307d2e674c0dd123b601151); /* statement */ 
bool isPaired = pairedContract.paired;
coverage_0xb3fcc7e2(0x3a7713cb9f36aca56725442df028aef83cb26d762f0bc6b0c104673a40bda7fb); /* line */ 
        coverage_0xb3fcc7e2(0x80c501cd027e037460950e18db3ac1b72b132ea10df9c7ba3f4653ee7a669fc4); /* statement */ 
bool senderMintNewTokens = isPaired &&
            pairedContract.connectedRollups[_from] == PairingStatus.Paired;
coverage_0xb3fcc7e2(0x18da625355d5b9655d8552291627acdc98fd0c74e2a6412d79b3454a425ddc95); /* line */ 
        coverage_0xb3fcc7e2(0x296aefc02d298e97f7b90e317b251a1e8f81b807cb089aa15cca86af5de87693); /* statement */ 
if (!senderMintNewTokens && !removeToken(_from, _tokenContract, _value)) {coverage_0xb3fcc7e2(0x2f9477d9e5086c09fb47f153a900a3b4a10b3593d0596a94b51497aa3b86b28a); /* branch */ 

coverage_0xb3fcc7e2(0xc1e048e5015d091cf4330a66583f122bd6b23617351fa9fbe8256af357a9e892); /* line */ 
            coverage_0xb3fcc7e2(0x7d13f1bb29b15e7c98fd90921d5dd5d41ac38ffc635059fe5be832933659e2c3); /* statement */ 
return false;
        }else { coverage_0xb3fcc7e2(0x9bb3e62ece5bc9c780eb8ed06c8da0d67a9c89a9997d967f2d8684d64c528e16); /* branch */ 
}

coverage_0xb3fcc7e2(0xaf21e39c6728491b4b47de7225944932430cb3211ba40ae35c85cbad25289d53); /* line */ 
        coverage_0xb3fcc7e2(0xd4cafa5be56cd404ec7fad131c72681b817c95338e3bbfbbd4d85d678d773e2f); /* statement */ 
bool recipientMintNewTokens = isPaired &&
            pairedContract.connectedRollups[_to] == PairingStatus.Paired;
coverage_0xb3fcc7e2(0x42f2840d20061d463b3262d5a1c72f9c8f2729db7063f60b06dc2ed2c18f89b8); /* line */ 
        coverage_0xb3fcc7e2(0xd6af75f466f34cfb90d622db858e525107bcbf8363d3c4c1676108c485db7f32); /* statement */ 
if (!recipientMintNewTokens) {coverage_0xb3fcc7e2(0x9556687895dbd8ae673d069d122612661fa02e00ad4a6392dbc3a72f20bfb591); /* branch */ 

coverage_0xb3fcc7e2(0x13001071ad648c2b988afbf1334a7a5fde287bea44d75e32572639a5f8412a76); /* line */ 
            coverage_0xb3fcc7e2(0x76a65f548b1ae05079d315f3cc801813aacbf78f911bc0b3377f97d246778321); /* statement */ 
addToken(_to, _tokenContract, _value);
        }else { coverage_0xb3fcc7e2(0x846a7ca443bb0bfcf6c41a6775ab6b98cdb2d24c1a4c3900cf4872b1820d2676); /* branch */ 
}
coverage_0xb3fcc7e2(0x092742ed9090cf4bb125771e5489b3ac609952b9ab18d85af406a42b83e54e74); /* line */ 
        coverage_0xb3fcc7e2(0x3334d7cb6ffe05ab7e919d400d1d25498e7dcd27bb876587b80b2e9f975c65f8); /* statement */ 
return true;
    }

    function addToken(
        address _user,
        address _tokenContract,
        uint256 _value
    ) private {coverage_0xb3fcc7e2(0x680ce8d2e5bfe65bb19fd1f829b973cda8f0fb026a126b4f35c1c033c7376eeb); /* function */ 

coverage_0xb3fcc7e2(0xa775151dc32431a732705bd34f31ac116ef86b7e97b6a9d6389a3a143673dfca); /* line */ 
        coverage_0xb3fcc7e2(0x08d325f8afbffcb6a111c7a8c2eecd115f57977dbbccb899b3e52ff9fcd85259); /* statement */ 
if (_value == 0) {coverage_0xb3fcc7e2(0x8d817ecd4cc8aaba372151bb3dc63e19de485031277cf47ac4b87aaecb618903); /* branch */ 

coverage_0xb3fcc7e2(0x5d0faf2f37d6be8d095f94abd2dbdc079256bcdd43d19e1747756cb7273df765); /* line */ 
            coverage_0xb3fcc7e2(0xd6b3d6b378ca54f9becbac1a451ea694f87684596c2b4e79e8a3e01600ccdee4); /* statement */ 
return;
        }else { coverage_0xb3fcc7e2(0xd537ea7c0d71bdb04285cdc93b04d35440287059718662872188dc957c8e0138); /* branch */ 
}
coverage_0xb3fcc7e2(0xd37c57fe688e34fa31983ce5571af8eebcde28b81e9c5a51e59c7715b1934c0e); /* line */ 
        coverage_0xb3fcc7e2(0xb8ad3b5c8aea06f2425f3655c4731f8772cd193458205ecbdd6f38047d33cd5a); /* statement */ 
UserFTWallet storage wallet = ftWallets[_user];
coverage_0xb3fcc7e2(0x4bab7a9212378f770028a8d7331721522d5f331db3d9071ba9b6b600971e58ed); /* line */ 
        coverage_0xb3fcc7e2(0xd759390d05454cee47db5bdc61ad7223a488f443ccaa98b1132393dd8a1c3e93); /* statement */ 
uint256 index = wallet.ftIndex[_tokenContract];
coverage_0xb3fcc7e2(0xf3d7876f08d26836773c906f94cb7ef8a6a0786e899a22d280c93f1f30e06832); /* line */ 
        coverage_0xb3fcc7e2(0x4d73c56776d1c128059600cede834a954610d1d69feb9e3eec9624bf05ecaf71); /* statement */ 
if (index == 0) {coverage_0xb3fcc7e2(0x588ba43fb951459a08306b62e12eb077829fcb8f36acf66198a30ee898014fa4); /* branch */ 

coverage_0xb3fcc7e2(0x939bec6e941ff76f23b3a6d710653648016975e43bd597822f747cd1f60190f2); /* line */ 
            coverage_0xb3fcc7e2(0x3a798eb716bc09f90ca7603cef6ae6db8d908e9c46ef5d266a091e0dc9eb3b65); /* statement */ 
index = wallet.ftList.push(FTWallet(_tokenContract, 0));
coverage_0xb3fcc7e2(0x53c17561200f168f24762150ebe362853e1b74fa239ba5a8b3e034eca1dce6ea); /* line */ 
            coverage_0xb3fcc7e2(0xacd727af3e2221f2e39d0f66f759e163c12a35bb58e79d056f97807f139d459f); /* statement */ 
wallet.ftIndex[_tokenContract] = index;
        }else { coverage_0xb3fcc7e2(0x450b57119d8c74d4ebdff442437a1ed88401ca8402c463f74207009d7a3d7c94); /* branch */ 
}
coverage_0xb3fcc7e2(0xaaf1364db019bcd0f315343bb9c0253b899529545b7e9b531c67ab651baa988d); /* line */ 
        coverage_0xb3fcc7e2(0xc746948d10ed09c24885908f8f8c6e2bc65481affb415bb6067e3fe93447c168); /* statement */ 
wallet.ftList[index - 1].balance += _value;
    }

    function removeToken(
        address _user,
        address _tokenContract,
        uint256 _value
    ) private returns (bool) {coverage_0xb3fcc7e2(0xa9bb915a16f8b62a958dc892a6594aadd5095013ea8362b7c6856265f15da195); /* function */ 

coverage_0xb3fcc7e2(0xfa22aa882e417ee65cb81c25fadc312886a101a2be88c7a7dd115400bad9f4f4); /* line */ 
        coverage_0xb3fcc7e2(0x5ec41edee5d11447194a314e294a8279432ee3b2f7f2fc1e177b33456c37ca0c); /* statement */ 
if (_value == 0) {coverage_0xb3fcc7e2(0x06b6dc3acd43ca2648afb06313f88c9952ab0c0646eccb93c6675c26039a79b1); /* branch */ 

coverage_0xb3fcc7e2(0xc4ca3c50c436c73480c3d630f22a755ccb95d28e357573822f2d3b2db6deb3f7); /* line */ 
            coverage_0xb3fcc7e2(0xa65dd8c02eac735141eeaaf46a0be54de3c8848d4901aa401086fe5bc6712e55); /* statement */ 
return true;
        }else { coverage_0xb3fcc7e2(0xa94e0a841fbe79cf840b1e980d395fb4c326b1cfb4e021af288891e0274792de); /* branch */ 
}
coverage_0xb3fcc7e2(0xe3bf354739b3cabe608bf8886f24a5c1bbd8d0519faa81c61e345f41226cb3a5); /* line */ 
        coverage_0xb3fcc7e2(0x5d7f6e130fef16753a24a57894607cdb623c5db1ac41dfe5b60fdff11e3149a7); /* statement */ 
UserFTWallet storage wallet = ftWallets[_user];
coverage_0xb3fcc7e2(0x0cd102ae44b40a41077502a5a9c87d7c909eee1159f57c3a79b5107b72cf2fc5); /* line */ 
        coverage_0xb3fcc7e2(0x77c7461ed2d15a12071759b3a89b55636ece72229d4c4010ba7e337b81984a05); /* statement */ 
uint256 walletIndex = wallet.ftIndex[_tokenContract];
coverage_0xb3fcc7e2(0x43fb941199cd792e8cf966b02a582a8bb125b86d20f05d30fb11a10c68741451); /* line */ 
        coverage_0xb3fcc7e2(0xf1f9b226157aff337d6dc2a71b6d2937cc3577363850da42e02f649946aac2d2); /* statement */ 
if (walletIndex == 0) {coverage_0xb3fcc7e2(0x0b06c2ee29a299358d01cd3cb1b97e5a7cdc022a28831f0582056209a6f04338); /* branch */ 

            // Wallet has no coins from given ERC20 contract
coverage_0xb3fcc7e2(0x37f6ab3b7a3ef39205ab624ad59e31c23a71be050a16e1725896a019a6802be5); /* line */ 
            coverage_0xb3fcc7e2(0xce41e34282e4c018e74e124dbd3e862c34dfed4449c21886df2f411b8d6f8711); /* statement */ 
return false;
        }else { coverage_0xb3fcc7e2(0xfcbadaf30e79d8ed0ab29c56c4ba5aad8f2a934045cb7cc8f725d98d8a53948f); /* branch */ 
}
coverage_0xb3fcc7e2(0x297151ad1989e0bf2c01b500ac214afcce7e4620f9451150aeaaec7a0c6ee49d); /* line */ 
        coverage_0xb3fcc7e2(0xe025d66b6ddf37900712fdf6ac888f6ed2afeeec02fa2362491dd937291b14c3); /* statement */ 
FTWallet storage tokenWallet = wallet.ftList[walletIndex - 1];
coverage_0xb3fcc7e2(0xfd0d982ce6a3ffc08b3a33a5468f857f8a594feba7df9c5fb5eabfa3152c529d); /* line */ 
        coverage_0xb3fcc7e2(0xdcf3c3e7aa2723fa9579d91c78026a17a714fea08aab816ae035c33fe31f4433); /* statement */ 
if (_value > tokenWallet.balance) {coverage_0xb3fcc7e2(0xb766c711c5d4d3c1083c6c9b7306d9cec44ab02f69ccaf68bbe76c34e3204ce4); /* branch */ 

            // Wallet does not own enough ERC20 tokens
coverage_0xb3fcc7e2(0xfb9446733f39e9c158162757c3f9cce047e05a8aff29c7c832dc4aecb09febdd); /* line */ 
            coverage_0xb3fcc7e2(0xa35158c048fc4ab3475444e4bf5a7ad29917647de05e1b29204eb6c0f3d409e5); /* statement */ 
return false;
        }else { coverage_0xb3fcc7e2(0xa84ca04fd38fb25c953e16556fffda8f2ee07ce22073b0b08076493232d64b2e); /* branch */ 
}
coverage_0xb3fcc7e2(0x13325e8124d09da4488409a2eabb77755dc30c001937d11ae9931b3a9e85d43b); /* line */ 
        coverage_0xb3fcc7e2(0x0f64e628a6d1b78b2ec67ce230b56b09d91a1b8bb0807b0b76c1317a187da963); /* statement */ 
tokenWallet.balance -= _value;
coverage_0xb3fcc7e2(0xd3a635ced573b70c50f25a67d5ee03e697952b3ed8db059c5d51530d65baf95b); /* line */ 
        coverage_0xb3fcc7e2(0x372211ee5bf00880a0e87aa102822bce725b6ff0e12bfdd343f6978aeba6bd22); /* statement */ 
if (tokenWallet.balance == 0) {coverage_0xb3fcc7e2(0x4dc08cb9bc85d142da2e2440790cdc2c066cc24b8ca191beb92ae720e6f9fa48); /* branch */ 

coverage_0xb3fcc7e2(0xb7aed4c9529bb0e8bc3f095bd59adb503c6355598c84497a898c91b8d15fbf20); /* line */ 
            coverage_0xb3fcc7e2(0x61c1d2473fd9c04db8abb03c3e770dd8afc7705112a282973f8ca95fa2ddaee1); /* statement */ 
wallet.ftIndex[wallet.ftList[wallet.ftList.length - 1].contractAddress] = walletIndex;
coverage_0xb3fcc7e2(0xcdc457c42d179c4ce030c0671922c272fb236da2996aa56e952314b39f475f92); /* line */ 
            coverage_0xb3fcc7e2(0x71b9354c860d7a2e141883d2e66d0a1425f417027230fca91056ebc3c65c9290); /* statement */ 
wallet.ftList[walletIndex - 1] = wallet.ftList[wallet.ftList.length - 1];
coverage_0xb3fcc7e2(0x566ff96c9f6af5cc7a2a2cac6823637f77c2e0e0bb02bf9496b3cf0ebed2729e); /* line */ 
            delete wallet.ftIndex[_tokenContract];
coverage_0xb3fcc7e2(0x1a83c2309827ae46291d18e970bd201c3ecd1b6da5552aa0a59b531eb7ca5521); /* line */ 
            coverage_0xb3fcc7e2(0x619e4ceb0e88cb67231022f72651943e9b7632657f9ea0f96dc0ee1e8ccda554); /* statement */ 
wallet.ftList.pop();
        }else { coverage_0xb3fcc7e2(0x5645382cf53c0ad78592041d9794c0d53fbe480e08b84e134fb1718e58fdbe34); /* branch */ 
}
coverage_0xb3fcc7e2(0x88fa0bcc60b149821d0085961e4b4c7cbe7c32d98ea82b51185c574fb87b0d0e); /* line */ 
        coverage_0xb3fcc7e2(0x8e2b7690cf0af8b51074eaf0133becae92f0f899b353cbe407512d903a83bb7a); /* statement */ 
return true;
    }
}
