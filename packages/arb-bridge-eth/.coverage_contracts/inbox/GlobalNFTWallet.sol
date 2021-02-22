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

import "../interfaces/IERC721.sol";

contract GlobalNFTWallet {
function coverage_0x269c27f7(bytes32 c__0x269c27f7) public pure {}

    struct NFTWallet {
        address contractAddress;
        mapping(uint256 => uint256) tokenIndex;
        uint256[] tokenList;
    }

    struct UserNFTWallet {
        mapping(address => uint256) nftWalletIndex;
        NFTWallet[] nftWalletList;
    }

    mapping(address => UserNFTWallet) private nftWallets;

    function ownedERC721s(address _owner) external view returns (address[] memory) {coverage_0x269c27f7(0xccba01c1b13bd45c57de486e40b6d6288651efc52c2d6b5228e40c8ff3475651); /* function */ 

coverage_0x269c27f7(0x1c2369e4ad6c0531609880f351bdb6c35f99a625ce4b4d4df1197d78b0c1525b); /* line */ 
        coverage_0x269c27f7(0xa568195835de72132e733f961ec6a48933af1b15dcb889c478222cb811f3f750); /* statement */ 
UserNFTWallet storage wallet = nftWallets[_owner];
coverage_0x269c27f7(0x1788ae363a0263e2c5a746db1059ec68fb35ade57f189abaedb6aca0431b2814); /* line */ 
        coverage_0x269c27f7(0xd7a5e91819340514ce7aa7a859016e17c61696e59f6de1308d537a93d46d62c1); /* statement */ 
address[] memory addresses = new address[](wallet.nftWalletList.length);
coverage_0x269c27f7(0xf91a86093812dbba52528ac71abb5bef195773e563ea3745356de9be3023d07a); /* line */ 
        coverage_0x269c27f7(0xa0bc9715e4e5962b9820b869153521a70d36480ab99c5dc0c8a3b6278f1b3dd0); /* statement */ 
uint256 addressCount = addresses.length;
coverage_0x269c27f7(0x50ae4aeeb007c0e5011254954941dc1afe3daa66b2f4f7e8d050922dc3c9107c); /* line */ 
        coverage_0x269c27f7(0xced2ddf602d258aaf2d4be6e2d3d5809481bfd02aa6d2e59dbc41f501fa857c0); /* statement */ 
for (uint256 i = 0; i < addressCount; i++) {
coverage_0x269c27f7(0x556e6c8228560e342956d71fe4972a231004f220b9016971adeaa70a4986fc6f); /* line */ 
            coverage_0x269c27f7(0x8cabf9fe9a0493b06e8729e5db160133732c4e14ee9337307821e306944e145e); /* statement */ 
addresses[i] = wallet.nftWalletList[i].contractAddress;
        }
coverage_0x269c27f7(0x60637abb96399d1874e9b77e61346f93e8df6f88f640452e5697ef47ccbb88bb); /* line */ 
        coverage_0x269c27f7(0x645e0b408f56340b2deca1d73a0592518e64a5b1ea6b27bc0a9250eeadd5a488); /* statement */ 
return addresses;
    }

    function getERC721Tokens(address _erc721, address _owner)
        external
        view
        returns (uint256[] memory)
    {coverage_0x269c27f7(0x0be7781b1f98c5da89b92c62946675fd6a60b8f471479149d2c35e4dd7bd61f9); /* function */ 

coverage_0x269c27f7(0x9c66a08640d820e22ce64784de152018bd77028316dd70ba69b182dd1312f194); /* line */ 
        coverage_0x269c27f7(0x85fc1b356416ca046e7dbf431fe8770fd6f52aaeb13df62d7c2590dc01450fa9); /* statement */ 
UserNFTWallet storage wallet = nftWallets[_owner];
coverage_0x269c27f7(0xba6bcdc72ef35a320c1c22141e3dca48be5356ba046d39102a98effbc7847466); /* line */ 
        coverage_0x269c27f7(0xd8fca540ea480088abbfd31dc6b62e4a4aaef77b79e6788cd77aedeced95e254); /* statement */ 
uint256 index = wallet.nftWalletIndex[_erc721];
coverage_0x269c27f7(0x4649e9abdc9449d2d4681cbd3710648e773861f15307c83b8248070b2449581b); /* line */ 
        coverage_0x269c27f7(0xc31183f9f81332bbf9c7edf75cf52ba6ec29890db600b2da42ab6a8c98fb9a6c); /* statement */ 
if (index == 0) {coverage_0x269c27f7(0x06b9d8b77ce0e72997878e3051c6b74e9afc0781b42aca99c568574ca62c1bcf); /* branch */ 

coverage_0x269c27f7(0xc5585153247e2a2d4cf6986b12c057cfebc6d79c40194039a2258563ddceb6b2); /* line */ 
            coverage_0x269c27f7(0x897108ddecba66a846719fe92e89ebc5fbe776c9667d212dbb0ce27299e10e12); /* statement */ 
return new uint256[](0);
        }else { coverage_0x269c27f7(0x2e525cfecefaa6a8c3c8c97a47ac1aeffae6ef630397acaee26230a59b3b9ce5); /* branch */ 
}
coverage_0x269c27f7(0x3e78d895fa824cac89071dce0cc559bbaa36e1700ee2e04abfc4b80db64c2dd6); /* line */ 
        coverage_0x269c27f7(0x28bf809569125a4f481c9f15fe8f225463277e78f755b74e0b8462ae03b61ef0); /* statement */ 
return wallet.nftWalletList[index - 1].tokenList;
    }

    function hasERC721(
        address _erc721,
        address _owner,
        uint256 _tokenId
    ) external view returns (bool) {coverage_0x269c27f7(0x53e85cccb98cf7f212b9e7015797dacf2c667edca262d87354a074d7d2c5abb4); /* function */ 

coverage_0x269c27f7(0x7d698b1f06dafcfd874442c28f2767044ec6b396817418634a7d39dc96e77324); /* line */ 
        coverage_0x269c27f7(0x7bd02d61d20d45a4cb23862099060c48fee9078e744bcb234202b96b6779755f); /* statement */ 
UserNFTWallet storage wallet = nftWallets[_owner];
coverage_0x269c27f7(0xbb986b28ca902fceeec75379ed28975a6ea435564ab844432ce059df5e78d2b3); /* line */ 
        coverage_0x269c27f7(0x17a6553da1585a8f3ea4418de9ac67a8ac916d57141a41111060bfebefcad836); /* statement */ 
uint256 index = wallet.nftWalletIndex[_erc721];
coverage_0x269c27f7(0xa0d18b663bf9559c0a46fb0d4ef1ab31c3929e6268548eb510963c2eab2a8999); /* line */ 
        coverage_0x269c27f7(0x9cfd438b4d0f14883fb60b6f1374fb4652eb26bd768f35087d3ed39f4bee0886); /* statement */ 
if (index == 0) {coverage_0x269c27f7(0xef9ff101356c7101b85f14197fa8c51352f453546c77bbb35b02608aa434f923); /* branch */ 

coverage_0x269c27f7(0x80067bd080df7c0e18753902c9a82962e6e16b207da3e2b275711de3f8e2a343); /* line */ 
            coverage_0x269c27f7(0xb4a8335a8ed3971dc91afd86766af1e8563e29e90400e18c10210d1e4f4d4869); /* statement */ 
return false;
        }else { coverage_0x269c27f7(0xd9e10cb2bd6ee13f343572514fbc13687cf8dc25dd0986b51c4041221787ff88); /* branch */ 
}
coverage_0x269c27f7(0x86595940fa7eadb7cd99d4d08009a6e958aeea702cc93fdd0da57075815d9bb1); /* line */ 
        coverage_0x269c27f7(0x23a0ad0ef835dfbefa693656b84af2e78199b0c2757f2f0e40a3485067c58750); /* statement */ 
return wallet.nftWalletList[index - 1].tokenIndex[_tokenId] != 0;
    }

    function withdrawERC721(address _erc721, uint256 _tokenId) external {coverage_0x269c27f7(0xba0cee3cc2d549c7755a069c099bc9c15d70f796ced98db187b56833b143beb4); /* function */ 

coverage_0x269c27f7(0x6d0f94bc74e0d545402a62220c8cf6d174048c874120c2a5d77f21da989e5716); /* line */ 
        coverage_0x269c27f7(0x0a9fc9bc7e0309057fb3edeca7f4fc4a054a51d4bd6be7d9179f6f5e3838b244); /* assertPre */ 
coverage_0x269c27f7(0xe0d3e697bbb90d3f5c81c51fae731643bd407e3895069d867169058e8bd73eae); /* statement */ 
require(removeNFTToken(msg.sender, _erc721, _tokenId), "Wallet doesn't own token");coverage_0x269c27f7(0xfcc1be93810fefda36de3a845f2c59d1bf4e56c8adb39e5102ddee4ad85c3bc6); /* assertPost */ 

coverage_0x269c27f7(0xa9fd5ae9d3a1d4dfbab70e7d597694a82ef5a6d4ee72299c19de7a4607adbe63); /* line */ 
        coverage_0x269c27f7(0xed3c37d817c750ab9285d56bcfbeb78068171016d1c3587aa51d0f46b89e453d); /* statement */ 
IERC721(_erc721).safeTransferFrom(address(this), msg.sender, _tokenId);
    }

    function depositERC721(
        address _erc721,
        address _destination,
        uint256 _tokenId
    ) internal {coverage_0x269c27f7(0xcb3940155622c2f28856e2788f6b6496ac60e7c816ed9c39891896493fc60fe8); /* function */ 

coverage_0x269c27f7(0xc21b560bcdd9317d2a74b3c8137c4379fc222b8249e77b388ec1c66802b1834d); /* line */ 
        coverage_0x269c27f7(0x760ac27d0678c9c749e2960b6d237615cd67efa0d9e54c0586d12c237f63eae9); /* statement */ 
IERC721(_erc721).transferFrom(msg.sender, address(this), _tokenId);
coverage_0x269c27f7(0x0ed826028db27b0defa012ec96b040f64c4aaf44005c38ee253895a14c9a9996); /* line */ 
        coverage_0x269c27f7(0x96f701a9760cf37b241439f97399fc4dc2e0664f0d5c090e249eb173bec8c369); /* statement */ 
addNFTToken(_destination, _erc721, _tokenId);
    }

    function transferNFT(
        address _from,
        address _to,
        address _erc721,
        uint256 _tokenId
    ) internal returns (bool) {coverage_0x269c27f7(0xf196cf811ed7096eeda2d5a06ab8a060aead93b7c6599ab687a7826d26f5033d); /* function */ 

coverage_0x269c27f7(0xc02ec26eec88925ce97853306d2895532a35bd7caaf8dd856e8fa455f833722f); /* line */ 
        coverage_0x269c27f7(0x1280a6f6e76f73e92cc4c602ff712c9b4c909b5d424aba43e8fc743c9c392e3c); /* statement */ 
if (!removeNFTToken(_from, _erc721, _tokenId)) {coverage_0x269c27f7(0xfb42cd42796ca34adf8e8ea5f93b93ae9a3f68148a067e198cf7bc7d240bea86); /* branch */ 

coverage_0x269c27f7(0x02825e1873935b1892c1f5cc74cac7f7c536f3eac7aa5550b7ba1fb5cec6334f); /* line */ 
            coverage_0x269c27f7(0x2661dd7fba91207f7a52f1bb7b32f8aacabf7270e5cca0076aae97b432b0917e); /* statement */ 
return false;
        }else { coverage_0x269c27f7(0x8c015d85511bf57687b757da7419eac3fe4d63a5e0d2b53127e85f5fd8c243e0); /* branch */ 
}
coverage_0x269c27f7(0x6ed48d8522f5b2615ced09c32e30047670562ba4a9420f39ad3d93bf1ff04249); /* line */ 
        coverage_0x269c27f7(0x1af365bc1abc7dded4a4f8222f6ae4d1a93560b6403435ba075797e6c178cf83); /* statement */ 
addNFTToken(_to, _erc721, _tokenId);
coverage_0x269c27f7(0x8b81e7655ed04556cc2ee27eaff2a5cdc8ae254e164d1481b3cc0a2a6c9fc5a4); /* line */ 
        coverage_0x269c27f7(0x95ecc2ceebd7f8ea2d9d32beddc1ff2d828fd2c1ffbb0c7011fa7abefd879f0e); /* statement */ 
return true;
    }

    function addNFTToken(
        address _user,
        address _erc721,
        uint256 _tokenId
    ) private {coverage_0x269c27f7(0x65fab6fb9ddcc09df2d7390a2d11200986f887788ef8fd57f2b0273700aa7af4); /* function */ 

coverage_0x269c27f7(0x24eaf295cab3197549aaa19884676370fae0d413159dd9440201e65a5ee263b3); /* line */ 
        coverage_0x269c27f7(0x50cda3be9e28e821af96261a55673ebdd5ba21399d1d2a1db852ac0d24c3e927); /* statement */ 
UserNFTWallet storage wallet = nftWallets[_user];
coverage_0x269c27f7(0xd3b2daa5d52470e6fa959f6040959a55fa8919fcc369fdefba38f45aef794db6); /* line */ 
        coverage_0x269c27f7(0x1ac40f4857165b805b47395481efbb3071300bc8a4cef451910853662ba100fa); /* statement */ 
uint256 index = wallet.nftWalletIndex[_erc721];
coverage_0x269c27f7(0x885d63e138860eb3bbeea6c37d983e4ba776e56c7ef62687a7e761295a410275); /* line */ 
        coverage_0x269c27f7(0x7a734c7bdba7b92949c37f03d1350973bc1f5286392539dbf9185e758ab0f654); /* statement */ 
if (index == 0) {coverage_0x269c27f7(0x1552ed718d553df7056d0b3d83287ae22884877e059cb5286552a4f6f1313510); /* branch */ 

coverage_0x269c27f7(0x3905595441049f117dd7d0d9217afd7ea38f97bbdfeb32e83cc1c582adac766e); /* line */ 
            coverage_0x269c27f7(0x6ba5fcdc8db791375b0ddcf94d76b47a0cbd57e19f988843adc42593b7fc4d1b); /* statement */ 
index = wallet.nftWalletList.push(NFTWallet(_erc721, new uint256[](0)));
coverage_0x269c27f7(0x738c70b29c66ee74d14508c9ddac40e2f9463abca00223e3fec475a3a79fbd55); /* line */ 
            coverage_0x269c27f7(0x65171fef778a00343594bffa52dd27d720f3a93a57b047992c3ff2375c7c2aef); /* statement */ 
wallet.nftWalletIndex[_erc721] = index;
        }else { coverage_0x269c27f7(0xeef864aef1c75fadf6a00c3aac6eb44ec17ae72c0fda3d32b314412fc32aa12c); /* branch */ 
}
coverage_0x269c27f7(0xe06d3e0bc95a2209e2045a2f201de36951c2df18fe820bfdb0e7e3546c8076b0); /* line */ 
        coverage_0x269c27f7(0xa85f3a4afef7be8f6c4a6db56bf9c2866a17ee1a7eab414a8c48bdb9729fe682); /* statement */ 
NFTWallet storage nftWallet = wallet.nftWalletList[index - 1];
coverage_0x269c27f7(0xec65a370e0a121c71dc0662dd5018cec176edb75ee92c53e3fae19f4fdf15a4d); /* line */ 
        coverage_0x269c27f7(0x3b08c650dacd90f24a791c0856bf1eac3c1ccac020273cc42137c28ea4b03b07); /* assertPre */ 
coverage_0x269c27f7(0x6ee9dc23e4c340f91d72201bf37aa837cbf38c8f3cc7ceece37e732aaf3caa1b); /* statement */ 
require(nftWallet.tokenIndex[_tokenId] == 0, "can't add already owned token");coverage_0x269c27f7(0x0aa9f4a4bf162f3015574512a3c6378a5f846d0c4cf2e3589504d1a23ca8e361); /* assertPost */ 

coverage_0x269c27f7(0xc81e406ebd036eb301cd0dd4678e4fc7a969b15a1fe26f7c8b56d05ba29d8a30); /* line */ 
        coverage_0x269c27f7(0x5a112596023a8045b948159c17a3251a52ef9a4387e2c8ce8113401ee7188a0b); /* statement */ 
nftWallet.tokenList.push(_tokenId);
coverage_0x269c27f7(0x55e6a5386bc9a28227e504f13ab1fa80146e1cdafbfb1b87cb619ae7f7c882fe); /* line */ 
        coverage_0x269c27f7(0xce31aa56bb93f3e117342e9e41653e2b08ca7ad2776a70e167dee84698910274); /* statement */ 
nftWallet.tokenIndex[_tokenId] = nftWallet.tokenList.length;
    }

    function removeNFTToken(
        address _user,
        address _erc721,
        uint256 _tokenId
    ) private returns (bool) {coverage_0x269c27f7(0x807cf514ac7b45c236899e61e4e227829a8dd5010387732e029a7370033d5bcd); /* function */ 

coverage_0x269c27f7(0xf6eaf1ef611e677be73131649b53fb3a544b34d2172f9a239e672164f34a51ac); /* line */ 
        coverage_0x269c27f7(0xa3e1b687e934baf83ef0bb5e05232dcd1c6f2031fc76695c0a86460d801c3452); /* statement */ 
UserNFTWallet storage wallet = nftWallets[_user];
coverage_0x269c27f7(0x4bfdb69785b86caad966e5587303fb37a454b6c8a7073514bdfb21e55bca4ac7); /* line */ 
        coverage_0x269c27f7(0x1ad2f80863f327e02d86dbcdbebadaaa00540b441af7025a8476f8ab63ad47f0); /* statement */ 
uint256 walletIndex = wallet.nftWalletIndex[_erc721];
coverage_0x269c27f7(0x6a9fd0436dfc4d24e8fa45be89b16a5fa4e9569cef725d7358c41a70ad13ead9); /* line */ 
        coverage_0x269c27f7(0xbb3369c8b83051d406e28868aa531de9603907385f98feeba08ef28ef4c2f487); /* statement */ 
if (walletIndex == 0) {coverage_0x269c27f7(0x37e0f81d067f37dddb3c84f2910934988e8d57a6fed499e0fd310741c015c7de); /* branch */ 

            // Wallet has no coins from given NFT contract
coverage_0x269c27f7(0x8bdd5075930277067d9fc1544a2403762d94002750ea91c2f7638739ff485556); /* line */ 
            coverage_0x269c27f7(0x4a835f735aa9d0240829f5bf26dda464c913c4d57ee23544a7288a08eda64c28); /* statement */ 
return false;
        }else { coverage_0x269c27f7(0xb1069e5e9beb7e1417f2853844ccd267687e3ce290c29a72900105880f2a079d); /* branch */ 
}
coverage_0x269c27f7(0xd2be427713a85265f0b416a5998a92503342cbefddcb36704c3e23a61d668c1e); /* line */ 
        coverage_0x269c27f7(0x9f38714434b43067ad6716ef4fd39872c190fdcdc50e855d73cdb97bdfedc795); /* statement */ 
NFTWallet storage nftWallet = wallet.nftWalletList[walletIndex - 1];
coverage_0x269c27f7(0x3a9a9497ec628228dccf6facef0bcf4df40c2436de1627ee414bac935628d861); /* line */ 
        coverage_0x269c27f7(0xfe0710b78c92ec043bd62c59383796706050f3dc97b333b89b4323a9de9ddd8d); /* statement */ 
uint256 tokenIndex = nftWallet.tokenIndex[_tokenId];
coverage_0x269c27f7(0x1bcf6cd53ae645c9b3be0ac9d31b555990466f8aaafd4297078468bf06c81bae); /* line */ 
        coverage_0x269c27f7(0x08d0bd118934e85aba7e472ccc33a61b75c3e42c39d1ca990b85bdf29f88b756); /* statement */ 
if (tokenIndex == 0) {coverage_0x269c27f7(0x91e4d8d5c2a25034fd30f2e34751278d84cbc7441775b56b3249907c54f36223); /* branch */ 

            // Wallet does not own specific NFT
coverage_0x269c27f7(0xed4dd92bc2a58e43a9cf8e98554686b252efd6ccdafb9cab5d45fa168fb7a0b0); /* line */ 
            coverage_0x269c27f7(0xa0de9af1174242a2d6d581980e14247ffc8ceb4fe248216ded4c7fff89c6af04); /* statement */ 
return false;
        }else { coverage_0x269c27f7(0x1918a02b165bb7c2f5adcfe5924390212813bdc6925ff36b32b45dfdda03b19b); /* branch */ 
}
coverage_0x269c27f7(0x10be05e928f3a8d97f679e5ba979a3379b6b96102060438a383dd4072a22d0fa); /* line */ 
        coverage_0x269c27f7(0xee3337fb5f39ebb90605bf1a6ee58b898ef45f67dd16b166e3ab132761af653f); /* statement */ 
nftWallet.tokenIndex[nftWallet.tokenList[nftWallet.tokenList.length - 1]] = tokenIndex;
coverage_0x269c27f7(0xfe1cb1fc16bb9064b64064d95b8ca9637a96851de5dc36c5f7003e1b337e21d0); /* line */ 
        coverage_0x269c27f7(0x5b3d0f1a6aeee46203b628301b32274c6397dd41eb9dd83bdcd2a2dbfb8d6ae7); /* statement */ 
nftWallet.tokenList[tokenIndex - 1] = nftWallet.tokenList[nftWallet.tokenList.length - 1];
coverage_0x269c27f7(0xd97b9b405f301b625c088a76abd908eddd9beaf4e5b224e721f44a0ec3e1061a); /* line */ 
        delete nftWallet.tokenIndex[_tokenId];
coverage_0x269c27f7(0xaca79a91b1728aa1e80c64f3ed5a2fc4a476d48b2ecd59efcf69e806359c6080); /* line */ 
        coverage_0x269c27f7(0xe7ca4f69c4be9c782167f15838e343730c744f99698d0051b655621fb3efccf9); /* statement */ 
nftWallet.tokenList.pop();
coverage_0x269c27f7(0x59f719e1da74b14f807bc9b26c412366a5ee51750c71cf4e8ac2ebb62ed124d9); /* line */ 
        coverage_0x269c27f7(0x153377cb73c6ba98beff71c05992131d21b76c2f797cf43e22ded663286651d8); /* statement */ 
if (nftWallet.tokenList.length == 0) {coverage_0x269c27f7(0xe2dbf125cf459c8908b2736667c7bec0fcc7fb9c7e5c26d834281b93038d5b0d); /* branch */ 

coverage_0x269c27f7(0x7feeda21ea3815dfd5a51e9ee4414239294acfb2810d2e78fbc081dfb41390ca); /* line */ 
            coverage_0x269c27f7(0xcac399a7d5aff164639be3d1d180e99b4a1f41e966fa07af6f62bcd10dcc8ff3); /* statement */ 
wallet.nftWalletIndex[wallet.nftWalletList[wallet.nftWalletList.length - 1]
                .contractAddress] = walletIndex;
coverage_0x269c27f7(0xa4a2f1292b8843054fb9ec57d44205d4f1cca057341c5265749376e697d4650c); /* line */ 
            coverage_0x269c27f7(0x0513b0147a4fcc36e0148ce7fe3eabfc9183ed8a72d23cf2bba834bb7daa5f09); /* statement */ 
wallet.nftWalletList[walletIndex - 1] = wallet.nftWalletList[wallet
                .nftWalletList
                .length - 1];
coverage_0x269c27f7(0xfb32e13f060453adeee7f61ed2fe19fd9ffe181070c50b86415f2b4bff55112e); /* line */ 
            delete wallet.nftWalletIndex[_erc721];
coverage_0x269c27f7(0xcaaf2a31c2ae86b93e47dceb9faf5cedd2a081af8e5196d7ef8dacf183e56dbd); /* line */ 
            coverage_0x269c27f7(0x2d680590532c69fd7ff808ec65f4670474ca8d8d50c71451083c269da7ea35a5); /* statement */ 
wallet.nftWalletList.pop();
        }else { coverage_0x269c27f7(0x9c02ac63cde57fb48e72a02281205eaf7a91e3b3ca72f85946cabfa815899289); /* branch */ 
}
coverage_0x269c27f7(0x8fee4f3772f1196f9462d224b5905453c1de8a4273325a9d287f73388f9296bf); /* line */ 
        coverage_0x269c27f7(0x6303c4a08b083bbe39e1a75c494656795f6ec03d614e6a5dd1e8f7f69ba2becb); /* statement */ 
return true;
    }
}
