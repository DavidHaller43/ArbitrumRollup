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

///      This algorithm has been extracted from the implementation of smart pool (https://github.com/smartpool)
library Precompiles {
function coverage_0xb85a875a(bytes32 c__0xb85a875a) public pure {}

    function keccakF(uint256[25] memory a) internal pure returns (uint256[25] memory) {coverage_0xb85a875a(0x7ba4e3d3a5b64e8fdb894275bff135c8aee2575dc0fadad3f4831a7286edd9b0); /* function */ 

coverage_0xb85a875a(0xde6f876c0184b1e4a21f9006f16e2e58d8c2ac6816c2c480b99f0f6679177fc4); /* line */ 
        coverage_0xb85a875a(0xbd71636885456394cfaa758e669a77d952a1515855361bdd3c124f2e3c23e115); /* statement */ 
uint256[5] memory c;
coverage_0xb85a875a(0x1b43bcfd15e03d626faae016e06f55c840c52b8f3aab509d80dbc94e69572160); /* line */ 
        coverage_0xb85a875a(0xc9933223242d9c86f76fe08125d1a6fd3ab53c7d3ec9e04b02ed40ff83a704c6); /* statement */ 
uint256[5] memory d;
        //uint D_0; uint D_1; uint D_2; uint D_3; uint D_4;
coverage_0xb85a875a(0x0f740e2cc4c33554ac69266d4e276acc296ee1b475ea226b9147cca757b25e82); /* line */ 
        coverage_0xb85a875a(0x93c5563a69dcf9908720a9123011b9b0d3a2a74ddc958adcdc84b99e7db04a05); /* statement */ 
uint256[25] memory b;

coverage_0xb85a875a(0xca9a57825e9a00ee9a5496b27eae603121d6a72a17240520e5d93bd1ea8e4dde); /* line */ 
        coverage_0xb85a875a(0x4adfc9180d7c7a1b292af3165136838784ec0209db2764b75c221ca31c46a0aa); /* statement */ 
uint256[24] memory rc = [
            uint256(0x0000000000000001),
            0x0000000000008082,
            0x800000000000808A,
            0x8000000080008000,
            0x000000000000808B,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008A,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000A,
            0x000000008000808B,
            0x800000000000008B,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800A,
            0x800000008000000A,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008
        ];

coverage_0xb85a875a(0xc79351e1a482f31a5f77104e9dd9cbc25e4ed8b098a1a82b8ef10a9fbc1b609f); /* line */ 
        coverage_0xb85a875a(0x2a69fee9adbec1978ac7a46ac4ebc6b3f413e95fcb8d186283c08b8642838775); /* statement */ 
for (uint256 i = 0; i < 24; i++) {
            /*
            for( x = 0 ; x < 5 ; x++ ) {
                C[x] = A[5*x]^A[5*x+1]^A[5*x+2]^A[5*x+3]^A[5*x+4];
            }*/

coverage_0xb85a875a(0xafcb1527de0fbf036f0aefa786de179e8972e08f8afacf3004816fb995088305); /* line */ 
            coverage_0xb85a875a(0xb9b87ec3431ccdbce8dab3f30183686dd1cd69e4bef7b5e5a273ae0e2008ac5e); /* statement */ 
c[0] = a[0] ^ a[1] ^ a[2] ^ a[3] ^ a[4];
coverage_0xb85a875a(0x13d82418923303394f2573cd363f3255060180139fcfb6e3de2f9d48a38c8e0d); /* line */ 
            coverage_0xb85a875a(0xca747fcfa8983f48bfcf5c03cf09155aa923096e310e0a6e164a77f15a54d2aa); /* statement */ 
c[1] = a[5] ^ a[6] ^ a[7] ^ a[8] ^ a[9];
coverage_0xb85a875a(0x72100de1625018a8a7c32134edd0a52e8f38b524bce4e0b016725d45fe7f0037); /* line */ 
            coverage_0xb85a875a(0xae26920d0a87e451938172591afc3177950c5bd414669002dd8d6122a435213f); /* statement */ 
c[2] = a[10] ^ a[11] ^ a[12] ^ a[13] ^ a[14];
coverage_0xb85a875a(0x55ad76a3c52ebd9aba5670f9a1bd8c436d176a5270c413c3f20b4ebbeb3ad0d8); /* line */ 
            coverage_0xb85a875a(0xfc75074f07550457a3bbafa61b551a92b639b2ccf19a1bf594942eb279c52c9a); /* statement */ 
c[3] = a[15] ^ a[16] ^ a[17] ^ a[18] ^ a[19];
coverage_0xb85a875a(0xd2877bcf0c1ae38efbe06a385803de7ce0d9a24cb85f130a13f89ff48a65beef); /* line */ 
            coverage_0xb85a875a(0x393bf2603422df524a2694ddcce53ba6b34db6924d3a167ccfc71e2ba03cbb37); /* statement */ 
c[4] = a[20] ^ a[21] ^ a[22] ^ a[23] ^ a[24];

            /*
            for( x = 0 ; x < 5 ; x++ ) {
                D[x] = C[(x+4)%5]^((C[(x+1)%5] * 2)&0xffffffffffffffff | (C[(x+1)%5]/(2**63)));
            }*/

coverage_0xb85a875a(0x0cdd9dc78cd012c119babbb88dfa6261e685c13c76e1febe1c08cb52c875eabb); /* line */ 
            coverage_0xb85a875a(0xd7ca4feb7b73ea71704e2c4301c1e1eee30e21a919aff609c774f1ec5e9ffafd); /* statement */ 
d[0] = c[4] ^ (((c[1] * 2) & 0xffffffffffffffff) | (c[1] / (2**63)));
coverage_0xb85a875a(0x6261bdb19a9c36e2a292e8c29e916a4df83fce3c20514c105576d0f9899bb96c); /* line */ 
            coverage_0xb85a875a(0xf3c8016adfcbb6bf94e70fb1d41bf00a29c0d032ebb8bac9d13a5102bd609551); /* statement */ 
d[1] = c[0] ^ (((c[2] * 2) & 0xffffffffffffffff) | (c[2] / (2**63)));
coverage_0xb85a875a(0x78b11b93a357d80623c45a85d071668e73232c3950a8b87299a2c69488fb0afb); /* line */ 
            coverage_0xb85a875a(0xb6e109b02e5075730607dd8dedecb26f7d13ac0b24c6c8ea0abe819fedef4026); /* statement */ 
d[2] = c[1] ^ (((c[3] * 2) & 0xffffffffffffffff) | (c[3] / (2**63)));
coverage_0xb85a875a(0x4b3004ed94900fc2078b3d4a1f4b99a95e7a5b112c03a2accb53b0fdadf6cc75); /* line */ 
            coverage_0xb85a875a(0x63a527559bd87a4a23046e5fd2f258eb26e692e8a64bdd945de9174b0ab8d83a); /* statement */ 
d[3] = c[2] ^ (((c[4] * 2) & 0xffffffffffffffff) | (c[4] / (2**63)));
coverage_0xb85a875a(0x7ce11002fadff3c923299a538dc1c4d66f73651889dd6c033e1d92bf862df121); /* line */ 
            coverage_0xb85a875a(0x32179ac40f1c1b302e879e9b519a5aad56060b099f3828efe5a1a45e7ecb89aa); /* statement */ 
d[4] = c[3] ^ (((c[0] * 2) & 0xffffffffffffffff) | (c[0] / (2**63)));

            /*
            for( x = 0 ; x < 5 ; x++ ) {
                for( y = 0 ; y < 5 ; y++ ) {
                    A[5*x+y] = A[5*x+y] ^ D[x];
                }
            }*/

coverage_0xb85a875a(0x8cae53e2d23de34cc07e4cba3ee746442b8b1274c8433dcd53b56d5eedaa08f1); /* line */ 
            coverage_0xb85a875a(0x621a76b180108154afd51841b013b771a07fdf033d50d71e74ba679970179b09); /* statement */ 
a[0] = a[0] ^ d[0];
coverage_0xb85a875a(0xba742dc48882e9072aaa92bb6d18dbef4f7d42c10f16e2208ffd8ec86e697f14); /* line */ 
            coverage_0xb85a875a(0x91f06719326b0486d23ccf8e729304c1e0730484a68f7959b7e29b453ad838cb); /* statement */ 
a[1] = a[1] ^ d[0];
coverage_0xb85a875a(0xfb1b84b66db316f9a828d88a319b80d3de6c2a5dbacc81813d95d729b725467f); /* line */ 
            coverage_0xb85a875a(0xd198cf11c7d26e8cdcec293309573926ee0101a69c006a4ae06de679f07e10aa); /* statement */ 
a[2] = a[2] ^ d[0];
coverage_0xb85a875a(0xab65ccb46e71c48e76ca48dba3cea84214c36c20377b4ed3317d0c4ba47f40bf); /* line */ 
            coverage_0xb85a875a(0x299bd7eb1e668fbec830933352a8ac36f563de033989d6bbf9d96686ede9df3f); /* statement */ 
a[3] = a[3] ^ d[0];
coverage_0xb85a875a(0x8d23b1aa59e7f76a5c3f84f1505dfd95282586940c98db1a8cbb26db9f8d47d6); /* line */ 
            coverage_0xb85a875a(0x472cbee431cd8c69dd8c350ddae077e03bd25b32ccce920082fc0afc115160f0); /* statement */ 
a[4] = a[4] ^ d[0];
coverage_0xb85a875a(0xe87a2f266c8762798d12bc4db142a9e2f353713d9f7c6156bb81f155b376b685); /* line */ 
            coverage_0xb85a875a(0x2447455e3e27ceafb20d9d2a978507cac877a447a804609b3716c52c42e4b214); /* statement */ 
a[5] = a[5] ^ d[1];
coverage_0xb85a875a(0x4604605449baba651dea3efa91b01e3a2c345ce1b1f4cd7c0df59c1ac200fea4); /* line */ 
            coverage_0xb85a875a(0xf58220c9e35c470028683292b78eab8dfdf982388922433f9a9962ed43d9e3d9); /* statement */ 
a[6] = a[6] ^ d[1];
coverage_0xb85a875a(0x92c20d6d4595011cc1d8f89150841f3c70eaaf643dc41beae8426f9fe35b2719); /* line */ 
            coverage_0xb85a875a(0x1cc7720f94afed78aface87625469922066857ea13300d7db429163c5afd8c0a); /* statement */ 
a[7] = a[7] ^ d[1];
coverage_0xb85a875a(0x8ac34741d8188d83162b4288164d9211cab7cd9435a8cd7241de0bcf8944d7e0); /* line */ 
            coverage_0xb85a875a(0x07f9e18d6f8878c2f58045996dbbd4953b7b7e083eb55c85e5e42ecbd8ddc174); /* statement */ 
a[8] = a[8] ^ d[1];
coverage_0xb85a875a(0x336ce1beb54641c5ec1751986869eef1488b6e586e30a5d936221f961a0b1330); /* line */ 
            coverage_0xb85a875a(0xecdadd44ae5899073a2a93a1137844ff1a0535aaca5d67e0e85c2b8265721a0f); /* statement */ 
a[9] = a[9] ^ d[1];
coverage_0xb85a875a(0x796753d41b399e954477de9128f9974803e5580e8c0c7fac4467007d6719a94b); /* line */ 
            coverage_0xb85a875a(0xb7692926826fc93216e56ef794c8ee5fcb346841184d93a2d6d34c7f3bfe2686); /* statement */ 
a[10] = a[10] ^ d[2];
coverage_0xb85a875a(0x55594b1e15c4ee2b8780e01d1179d65a861fc639ef88e94daf8c0d304256d3dc); /* line */ 
            coverage_0xb85a875a(0xb8eb423b0d19f2cc63ad1fe7699cfa082f909080f563dff9be7c04072df83624); /* statement */ 
a[11] = a[11] ^ d[2];
coverage_0xb85a875a(0xbf8535e43e8b00e0c67d651cb370196eb830aad8aa65b17e5c300c5eff45c7a4); /* line */ 
            coverage_0xb85a875a(0x98ceb35cd40b1d50320ed6a27fd2c50c5356e82a0b2e0e3853a76063e7ab500c); /* statement */ 
a[12] = a[12] ^ d[2];
coverage_0xb85a875a(0x6b1bb572d9f0f5360292352ec34009f3829a5397a85425f180a6caaf3cb6e511); /* line */ 
            coverage_0xb85a875a(0xf2597fc744d811066baf82ea6ca62c118a7052fd73b6ec5f1a57b41c20566cc4); /* statement */ 
a[13] = a[13] ^ d[2];
coverage_0xb85a875a(0x64219d9a529433f0af2dbe1e25f6742a3820d6716930a793b62be115eaec3282); /* line */ 
            coverage_0xb85a875a(0x160e5dc257cf4f9e551aee1f33c4e88d76b6b42497547f9ed075e340871746d1); /* statement */ 
a[14] = a[14] ^ d[2];
coverage_0xb85a875a(0x82fec34b5a033b0b0954b1e5d024dcab6785b5c1e82c831fafdbba7301a0084d); /* line */ 
            coverage_0xb85a875a(0x1bf9ba63e51d2a57ec1644bfb22d8935e0708cd118a9f33e5a0b0108d6d230cf); /* statement */ 
a[15] = a[15] ^ d[3];
coverage_0xb85a875a(0x182fc68e0360e26701aa24cdc634ac9f51722093b7c4d722ae1d4dd78c397361); /* line */ 
            coverage_0xb85a875a(0xa746f6ab2a432ea61ca532c4d84145ed9558383e597fa67ca68849ef640cf6d3); /* statement */ 
a[16] = a[16] ^ d[3];
coverage_0xb85a875a(0xc2cfcf4dae4e124d5658185f903f878bbe93117136574aed099308a00e03490b); /* line */ 
            coverage_0xb85a875a(0x50e77a116101e600897e125d7aca490a0c0121ba31b017f6661d4c96f9a227f2); /* statement */ 
a[17] = a[17] ^ d[3];
coverage_0xb85a875a(0xc68cb7360fd0f991f4fc267b55c2094899253a4179c202965bd2b4e2a1cee95a); /* line */ 
            coverage_0xb85a875a(0xc94f29d0917b1c3c8e2a4ba02f9f6f427617bc9a099c6fba74196279dba4b16c); /* statement */ 
a[18] = a[18] ^ d[3];
coverage_0xb85a875a(0x89d731617671de53b5e0574474fc30025da354d1ff21f4b8e9f32f272261eefc); /* line */ 
            coverage_0xb85a875a(0x9ceaff47fd8b4deb4fc0cb259e0ec39b9a3dda180c933b4cc426dba3d6429419); /* statement */ 
a[19] = a[19] ^ d[3];
coverage_0xb85a875a(0xeca8f61e22fa76161c8f1efca8071d71cdb5d98c505951ccf835604ea4f6c588); /* line */ 
            coverage_0xb85a875a(0xe6c27f0ed2e14c57d8a3f397e475f4a94b197a490ee0d419174a0a4adbe2af8b); /* statement */ 
a[20] = a[20] ^ d[4];
coverage_0xb85a875a(0xfff748260f75d8c760f2db83013a69d7bc423617ee1b4bd543917664ec22b9a8); /* line */ 
            coverage_0xb85a875a(0x7aebfa18e23f45c523f2b06ad30e3879f136914b22d97b1c81347d3fd359e0df); /* statement */ 
a[21] = a[21] ^ d[4];
coverage_0xb85a875a(0x9dfa448579fa2e5ac307c78fa41fc98a9e65a7951132f4edaeb1fb3ef7aac98d); /* line */ 
            coverage_0xb85a875a(0xd6c5ec83a24b9c13ec5a0a7208daf8e4a8f1a2804dbd7d99e1e28e9ac29ebe60); /* statement */ 
a[22] = a[22] ^ d[4];
coverage_0xb85a875a(0xb92f46b98bfce970182c2174d370acdcd1c006c8037b41d42f2538659ba8b3dc); /* line */ 
            coverage_0xb85a875a(0xff6609165117cba52fa24f01edc3098b425acc5aba7d9d13bb6644b0f405a774); /* statement */ 
a[23] = a[23] ^ d[4];
coverage_0xb85a875a(0x94e96c454d2b7d6017fcfb29fb40f0233baa6eec288ec8b53bad351ba628be57); /* line */ 
            coverage_0xb85a875a(0x4f4e193c337b2ec25562183d665a77023870c73aec9034850e58d9453e38cc9d); /* statement */ 
a[24] = a[24] ^ d[4];

            /*Rho and pi steps*/
coverage_0xb85a875a(0x75a01e5085411d73f784af3ccffc06b6cb3950a5cd49cc4ac91792f3d6a9095f); /* line */ 
            coverage_0xb85a875a(0x7e041c87e7100761715fec40df57c9077213ef046f570525b4186e01a8b39430); /* statement */ 
b[0] = a[0];
coverage_0xb85a875a(0x2323cb9097c002704627c5f923302fac777e9f61b65d6a79601a80b7ebfd66aa); /* line */ 
            coverage_0xb85a875a(0xac2e80fb17d2445b99007b140d6ef1d87d22cdc71a23a397af41bb19ce0610a9); /* statement */ 
b[8] = (((a[1] * (2**36)) & 0xffffffffffffffff) | (a[1] / (2**28)));
coverage_0xb85a875a(0x51a948e6ea0d53bab9c04f3559ef4f245c4b4fa64cda3a8776a1a471af7c8e39); /* line */ 
            coverage_0xb85a875a(0x36c5dbe9062a759e838602b7ded678c162c2b46931e8eb2a6b4c597cc9b0c2ab); /* statement */ 
b[11] = (((a[2] * (2**3)) & 0xffffffffffffffff) | (a[2] / (2**61)));
coverage_0xb85a875a(0xdbdd42413573edc774c8e12020f24b710c6db0055a0e70fe769b51ba811f5d63); /* line */ 
            coverage_0xb85a875a(0x907f7ef7b53a191813dd691c8e53817c7650f538a5bbf1b373ce8ef302597862); /* statement */ 
b[19] = (((a[3] * (2**41)) & 0xffffffffffffffff) | (a[3] / (2**23)));
coverage_0xb85a875a(0x87b289c51e5ad6d0e5858fe65b676c579567de1d716269aa8b46029ed5ad4a50); /* line */ 
            coverage_0xb85a875a(0xf0f73ed2f5f014c98d52cb329119c4f9a09b0f7d648bba17621fae7bf73554b0); /* statement */ 
b[22] = (((a[4] * (2**18)) & 0xffffffffffffffff) | (a[4] / (2**46)));
coverage_0xb85a875a(0x1a8ae037ecf862c43709187ce3f47a96d8b88fb55fc8d3cdeaaaeaaba2e818e3); /* line */ 
            coverage_0xb85a875a(0x2028144ab05b24adddc189c3b53f06035c2aabf8cbed8621953ad57746c4173e); /* statement */ 
b[2] = (((a[5] * (2**1)) & 0xffffffffffffffff) | (a[5] / (2**63)));
coverage_0xb85a875a(0xbefe945a3bf03e13c5d6b52916726baa2af078d21fc95039d5b987c5da432ba1); /* line */ 
            coverage_0xb85a875a(0x0b415dbccf1f73e5a6b6b7adf8192551b263e1c567bd59b769dd1d196542ce40); /* statement */ 
b[5] = (((a[6] * (2**44)) & 0xffffffffffffffff) | (a[6] / (2**20)));
coverage_0xb85a875a(0x781055bae44b6bcaa2690770e46c288981b2ad47e6c33188a7b9f5c18a13301f); /* line */ 
            coverage_0xb85a875a(0x3d0f63de069817816d38c64bafae985532cf9767f2565892443675c7df7320d1); /* statement */ 
b[13] = (((a[7] * (2**10)) & 0xffffffffffffffff) | (a[7] / (2**54)));
coverage_0xb85a875a(0xe60e3ba50f73e8d0c028c85a8d987f6c5e2fa04b881814f552a1e71035543dba); /* line */ 
            coverage_0xb85a875a(0xc5537b55890f327851d617b8b5b79f7597f21d7b070b89024c01aab150f8b7ce); /* statement */ 
b[16] = (((a[8] * (2**45)) & 0xffffffffffffffff) | (a[8] / (2**19)));
coverage_0xb85a875a(0x999334385100b4af0b7b02d0c75a6a9e0923f4916f214d152457328b63c377cd); /* line */ 
            coverage_0xb85a875a(0xc34ee20937bafed7c52353bae30eb7e72cd9b8ef873ffa5f243a6197317e5257); /* statement */ 
b[24] = (((a[9] * (2**2)) & 0xffffffffffffffff) | (a[9] / (2**62)));
coverage_0xb85a875a(0x1950ab47ee2acbab225d9abaff3deb893380318f757ccacfdb528c26af222298); /* line */ 
            coverage_0xb85a875a(0xd80a3fbfdebfe16fdef25029103164158be2b730d1eb11b6279903183424ce26); /* statement */ 
b[4] = (((a[10] * (2**62)) & 0xffffffffffffffff) | (a[10] / (2**2)));
coverage_0xb85a875a(0x7b75ad09da90dfea7f4fa97a6c4ea5c642b76c7b8a589e6775798a4fe58036fd); /* line */ 
            coverage_0xb85a875a(0xe3ee65c7d805a580137d81aad82ba8344c5aecc2dd6390d971463ea5bd72c18c); /* statement */ 
b[7] = (((a[11] * (2**6)) & 0xffffffffffffffff) | (a[11] / (2**58)));
coverage_0xb85a875a(0xb44dffe0bd5a7c76dd177fdfff8054334868b87239c03ae8d08bd0d46ae9542e); /* line */ 
            coverage_0xb85a875a(0x0e49cd33f9eb55406fdb143efb3db24424a9ab8efcd271c9033144921dca4583); /* statement */ 
b[10] = (((a[12] * (2**43)) & 0xffffffffffffffff) | (a[12] / (2**21)));
coverage_0xb85a875a(0xbc84af1213ce01207209be1d7f875374bd4979f87beb533b09a7909a5a79a2ed); /* line */ 
            coverage_0xb85a875a(0x89e4e32abf70033e73ee66514e70fc2a0e04ff1184c956a83d8a2f8b74ce8750); /* statement */ 
b[18] = (((a[13] * (2**15)) & 0xffffffffffffffff) | (a[13] / (2**49)));
coverage_0xb85a875a(0xfe53757894c5af56640a4541513df9e658e7a2195c1815b14130624522429527); /* line */ 
            coverage_0xb85a875a(0x7109ac5eadfbbe5ae6119f98ff3a95280816135e4676a0909ecf2a2ebe35b367); /* statement */ 
b[21] = (((a[14] * (2**61)) & 0xffffffffffffffff) | (a[14] / (2**3)));
coverage_0xb85a875a(0x79492f99e4275ddf73760197c7f3f0859a1ab39fa5ac9dabafab83f222640f5d); /* line */ 
            coverage_0xb85a875a(0x8d130e113b29d311247422a8254530508ca54a0befb64d95072f645776be4275); /* statement */ 
b[1] = (((a[15] * (2**28)) & 0xffffffffffffffff) | (a[15] / (2**36)));
coverage_0xb85a875a(0x011a55acd39b7471ebc47546aec6cf5f02eec9f0e4db99ad3265f72bf49230d4); /* line */ 
            coverage_0xb85a875a(0x99a6a8b10276d07239cc9fed737cf70f4bd8e0b1a692a89508905339cb9d7a0b); /* statement */ 
b[9] = (((a[16] * (2**55)) & 0xffffffffffffffff) | (a[16] / (2**9)));
coverage_0xb85a875a(0x137d12491e8f176e6c57b9b67d22bbd59ae9217836209cb584c2ba334d055c28); /* line */ 
            coverage_0xb85a875a(0x6a69ba76e353dd0b42fa3428f1da19c343fb0c1fe9c34511dcbf00a754357843); /* statement */ 
b[12] = (((a[17] * (2**25)) & 0xffffffffffffffff) | (a[17] / (2**39)));
coverage_0xb85a875a(0x3a2297ffee128835468602a23231cb42f5c72abe9e4505229c37f4004dcfef32); /* line */ 
            coverage_0xb85a875a(0xa35fc9eff0401c73562aa842bfbf403778057d6161fd94427fe1ab297a8d0c52); /* statement */ 
b[15] = (((a[18] * (2**21)) & 0xffffffffffffffff) | (a[18] / (2**43)));
coverage_0xb85a875a(0xfc6e5e56752f92e9b9e10dd882568961115e369cefc65de9f2c2433ef1cb33a5); /* line */ 
            coverage_0xb85a875a(0x5470559d581168e337c3a585dc8233ba8a9b22fb0febcae01d77bba7346ccdaf); /* statement */ 
b[23] = (((a[19] * (2**56)) & 0xffffffffffffffff) | (a[19] / (2**8)));
coverage_0xb85a875a(0x335b6d69ff8011501bd0e78c173c7d8be196ed77cfa656b53c9a99f0f2ebb234); /* line */ 
            coverage_0xb85a875a(0x22985450b51e34a6fb0f533d6d4df4f6b72d44c6dea1b1ed2f2d9cdbd86b1576); /* statement */ 
b[3] = (((a[20] * (2**27)) & 0xffffffffffffffff) | (a[20] / (2**37)));
coverage_0xb85a875a(0x90e70b15cceb32306b325b83fa4b361ce7cc2e0fdee7126bfe478af257d4b1a4); /* line */ 
            coverage_0xb85a875a(0xd058407ccfdafcd2bcb95257f8a0bd9d3dc6c12bd92a20c7a7889f26308e421b); /* statement */ 
b[6] = (((a[21] * (2**20)) & 0xffffffffffffffff) | (a[21] / (2**44)));
coverage_0xb85a875a(0x768e9a24b57a2de0fac5419a22df9996b5f99df4ce62138b0304b6f0b87a3012); /* line */ 
            coverage_0xb85a875a(0xc0dce3515bfa4037b3b0ce0cf5b975dcc27a9f03a96fe4e8cac68086082f4b41); /* statement */ 
b[14] = (((a[22] * (2**39)) & 0xffffffffffffffff) | (a[22] / (2**25)));
coverage_0xb85a875a(0x16ae10cc07c107aaba374b9fe90a92cc308ad2385aff4ab501d244ee50afe9fa); /* line */ 
            coverage_0xb85a875a(0xd387474069fecc062d38622746816cd4bf60fa5ab0be5ddb9d90058f37bd0349); /* statement */ 
b[17] = (((a[23] * (2**8)) & 0xffffffffffffffff) | (a[23] / (2**56)));
coverage_0xb85a875a(0xf4c3482a6142083c69d1838d8439447397c60533fa3712a16835884bbf285d97); /* line */ 
            coverage_0xb85a875a(0x04e2c7458eb08d14fe0b1be9a012f9cea489ddee2e295449db38f077d5773230); /* statement */ 
b[20] = (((a[24] * (2**14)) & 0xffffffffffffffff) | (a[24] / (2**50)));

            /*Xi state*/
            /*
            for( x = 0 ; x < 5 ; x++ ) {
                for( y = 0 ; y < 5 ; y++ ) {
                    A[5*x+y] = B[5*x+y]^((~B[5*((x+1)%5)+y]) & B[5*((x+2)%5)+y]);
                }
            }*/

coverage_0xb85a875a(0xd1e8eace71e494bb52998b5d0d4b3961d0ee716dfb0be7f246b2e0282b10cab6); /* line */ 
            coverage_0xb85a875a(0x15b542c844a062ffacf2b7d00673513c26bc128b069549da6d347d1f52409c90); /* statement */ 
a[0] = b[0] ^ ((~b[5]) & b[10]);
coverage_0xb85a875a(0x3b63e65859160f35c316ef483c6793b977819964cdf70695af7c06236500d186); /* line */ 
            coverage_0xb85a875a(0x637d50fe9858a8fef9911440fef5fc8930d4efdce47d102d05d9fddc97783aae); /* statement */ 
a[1] = b[1] ^ ((~b[6]) & b[11]);
coverage_0xb85a875a(0x41c72078936f85fa0211e7916c05dcdb0204be3073d7716244d7fded2dc9edac); /* line */ 
            coverage_0xb85a875a(0x64c36e1fd279f5b43efbfd1d562be071577c45dc191a0fb4d0a63c90faf48f08); /* statement */ 
a[2] = b[2] ^ ((~b[7]) & b[12]);
coverage_0xb85a875a(0x7a5514573d617b6013285d63e28e09c22827f320dbd0a37812eb9a664f11bc06); /* line */ 
            coverage_0xb85a875a(0x8f361febfeb38a0ddcfea9595b83941c550b6839d1b183cc7605589ed3ed3624); /* statement */ 
a[3] = b[3] ^ ((~b[8]) & b[13]);
coverage_0xb85a875a(0xfd4fec4d96649d474209fdd24fb6cafe1d19419a8b5dd04e922294609325afa2); /* line */ 
            coverage_0xb85a875a(0x4f118721ae7ab6537ddcf429fc680aeb9b9e0271bd539fc678af520b1ee209ed); /* statement */ 
a[4] = b[4] ^ ((~b[9]) & b[14]);
coverage_0xb85a875a(0x0cf65367144e455b853803bb4a9eb2c347df5456f6086c68280bcc874370ab35); /* line */ 
            coverage_0xb85a875a(0x46d60baa67bd69613666bb3905eee358f7782a0b71ef3771a59c13e699adabc8); /* statement */ 
a[5] = b[5] ^ ((~b[10]) & b[15]);
coverage_0xb85a875a(0x5794ed7a78a2b44e408d046ca53d6d227f96b580bf3ec10ccf2b7ab4e054762e); /* line */ 
            coverage_0xb85a875a(0x14599a82d65c805abf511754884f57de91a0e542d18ec085a2cc3eea7bd33e78); /* statement */ 
a[6] = b[6] ^ ((~b[11]) & b[16]);
coverage_0xb85a875a(0x705fd608464a1424e0128f5d7265c3924904a8ca374436fbd67814fabde45aa8); /* line */ 
            coverage_0xb85a875a(0xa8c13a67dfd2915f69306d8652fe2d6fd4490edf75850c5d4cdf62c08d74ca91); /* statement */ 
a[7] = b[7] ^ ((~b[12]) & b[17]);
coverage_0xb85a875a(0x9e2fce6a6465dcbb2b86ee7cd7e2747de2b98f081c074d4320ca6dfb8d0b12ad); /* line */ 
            coverage_0xb85a875a(0x1c9517c6c52abd8122dcc38069e494a460454b66fe94ed3e8b73f645f99c9a1e); /* statement */ 
a[8] = b[8] ^ ((~b[13]) & b[18]);
coverage_0xb85a875a(0x4dc3d732d33d8fc26969c047baa0b30b21c2afb3bb738f131d57c0f945b9c26e); /* line */ 
            coverage_0xb85a875a(0xea267bb96bf12137bb29d78d61daebf89d06a1219b4035413e49c788903d3538); /* statement */ 
a[9] = b[9] ^ ((~b[14]) & b[19]);
coverage_0xb85a875a(0x6c9bbad5941e2c5d3e5f3f6672c1eff78b6b65f028d709cf80ab2cbc34ada6f9); /* line */ 
            coverage_0xb85a875a(0x966903d15a36c0ab0851d42fdd4db8808f00ea438ab0023ee103ed43fae3ebdc); /* statement */ 
a[10] = b[10] ^ ((~b[15]) & b[20]);
coverage_0xb85a875a(0xdbd97c3cf3dcaeed5e9cc5d6e1f4ea44f7625289e349a25057a75578a1768a0d); /* line */ 
            coverage_0xb85a875a(0x9df85bbc177a34f625a372c8ead09853b119ba8e8dad37df78e742dd0cdf8ba2); /* statement */ 
a[11] = b[11] ^ ((~b[16]) & b[21]);
coverage_0xb85a875a(0xe7f09b22867d9ec16c32c7e29748c71e4afee8f3cde7849372956243800fa7fc); /* line */ 
            coverage_0xb85a875a(0x98d7e7cfa10a7c430906c1f53317a0e8decbdd7db969a040ae6256ba65b300a3); /* statement */ 
a[12] = b[12] ^ ((~b[17]) & b[22]);
coverage_0xb85a875a(0xd5a6c0502dd6abf0eaf89ced929d9c068d0bb3778821907478cf47a666fcf3db); /* line */ 
            coverage_0xb85a875a(0x7e0870aa5ffe99af473ad1e48114576dbe1e5f7122d31cd64ef473528770a828); /* statement */ 
a[13] = b[13] ^ ((~b[18]) & b[23]);
coverage_0xb85a875a(0x79dc293a3a5e927476bef3cf0a0d572b946ebe907c7f0c7a4175203e42622ec7); /* line */ 
            coverage_0xb85a875a(0xb3e2b0660f6656c93e5ec8e26dea8bcd63b619dcf7fad2ac1b4c046d4966a78a); /* statement */ 
a[14] = b[14] ^ ((~b[19]) & b[24]);
coverage_0xb85a875a(0xb6c6aea3eab4c0900acde48f15d5ac39cb4c796e43e72a81ea54c7734914c5cf); /* line */ 
            coverage_0xb85a875a(0x3357fd66810d6d6573ffce43e0de2ecfcb013372e54c39c48c75b280d63e80f6); /* statement */ 
a[15] = b[15] ^ ((~b[20]) & b[0]);
coverage_0xb85a875a(0xa3963102be592a8fd3133d717b0acf62542a901b1f4a4572b06e807217dce87b); /* line */ 
            coverage_0xb85a875a(0x19bdc583f7e89e33a05216d00d53ebf69dabafc2b559c9fedba81d090822e0e4); /* statement */ 
a[16] = b[16] ^ ((~b[21]) & b[1]);
coverage_0xb85a875a(0x862477b5251f8024dd80b9b0b3fffce425dee945d743da961729ebb568c5b867); /* line */ 
            coverage_0xb85a875a(0xb430cb5ce10482359e035ef12b56efd978a125bf0cfadcde6535c2ae189d8b0d); /* statement */ 
a[17] = b[17] ^ ((~b[22]) & b[2]);
coverage_0xb85a875a(0x943747f5cb1f1003bcf0f3400c252141e409f0c832cfda3b58f489142195a7be); /* line */ 
            coverage_0xb85a875a(0x2310e727e712f7c4d6c12b55d2328ae76b7e0208f10f91a97f7dc327c58ee26e); /* statement */ 
a[18] = b[18] ^ ((~b[23]) & b[3]);
coverage_0xb85a875a(0xf7474b2669a84c293f35b8872ee8d6c6d4914fa85b74881074d42530452ebf89); /* line */ 
            coverage_0xb85a875a(0x2b25d5f15af54a558c2029b0b17dc1bd9bdd74df16e883a14805b581ae39766d); /* statement */ 
a[19] = b[19] ^ ((~b[24]) & b[4]);
coverage_0xb85a875a(0x700ec3812b81e5e75fd2d7993bd3dd26b715b97006af895ee98f0e994e9daf3d); /* line */ 
            coverage_0xb85a875a(0x2604f4605a1d50feb680c7743607aa21cbbcde17274b481f856496fb09d14392); /* statement */ 
a[20] = b[20] ^ ((~b[0]) & b[5]);
coverage_0xb85a875a(0x8dba1877e5f6c9495fd74d27edc6fb8d76945c6082eec9e1f446b8a84c5c6987); /* line */ 
            coverage_0xb85a875a(0x9773bd5ed9b867fbf645448c0e695a7d3f85ab171402b0f2cd83227b8222d51c); /* statement */ 
a[21] = b[21] ^ ((~b[1]) & b[6]);
coverage_0xb85a875a(0x8b5448f8bc290e895aad158a7287a0ef248df861bf255c7d68816091187c4f7d); /* line */ 
            coverage_0xb85a875a(0xd41e388facf3e5850a4e6f31e8f281a61921782420541fc1598f9a334f84c97c); /* statement */ 
a[22] = b[22] ^ ((~b[2]) & b[7]);
coverage_0xb85a875a(0x71485506865bc64268d8406d2e904eb727495deddc5f9af8469bcf8fc717245d); /* line */ 
            coverage_0xb85a875a(0x9f9e6daf8e3541e9486e5ff324d92d4ad9bc5b0274c349a49ee9bb11a7725e11); /* statement */ 
a[23] = b[23] ^ ((~b[3]) & b[8]);
coverage_0xb85a875a(0x3b9b2b4efd7b3664f88162a97d39dcac055f4c63a26b3feb1658726b9d1e0ff7); /* line */ 
            coverage_0xb85a875a(0xac5539adf21233b4100450dbccff9bae4f5cbdcbd237329d15c9c35b1362c519); /* statement */ 
a[24] = b[24] ^ ((~b[4]) & b[9]);

            /*Last step*/
coverage_0xb85a875a(0xbcb680689e418cdbb867ffbb3faf2e21af830ad124f95b85b4907f5e7e40c3bb); /* line */ 
            coverage_0xb85a875a(0xb99d1b8b0d340ab6291bc79457a92d2ee06478b673abfb3314d2303452ecba85); /* statement */ 
a[0] = a[0] ^ rc[i];
        }

coverage_0xb85a875a(0xa444041f30dd86569c353b5abe4cc9e6d7c2d256473fb5d7e743216e68e81a0d); /* line */ 
        coverage_0xb85a875a(0xea6d7cc4c228008e8e3d9393bbd103f7c1fa66f55ef697d06cd5d3a8f900edce); /* statement */ 
return a;
    }

    function rightRotate(uint32 x, uint32 n) internal pure returns (uint32) {coverage_0xb85a875a(0xa4ad537425d7813784a679a9ed986cfc203592e2763640c30403d76cca61c6f5); /* function */ 

coverage_0xb85a875a(0xd8c3e9199ff130318cd78668a23ef5a7a3edfbd4475c03ccec7d91a72283496a); /* line */ 
        coverage_0xb85a875a(0x79b8a24828a0ea9f6b28c7ebe6f98a6db7997ec6a5a3fb96bfdc3b89cdefd81c); /* statement */ 
return ((x) >> (n)) | ((x) << (32 - (n)));
    }

    function CH(
        uint32 e,
        uint32 f,
        uint32 g
    ) internal pure returns (uint32) {coverage_0xb85a875a(0x10170d4ba4fcf75bf35737546831a60af2dadb75ef973a2eb1c27bbc3845996e); /* function */ 

coverage_0xb85a875a(0xb02f6e23ddfff29161c68942d1f744561cb1ebcc5bf92c649009ed1ba78e8d02); /* line */ 
        coverage_0xb85a875a(0x20c87661b6eaaf5d422e6b73c2d258b8e8cc42d080ffd1084cb631a01923aa65); /* statement */ 
return ((e & f) ^ ((~e) & g));
    }

    // SHA256 compression function that operates on a 512 bit chunk
    // Note that the input must be padded by the caller
    // For the initial chunk, the initial values from the SHA256 spec should be passed in as hashState
    // For subsequent rounds, hashState is the output from the previous round
    function sha256Block(uint256[2] memory inputChunk, uint256 hashState)
        internal
        pure
        returns (uint256)
    {coverage_0xb85a875a(0x851011a98d712290bb99ab5e98b46edc6963c7f40acb10cbd0900c23d27e6b38); /* function */ 

coverage_0xb85a875a(0xc8c43f2de94326451b1e02438a6dfa3e80497c14fb2d00842933ad5e6ba92cc2); /* line */ 
        coverage_0xb85a875a(0x5adc1f951e8829a83d5d1a78a0733186ed8f10df105cb7ca24eb670d23513999); /* statement */ 
uint32[64] memory k = [
            0x428a2f98,
            0x71374491,
            0xb5c0fbcf,
            0xe9b5dba5,
            0x3956c25b,
            0x59f111f1,
            0x923f82a4,
            0xab1c5ed5,
            0xd807aa98,
            0x12835b01,
            0x243185be,
            0x550c7dc3,
            0x72be5d74,
            0x80deb1fe,
            0x9bdc06a7,
            0xc19bf174,
            0xe49b69c1,
            0xefbe4786,
            0x0fc19dc6,
            0x240ca1cc,
            0x2de92c6f,
            0x4a7484aa,
            0x5cb0a9dc,
            0x76f988da,
            0x983e5152,
            0xa831c66d,
            0xb00327c8,
            0xbf597fc7,
            0xc6e00bf3,
            0xd5a79147,
            0x06ca6351,
            0x14292967,
            0x27b70a85,
            0x2e1b2138,
            0x4d2c6dfc,
            0x53380d13,
            0x650a7354,
            0x766a0abb,
            0x81c2c92e,
            0x92722c85,
            0xa2bfe8a1,
            0xa81a664b,
            0xc24b8b70,
            0xc76c51a3,
            0xd192e819,
            0xd6990624,
            0xf40e3585,
            0x106aa070,
            0x19a4c116,
            0x1e376c08,
            0x2748774c,
            0x34b0bcb5,
            0x391c0cb3,
            0x4ed8aa4a,
            0x5b9cca4f,
            0x682e6ff3,
            0x748f82ee,
            0x78a5636f,
            0x84c87814,
            0x8cc70208,
            0x90befffa,
            0xa4506ceb,
            0xbef9a3f7,
            0xc67178f2
        ];

coverage_0xb85a875a(0x88fc3e0791922d152fcced4cd82fbe988304840b8a3e2157a0b9eae8aaf79aa3); /* line */ 
        coverage_0xb85a875a(0x5b232b851174a4f347b4748c6ef7f317e160ecf6e7bda41b9e3fcab5bc6f3d2c); /* statement */ 
uint32[64] memory w;
coverage_0xb85a875a(0x2cea31d31481738b1443c71ab9a956c4fb823d5d07e39fc19160b473caf50e7c); /* line */ 
        coverage_0xb85a875a(0x376c374362c7f011da76b1cf59b4505c703456edb24b54028d262d29823c47f7); /* statement */ 
uint32 i;
coverage_0xb85a875a(0x21777891c7eb9871194daee6f7939829a7e6703e09f644f8f3fada0b78094ae0); /* line */ 
        coverage_0xb85a875a(0x85afd68f47830e450620fc0fea79e0af1d174214a8b9edbb305314ebc65a318d); /* statement */ 
for (i = 0; i < 8; i++) {
coverage_0xb85a875a(0x7206995096133b144a28931a25519a632c1ef8f8eca739be08588e29c7840f76); /* line */ 
            coverage_0xb85a875a(0xc657815a99e22d8ff0b2c6eca86a0c8ccae0eb3b89ceeef4e753c6daf4964c4f); /* statement */ 
w[i] = uint32(inputChunk[0] >> (224 - (32 * i)));
coverage_0xb85a875a(0xc525230d50f161335a0848ac2480cb0e3d049b7b0a5d6392760a0b9dacc7efd3); /* line */ 
            coverage_0xb85a875a(0xd511788df4e3edd3609f7b4099f8b7de75373793bbc4b34ac067c55b9e933902); /* statement */ 
w[i + 8] = uint32(inputChunk[1] >> (224 - (32 * i)));
        }

coverage_0xb85a875a(0xdabe8a3c293f3d55f9136a5a86d5efb19b6f463823beae9a1cb1f8893dd6b7bb); /* line */ 
        coverage_0xb85a875a(0x106748756aff5a842fac4cd4a26abaa71c215eb1dc64f79f0b4a82f5cca43aa7); /* statement */ 
uint32 s0;
coverage_0xb85a875a(0xbd5ab0c47c091dda1213c7b90d6ff58b4ca5bb17e3df792bad65c93f29c291e6); /* line */ 
        coverage_0xb85a875a(0x365be132a92b818eb39033198abf672d302faac8422923e0b6e48a31cbc31edd); /* statement */ 
uint32 s1;
coverage_0xb85a875a(0x61dcb2d6c973c4cfcec54d57b9dbb5bc84bdaf5d31b73178da475b23b8f5d662); /* line */ 
        coverage_0xb85a875a(0x9fad29ad550f195fd68dd942a286f8a4c5e2733125083ac4ca928ed1e0a7e4ee); /* statement */ 
for (i = 16; i < 64; i++) {
coverage_0xb85a875a(0xdb270ba135adbfca0c1eb03765bd74159a6cdf22ef4f99e5cdcd572e7a39a2e9); /* line */ 
            coverage_0xb85a875a(0x096d4dda584c87d05606d3b6308714473a55c4df83f20fa89614283a91fc5881); /* statement */ 
s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);

coverage_0xb85a875a(0x194bd4adb5d0aa444d98ed0816cb86404d658189764fba2f08a7702730378b60); /* line */ 
            coverage_0xb85a875a(0xbb7f5addb068c1dcf66d45df9ee6681ee64cfb1dfa5078ce41d1fcdad4a7e48b); /* statement */ 
s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
coverage_0xb85a875a(0x2e9c242880a9963bb6f165b9f9ec574d0f880d68a55d1b4a0aaf2129dd72330e); /* line */ 
            coverage_0xb85a875a(0xba035f60d936bfb5909423ae606870bf2a477a41cad018cb10eb0eff774f8ab6); /* statement */ 
w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

coverage_0xb85a875a(0x5c4e9bfb6fcc30945076742842bee75c26e293bdfeca9edcff5c12d0f2163c92); /* line */ 
        coverage_0xb85a875a(0xe564499b5b03977e30acef4f9049cfb05e6c17488bb8ea610624f4bc40d00313); /* statement */ 
uint32[8] memory state;

coverage_0xb85a875a(0x0928ef15fe2d333529f4a01a6425aaf060014cc101cc2b90d38569b69bffd6df); /* line */ 
        coverage_0xb85a875a(0x81a68e8f9546edddd9cdcea085e6c2d42868220599d7cc910e95b237ecf094c6); /* statement */ 
for (i = 0; i < 8; i++) {
coverage_0xb85a875a(0x2faaafc6904668acccaf589a83353e8a631294f7de0eb17596147193e7efa569); /* line */ 
            coverage_0xb85a875a(0x60eb4951275038d8b88fcf4fb85a882ad915c3d8d1ba00034542fc71f0c6ed7e); /* statement */ 
state[i] = uint32(hashState >> (224 - (32 * i)));
        }

coverage_0xb85a875a(0xd5107fb270ebeb6b212d1209e117f9b82a0339a7ac593ae1f669713b8482746c); /* line */ 
        coverage_0xb85a875a(0xaaa331385d9c48b2ede33d140ed21baf27919e71147a3032249112a03df088be); /* statement */ 
uint32 temp1;
coverage_0xb85a875a(0xb4b787facfaacb54f7c1bde202c40dd724b5607a630c3ce647365d4cbd84b281); /* line */ 
        coverage_0xb85a875a(0xb60563cda6829cb6d7dade7f0a20255de967ab0749699361b874bece07434051); /* statement */ 
uint32 temp2;
coverage_0xb85a875a(0x7eabde35ad3de1e756040038e9a3be203cde632aa76d968094ea00b5b83c23c1); /* line */ 
        coverage_0xb85a875a(0x3d6dd55f1ea00e4964e6fe8ded8d25088eb2609a073fadc03aada8400f4f7f4f); /* statement */ 
uint32 maj;

coverage_0xb85a875a(0xec27ec35884109ff25d148ccb2b46d4eceacd841211a3fcb641b67136e16b1fd); /* line */ 
        coverage_0xb85a875a(0x367906754c47d41686efb697e177f40e0483af3d03fa6bbab307d9d666cd6fbd); /* statement */ 
for (i = 0; i < 64; i++) {
coverage_0xb85a875a(0x0995ee55aa900b53dd63b8aad08fd6ac08cdfbf036d41cd4b90bf9e83f1b8ff4); /* line */ 
            coverage_0xb85a875a(0xcaeda584c7dec93809e80d0e4d44111ed19514365d91716035b24da477d038fa); /* statement */ 
s1 = rightRotate(state[4], 6) ^ rightRotate(state[4], 11) ^ rightRotate(state[4], 25);
coverage_0xb85a875a(0x89ab315607c73dbeef2f0621d1ea39841c877a40da13ac00f638427d9fa5f63f); /* line */ 
            coverage_0xb85a875a(0xc306d1f542b23dd182ed51f5d6ddf604fa3ba58f7f512791510b8dc7793e4c31); /* statement */ 
temp1 = state[7] + s1 + CH(state[4], state[5], state[6]) + k[i] + w[i];
coverage_0xb85a875a(0xedbeffa58f46374527ee41f1dd63d8e6849e027a93c12288367ed2b9d752ab1e); /* line */ 
            coverage_0xb85a875a(0x6658a61ed455edf5ba7406158047a5e017f8cbba389675cccd9ddb210a3e0776); /* statement */ 
s0 = rightRotate(state[0], 2) ^ rightRotate(state[0], 13) ^ rightRotate(state[0], 22);

coverage_0xb85a875a(0xa7fca160b8fa3b8b853e4140d542ad7896a3f77b84c0187957a10e129bcb6cd8); /* line */ 
            coverage_0xb85a875a(0xc0c7e98cabfcc4bf3b1c6eb3da5b05270aaea5e651470cb08cabd51da56b0577); /* statement */ 
maj = (state[0] & (state[1] ^ state[2])) ^ (state[1] & state[2]);
coverage_0xb85a875a(0x5af753759fa976fcad663d3d4f4bf75532463bc374218bd10b264c8b7abb0893); /* line */ 
            coverage_0xb85a875a(0x25355008630e9d3cd00ac6c63d76efb58b8888c1ceeb38c7c18eaa938b8b7b5f); /* statement */ 
temp2 = s0 + maj;

coverage_0xb85a875a(0x85873d94610707feaa9db24bc722fff8651ffa025585ac764f1bd33dd615a332); /* line */ 
            coverage_0xb85a875a(0xc62b8e05a607e64cc4a2931bf530546e2652bdcb5c8c8fd8871367d422288f69); /* statement */ 
state[7] = state[6];
coverage_0xb85a875a(0x076b35d60811e6aaf4d8ffda1da7c5067452c2b4d3893925603abeb5e24156f4); /* line */ 
            coverage_0xb85a875a(0xcc900f9d3fc00a9a4a5684cc07574228d21d676d7e654fff6a525bea1ef5d227); /* statement */ 
state[6] = state[5];
coverage_0xb85a875a(0x95a6c38822020579e2ad5b68cfecf8a3c2fdc8dd0bd126c311bc3c650ebccbce); /* line */ 
            coverage_0xb85a875a(0xfc3dcfc4cb9d716f7f6c20a1e7deff2b3e307f40beed66ab389633bc4ccde236); /* statement */ 
state[5] = state[4];
coverage_0xb85a875a(0x88f9a1ddf874da6981f6c6a109c84f5a59de0414ada7d41aa52132ba00a915d8); /* line */ 
            coverage_0xb85a875a(0xe0567dc7e3d1adda9e4cffda3ff4dfea8f126f1ee9fe754314e0541a34f583c7); /* statement */ 
state[4] = state[3] + temp1;
coverage_0xb85a875a(0xfab8f0002a3c6e90804f9f18579d3f6230437b38fb48b7c28146d1fde3ace159); /* line */ 
            coverage_0xb85a875a(0xe5a0cf0d804f31edbd940ccf03cffaf08ad78bf98a19eb22561f093186fccc3b); /* statement */ 
state[3] = state[2];
coverage_0xb85a875a(0x661166ff8d8fcbcac717c85d1aa148f5e98f6970e4123fc2a689d434c57be141); /* line */ 
            coverage_0xb85a875a(0x26689357c4062e62f1ef5a6e3f379a0ddf5255c05389a5374182551256814c61); /* statement */ 
state[2] = state[1];
coverage_0xb85a875a(0x7826c448451d2d7bdebafcef80e65f47b05c6684bb927122e8897c2370095c48); /* line */ 
            coverage_0xb85a875a(0x886d05733c4cb8f5a3a6df800e8a1dab1b1cc7ef77775a04cd37c2115080beee); /* statement */ 
state[1] = state[0];
coverage_0xb85a875a(0x2bc5c2179c5e32aa0ce5aa708b888bc19d89c1cb37be247aac07ec8bddd097db); /* line */ 
            coverage_0xb85a875a(0x01a724859f4bbd931f8bc78a0fe5e3e947481de6f779c409b201696e97b36da4); /* statement */ 
state[0] = temp1 + temp2;
        }

coverage_0xb85a875a(0xed86c9240768a41c6a618a253a882e5a000754922d476ee06bff935f4c3c1052); /* line */ 
        coverage_0xb85a875a(0x9f1505cacd80c822cfb2e7429d6730110b61ae486a4aec41cd9086d939d33d5f); /* statement */ 
for (i = 0; i < 8; i++) {
coverage_0xb85a875a(0x1f6047e5845f523188eb41f30ef73cd5d1523231a7db987a0633325e9d0ee209); /* line */ 
            coverage_0xb85a875a(0xdc5694066bcc8c07380f245f6a3467437b3eb60aa13870a2e979c552146c7152); /* statement */ 
state[i] += uint32(hashState >> (224 - (32 * i)));
        }

coverage_0xb85a875a(0x64af4f4f85cd8fac5588560398c5f7becc555ba2e092acd602801a248a65db15); /* line */ 
        coverage_0xb85a875a(0x1b0f2a43aeb575a20a19b1a943cb2e925a67fb2c7c7d3c290492912499eeb8b6); /* statement */ 
uint256 result;

coverage_0xb85a875a(0x5ccb03833eeb6784fe74e7a07ef086aeef6ab6f5e17e72c8d6047d0c13585909); /* line */ 
        coverage_0xb85a875a(0x3313952c37d1ead5389494c78151b46218661c9318181f09e8df5359a97f3fd9); /* statement */ 
for (i = 0; i < 8; i++) {
coverage_0xb85a875a(0x900696fdaf505d0337ca17d5ae6fca31e69a1f60b32e7bb6a0135f72a6951673); /* line */ 
            coverage_0xb85a875a(0xeb7f8ef2fbff90fe9bf38afaf75b05852e67edb6aa94108bec76eb32f0997c96); /* statement */ 
result |= (uint256(state[i]) << (224 - (32 * i)));
        }

coverage_0xb85a875a(0x62a1bdc8d749b8f930176bb9533a25024bf2fe4a16006277e80d307f6a51cb98); /* line */ 
        coverage_0xb85a875a(0xc1cf51083b380c45cd4d77c238551ec01be50458562a5bd1281f8bc98d8b57e1); /* statement */ 
return result;
    }
}
