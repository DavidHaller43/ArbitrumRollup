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

library MerkleLib {
function coverage_0x8d8db0d7(bytes32 c__0x8d8db0d7) public pure {}

    function generateAddressRoot(address[] memory _addresses) internal pure returns (bytes32) {coverage_0x8d8db0d7(0x0734ad0739cbab21c8c2c8325a9155bde33d0b5d23c032ab80fc6cb75f2eced2); /* function */ 

coverage_0x8d8db0d7(0xf9fca17adba72f0c08e4ddf4a4fee18fdf238cf193e390c7022f302e3b9cde4d); /* line */ 
        coverage_0x8d8db0d7(0xde70082cac920b6fa94a185a8eb5db0a29513d14c787ccd2a5ca327b81016c9f); /* statement */ 
bytes32[] memory _hashes = new bytes32[](_addresses.length);
coverage_0x8d8db0d7(0x9499b2886f54f5ab2d21d895567b1338486a54905eb0a6e3c4aa44ef5b4105ce); /* line */ 
        coverage_0x8d8db0d7(0x3fdc4973c303e41402009af8d12677adfd0dda3c7d9dfa8fefc44af0e57bf25c); /* statement */ 
for (uint256 i = 0; i < _addresses.length; i++) {
coverage_0x8d8db0d7(0x908f93eabc9666268b451e7f843d91547485633df953542e573f8f664f5e2c78); /* line */ 
            coverage_0x8d8db0d7(0x6b9a4b1e942764fd1d136a9ba802914f758e936d8d3f2b7f37daa8398b6a8adb); /* statement */ 
_hashes[i] = bytes32(bytes20(_addresses[i]));
        }
coverage_0x8d8db0d7(0x4956ca81d2df9d6bf037ba3ca3b7c71e7e685db6b590ac89e63cb0383d9e879b); /* line */ 
        coverage_0x8d8db0d7(0x73d07fd8958f6ef9c23eeb8cb8a39aaca3dfa796009db653ad7ec8f523be69ce); /* statement */ 
return generateRoot(_hashes);
    }

    function generateRoot(bytes32[] memory _hashes) internal pure returns (bytes32) {coverage_0x8d8db0d7(0x3c33cf32a1e361796a7bcd83044af2b2c448dd95063a67c107d855cc7c6f1be3); /* function */ 

coverage_0x8d8db0d7(0x433681f81a4cfcda34705fdf1d6b9ec1b27b32b6d11da7fae27695457be1c4fc); /* line */ 
        coverage_0x8d8db0d7(0xf9f23212a8796899248f1c215767764252bf4d76e173582bd709e344bb274fe4); /* statement */ 
bytes32[] memory prevLayer = _hashes;
coverage_0x8d8db0d7(0x585f8eb0c273a63ebe369da0e01fa0f39698ec37ff15b90f04b8182a72cb0259); /* line */ 
        coverage_0x8d8db0d7(0x9d785665d2dd44a856f6788c43abce41dc118052ee6d3f4f08a356d4f1dad3c8); /* statement */ 
while (prevLayer.length > 1) {
coverage_0x8d8db0d7(0xa39abd5fef05b25d193ae228da924ccbe11f2c090781c45188e9fc4362ff2ab5); /* line */ 
            coverage_0x8d8db0d7(0xc6075f9e13bf34c7ca74d97053b706fb9b522c6cad02f12289eee061b84af71e); /* statement */ 
bytes32[] memory nextLayer = new bytes32[]((prevLayer.length + 1) / 2);
coverage_0x8d8db0d7(0xee7d7d1d39257d1dbec21d54fdd392359c7adc1ab8f211dad90c5ad1f94a591f); /* line */ 
            coverage_0x8d8db0d7(0xd608f071123f481751c67c376d90ff56574a72b9e6b27cf872e2038e957c9a27); /* statement */ 
for (uint256 i = 0; i < nextLayer.length; i++) {
coverage_0x8d8db0d7(0x93f28f86eb880917f603094ef91b6c2a603af0f35d336fbb9e0ef2de8783f471); /* line */ 
                coverage_0x8d8db0d7(0x393753ac5034743b886c160748f43d69b669240f033c9912b64b12afb7c07432); /* statement */ 
if (2 * i + 1 < prevLayer.length) {coverage_0x8d8db0d7(0x20e0063e77640c1a1d91fbb656aaff4593df39619597cc341707a7ccd8995473); /* branch */ 

coverage_0x8d8db0d7(0x69a64d20e06b1917d7e77bfc18f782cfd3c5e3545b846330d0d15e54510b623e); /* line */ 
                    coverage_0x8d8db0d7(0xfe98d107c04f5688d5ca85f17b168b530fda17e1bc128d678e18010a729d55ac); /* statement */ 
nextLayer[i] = keccak256(
                        abi.encodePacked(prevLayer[2 * i], prevLayer[2 * i + 1])
                    );
                } else {coverage_0x8d8db0d7(0xfd62ec9f2d2319f5c17d4b306fbb9a68acbed7d805cff64dd0eb66634b787307); /* branch */ 

coverage_0x8d8db0d7(0xca430e5fd0e3f9c28f45a0600bfd4953359a3712f3a192ea54599bd194ee1f98); /* line */ 
                    coverage_0x8d8db0d7(0x714b59dda099b21c03e4b876701739292f12c6375886f4aed7e9dc4700da9e61); /* statement */ 
nextLayer[i] = prevLayer[2 * i];
                }
            }
coverage_0x8d8db0d7(0x4602c77652dacdb0faea4877fcf1f9b6941afdd95c577a233e5487aea26b41e1); /* line */ 
            coverage_0x8d8db0d7(0x5d4049162ea39e14b404044e465d31df90046fe0db8dd5d43ccedd099e21a8be); /* statement */ 
prevLayer = nextLayer;
        }
coverage_0x8d8db0d7(0x62e80b5fee669b9ac3f613004a9acd4f85086b308cac9629510aa955afdc8568); /* line */ 
        coverage_0x8d8db0d7(0x265d040ddc44ec37b8eec1bd02f911d73a7f44a07848dfbd7e7645b9478f9636); /* statement */ 
return prevLayer[0];
    }

    function verifyProof(
        bytes memory proof,
        bytes32 root,
        bytes32 hash,
        uint256 index
    ) internal pure returns (bool) {coverage_0x8d8db0d7(0x06bcadff5068b7700d03a209d3e648694cb6c1a5682fedaf49e37bd2a6112daa); /* function */ 

        // use the index to determine the node ordering
        // index ranges 1 to n

coverage_0x8d8db0d7(0xc0a1d9ec074695d14441e2deb3acc06103fa3d7dc78891647b3dea5a9ce1c036); /* line */ 
        coverage_0x8d8db0d7(0xcb7ce8c0bc6ffcc1c650b3f187d4faffbf4934a2d0bf3a7278357ebf494a3559); /* statement */ 
bytes32 el;
coverage_0x8d8db0d7(0xd11f8f1377bfa98243ef8f0ade3cd8f1af7d17cba8caafbdbb01ccd7ec1659c5); /* line */ 
        coverage_0x8d8db0d7(0x7938eaecd3663924a9a331043445bf6287ecd71643865e7ad5081ed9c143771c); /* statement */ 
bytes32 h = hash;
coverage_0x8d8db0d7(0xfc6675ebff1fb58c07ab0e36e9defe591384ddffd0102406c03c6087750a7258); /* line */ 
        coverage_0x8d8db0d7(0x68950ccdb05c0294b163d465e9e49662836e4ab3e646bc1e9fd3165acb1b2673); /* statement */ 
uint256 remaining;

coverage_0x8d8db0d7(0xbc617d9a2d9a069f2e76bee91fe6e1bb081aea62dac4badef2ccef3eb5dc358a); /* line */ 
        coverage_0x8d8db0d7(0x7efc1ff32c83596e9a539aae3d05adf2918c23f700efc1c7a6e75b1e320354d1); /* statement */ 
for (uint256 j = 32; j <= proof.length; j += 32) {
            // solhint-disable-next-line no-inline-assembly
coverage_0x8d8db0d7(0x42659a588b0d6f178cc1471b6f894eed98f6d6711cfc3bce2fa7b55018815fd6); /* line */ 
            assembly {
                el := mload(add(proof, j))
            }

            // calculate remaining elements in proof
coverage_0x8d8db0d7(0x54103726a32f4c4e8ab6c15f8ce52aeaac2ccca7878c941c6a43dcf3504655ac); /* line */ 
            coverage_0x8d8db0d7(0x0b6b9126d219cca7c24f4c014ec690034b8c18ed876b634a100082b486fac313); /* statement */ 
remaining = (proof.length - j + 32) / 32;

            // we don't assume that the tree is padded to a power of 2
            // if the index is odd then the proof will start with a hash at a higher
            // layer, so we have to adjust the index to be the index at that layer
coverage_0x8d8db0d7(0x881e45fad000c55924104ca70decc3a4a34d4085b1de6caad2c1403b2c51b7fc); /* line */ 
            coverage_0x8d8db0d7(0x078d01057b923de9b1e982e6b71d7822cf0ab34b05f93980654078a146d25ffc); /* statement */ 
while (remaining > 0 && index % 2 == 1 && index > 2**remaining) {
coverage_0x8d8db0d7(0x1ff1ffd5b7fe6202c3bfa7e16cd7a9d59a9b8bfcf94885f4141cb69999646297); /* line */ 
                coverage_0x8d8db0d7(0x42be2ab98b82b0af54eb414f3efc27870381919f2f2ac5646d71485c01e09b9f); /* statement */ 
index = uint256(index) / 2 + 1;
            }

coverage_0x8d8db0d7(0xa2045e81ed910d4318083f7a26b77443fcc71c136d8dc0fedd28f7b785783d21); /* line */ 
            coverage_0x8d8db0d7(0x00c524a521d9387afb52f578c61dbaae05d5036fc01675ddfa23e4a0803c3915); /* statement */ 
if (index % 2 == 0) {coverage_0x8d8db0d7(0x669c849132526f6ad21ba74663c226aefb83f8ca4149fc691898b8dc5d535825); /* branch */ 

coverage_0x8d8db0d7(0x41fa7fa76074b11b5dbc7bd9ca8260b6f700dc9618f345694e4d8cd278c6c47b); /* line */ 
                coverage_0x8d8db0d7(0x4bc650277d3e124cccbf4007cf325a50b59cc992a4ca83be3fa1827272a4cb67); /* statement */ 
h = keccak256(abi.encodePacked(el, h));
coverage_0x8d8db0d7(0xb2cd9192ef6c93f7ba1c6ace171312e7336953523775e2aca1f7763461f428c8); /* line */ 
                coverage_0x8d8db0d7(0xd83bbd2d4a55c7bc7b9b0d0bd4305cb4aa739c5d5e738009d5b929e9874aea6c); /* statement */ 
index = index / 2;
            } else {coverage_0x8d8db0d7(0xc5e1a4f9751c1f4e18009de156a053b3a966416f2f1d7c24230e35fc318948bb); /* branch */ 

coverage_0x8d8db0d7(0xe0cd0829f1e330aba88602894aa8fc6d158dc7f17bb719c4cf2a598197d30198); /* line */ 
                coverage_0x8d8db0d7(0xeb4b0ca22c6ee7ad030aaa1b94982dfe7d698f36bf50ab4c1d874fbbdb4462f1); /* statement */ 
h = keccak256(abi.encodePacked(h, el));
coverage_0x8d8db0d7(0x9d81e7432b188cbbdb8aec87f856e6876719ada81bf68a9f5270169618f9d24c); /* line */ 
                coverage_0x8d8db0d7(0x44b104ceaf746b820b86356fdde32a3d12a25ecedc1de221aa0d306965b73f95); /* statement */ 
index = uint256(index) / 2 + 1;
            }
        }

coverage_0x8d8db0d7(0xdd8c63424391bb6705a9888c10fdc6411b8c8ac90d3aaccaca2a07395c17468d); /* line */ 
        coverage_0x8d8db0d7(0x4f90b56ab9bb42363d636a67e4a3361708d244a72790e0ad04e41793ab31673c); /* statement */ 
return h == root;
    }
}
