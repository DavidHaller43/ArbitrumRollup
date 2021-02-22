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

library Value {
function coverage_0x04be09c7(bytes32 c__0x04be09c7) public pure {}

    uint8 internal constant INT_TYPECODE = 0;
    uint8 internal constant CODE_POINT_TYPECODE = 1;
    uint8 internal constant HASH_PRE_IMAGE_TYPECODE = 2;
    uint8 internal constant TUPLE_TYPECODE = 3;
    // All values received from clients will have type codes less than the VALUE_TYPE_COUNT
    uint8 internal constant VALUE_TYPE_COUNT = TUPLE_TYPECODE + 9;

    // The following types do not show up in the marshalled format and is
    // only used for internal tracking purposes
    uint8 internal constant HASH_ONLY = 100;

    struct CodePoint {
        uint8 opcode;
        bytes32 nextCodePoint;
        Data[] immediate;
    }

    struct Data {
        uint256 intVal;
        CodePoint cpVal;
        Data[] tupleVal;
        uint8 typeCode;
        uint256 size;
    }

    function tupleTypeCode() internal pure returns (uint8) {coverage_0x04be09c7(0xd7e0589d4c113baf5572348e58bb6ebacce9d2306a1c6100f87b277498e270af); /* function */ 

coverage_0x04be09c7(0x8368611b2ed88b90fa5ce45a1ca1f31381b4d1e41eca4947c72a78bb8872e1f1); /* line */ 
        coverage_0x04be09c7(0xfa548d92d5f0fb37157d18fff554355b0f8dbaca80ebd63255ea24985ee25ce5); /* statement */ 
return TUPLE_TYPECODE;
    }

    function tuplePreImageTypeCode() internal pure returns (uint8) {coverage_0x04be09c7(0x3c9a94a0e49d593d9879c0a8ce82843e8f94222ff5bfb7ea6fdd99803f6bb34c); /* function */ 

coverage_0x04be09c7(0x2681a132f77c098349a13efe5cbc3f9aba8878d0601fd38c2a040349881a4047); /* line */ 
        coverage_0x04be09c7(0xfb7c0ceb17661e0098f59367b21b1cc29b3dcd7c77a671c9c8f31d4f1134ef48); /* statement */ 
return HASH_PRE_IMAGE_TYPECODE;
    }

    function intTypeCode() internal pure returns (uint8) {coverage_0x04be09c7(0x73275b64c810e4a9580d191cf9ba01b17675f24c8ccd2d6dffa9aa1e7ca9d6ee); /* function */ 

coverage_0x04be09c7(0x456a01af384e2214f8d43224af3ce8b11283647a82889a88f74a1ed9f3889654); /* line */ 
        coverage_0x04be09c7(0x5fca3708de856d52944a5320b7e8a0d541267868c894e1494a2418af7ce8c9e9); /* statement */ 
return INT_TYPECODE;
    }

    function codePointTypeCode() internal pure returns (uint8) {coverage_0x04be09c7(0xb341e1b9d450c11c8f5958c236b30a8867749f6cd791629945e05d0be39e7265); /* function */ 

coverage_0x04be09c7(0x450c428c6d478cc1994c24b5bbc973539a8d0cfb8708830e6a9d3418e6e2c991); /* line */ 
        coverage_0x04be09c7(0xd0b066fb67fe6bc14667c30a6b0df480d311e889e09073f883e85b6cbea841bf); /* statement */ 
return CODE_POINT_TYPECODE;
    }

    function valueTypeCode() internal pure returns (uint8) {coverage_0x04be09c7(0xafaf072e5be036912341e1e23e6f50063721f347265d6d5b71a519e5f01ba139); /* function */ 

coverage_0x04be09c7(0x4ceb93b3b6eacf1bbb2b9cea35b687cfc501b57dab5c10946f038461cdc715a3); /* line */ 
        coverage_0x04be09c7(0xab4ac7a14f738b1a294a620da24c8ea6ff76b724105d3d3115734e4d6880d49c); /* statement */ 
return VALUE_TYPE_COUNT;
    }

    function hashOnlyTypeCode() internal pure returns (uint8) {coverage_0x04be09c7(0x8911de75c878c233098edb1f2fef9ad46182ebed2d960bba36c5b659b516e63b); /* function */ 

coverage_0x04be09c7(0x4137ed7ecbc3cc0311d16944567647668e85407e4cc8c6eba9c489d146b81861); /* line */ 
        coverage_0x04be09c7(0x67e2a88fa9bd5c59bd313a45cca4e5e39b6283127247468128212ded26b6a0d5); /* statement */ 
return HASH_ONLY;
    }

    function isValidTupleSize(uint256 size) internal pure returns (bool) {coverage_0x04be09c7(0xbcd7b430a819123c2ef82ee3dd11ca2d735d1d10d65733ec8027962269af21e6); /* function */ 

coverage_0x04be09c7(0xaec8833a01caa68d3095160f940347c26a4dc644ef5482a20186fc2ff80cc33e); /* line */ 
        coverage_0x04be09c7(0xd61e7b7864958bb3ddcbb948a931933c12703a09bf0e3472cea9bbda3b2cd086); /* statement */ 
return size <= 8;
    }

    function typeCodeVal(Data memory val) internal pure returns (Data memory) {coverage_0x04be09c7(0x7b085f9112fdec6cce840b16440d76af3e872b5cee739f84b465a2a3c831f319); /* function */ 

coverage_0x04be09c7(0xd3c750a83b40e40518e3f1f0fb710f5dcc7098d7f8e747a92f87a3498aef2e62); /* line */ 
        coverage_0x04be09c7(0xc359b5a6766fc48c2d18b81de2cc77a87e6789da7086dcd47f2bbe87c648445e); /* assertPre */ 
coverage_0x04be09c7(0x002913eb25b1753132d467eebdc99ed9ffc9d3602fdc7fa0c845b175fc5e8e2d); /* statement */ 
require(val.typeCode != 2, "invalid type code");coverage_0x04be09c7(0x4d90412f08418580da53ccf53f54a11bd70d4954253865bc54e8a552870aab1c); /* assertPost */ 

coverage_0x04be09c7(0x750c0a03eabf40a1ee0dbafdd5243b405569a1b35b1af8cb9857ce719183733b); /* line */ 
        coverage_0x04be09c7(0x38fc11b2ad27cfaf22bc547da0de1229be2e0e11ed5b89c07be8ddac71429f8b); /* statement */ 
return newInt(val.typeCode);
    }

    function valLength(Data memory val) internal pure returns (uint8) {coverage_0x04be09c7(0x3e4e6ba65cece25a028f42e735969bc893312066734830735a3646f07b5c8d91); /* function */ 

coverage_0x04be09c7(0xa7ee343f1beb2cd0300231a5fcff72a76e1a25b5def5e7c8f792ce5e4c6cdbeb); /* line */ 
        coverage_0x04be09c7(0xc3c92d63cab1f1aa5861ed0b4248734c43d7c7db1724051c912a51be1549af00); /* statement */ 
if (val.typeCode == TUPLE_TYPECODE) {coverage_0x04be09c7(0xeb0e234529b9dd09cfaf7285ca0fa8cf8ca869848b4b810617b84337ffde960b); /* branch */ 

coverage_0x04be09c7(0xc9887b5cc25f584f27597c3cd1d8032e849753ad93de7b308494f85d20397601); /* line */ 
            coverage_0x04be09c7(0x09570cd4df5bfb8f2fd25f84cf9a8a2ecd9938d5ccf8fd169d150a102c8647d8); /* statement */ 
return uint8(val.tupleVal.length);
        } else {coverage_0x04be09c7(0x1ee8d03b472d4725aea581ad25a2400a077d4f85e774283aaf7fcded28b4b41a); /* branch */ 

coverage_0x04be09c7(0x7285ba2dbf3dc52c3ef35243abe461bbfa886136990556d3a5113435124133cb); /* line */ 
            coverage_0x04be09c7(0x89087d5179bbd0259aa1b0253703471ea8e801a010d13f16de5ba8de18d587df); /* statement */ 
return 1;
        }
    }

    function isInt(Data memory val) internal pure returns (bool) {coverage_0x04be09c7(0x51484908f5f963407246d2abd0ff8b37b9540f5d6d4cab1b2b22ae267b603530); /* function */ 

coverage_0x04be09c7(0x6dbad77cbe0398496c07dbd3804baa4f24c208f663e4508e6cfea7a537e0d6fe); /* line */ 
        coverage_0x04be09c7(0x90a9d3186371b33475946cca5d21b9610fb9e4f94ff3a1951ac794eb2c7a66f7); /* statement */ 
return val.typeCode == INT_TYPECODE;
    }

    function isCodePoint(Data memory val) internal pure returns (bool) {coverage_0x04be09c7(0xdc958fa5b2372e7653db6cf8faa815d5ca65919e366161a2b54127c111593a21); /* function */ 

coverage_0x04be09c7(0xc7abf4584442c799da8dd67fd20ccbc8c91dfc8908d7e6def57b41c7baf320d7); /* line */ 
        coverage_0x04be09c7(0x077f9de0198c916f04294cde6b6616a51393ff185200c55f7adf9fe0a12eca34); /* statement */ 
return val.typeCode == CODE_POINT_TYPECODE;
    }

    function isTuple(Data memory val) internal pure returns (bool) {coverage_0x04be09c7(0x0d6c568df8e096053d6317ecc57d489d79ab524bc2ca1dc672ad5c8ec2ee27b7); /* function */ 

coverage_0x04be09c7(0x0965bf1f5442cf4c4eeec175adc781ea59a342547b235d356c06f4c557e2c33f); /* line */ 
        coverage_0x04be09c7(0xaf4187dc872c2863b401f8274c92117629daa900866c15e30c174b7292150201); /* statement */ 
return val.typeCode == TUPLE_TYPECODE;
    }

    function isValidTypeForSend(Data memory val) internal pure returns (bool) {coverage_0x04be09c7(0x2185e34deb4097f9be62cb9406d78786e5f18bc42acb0504f373787166606eb7); /* function */ 

coverage_0x04be09c7(0x8c049e5c1f21620e33619480463283db73fe86bfc777878b34737e6c02e79835); /* line */ 
        coverage_0x04be09c7(0x3a87c64614ddc839bb57e56750e878c58c871c3a933df50309afe0852c36061c); /* statement */ 
if (val.typeCode == INT_TYPECODE) {coverage_0x04be09c7(0x3fc082b7ef3c7be250e2ef59ee4940967fbaf498d4a32a5d9e23fb16ff01ca79); /* branch */ 

coverage_0x04be09c7(0x7c2ddfbf87fdb955785bcea803f9069afdc7dc64c4742091b5c82958521481f0); /* line */ 
            coverage_0x04be09c7(0x378768b3f6d509e550532eda11aaf0fed4f8f16ea849ab75ab4a57c056841e30); /* statement */ 
return true;
        } else {coverage_0x04be09c7(0x400aa719dcf61650f58247c3b88b16452124c8a9dae9d07cd57da401d109c770); /* statement */ 
coverage_0x04be09c7(0xa7953dca7ca22d0cc613eeb304a212a8cda2f14738c580277e1c7c4b408e2ead); /* branch */ 
if (val.typeCode == CODE_POINT_TYPECODE) {coverage_0x04be09c7(0xbcb63d0837c321678068c50b1155d7d7a568fed5593e20ff771bd75a6b775d8a); /* branch */ 

coverage_0x04be09c7(0x02ef990555375a71f4175179c5543b9375954eeace453ad6e3e04c601a7c133b); /* line */ 
            coverage_0x04be09c7(0x383c20bc558d3843ce5e9b0956d1e716b0e7aabebe86ed6739d95045e4a55b2c); /* statement */ 
return false;
        } else {coverage_0x04be09c7(0xfcbfa54c7986ef50161e0135ac6e83a57183ca5bd359dd141ecc1ccc07e86f9f); /* statement */ 
coverage_0x04be09c7(0xe7f401ec65c46d46838c2880d0fce3d9c06cfb559b36210f6f1046db5e9676f7); /* branch */ 
if (val.typeCode == HASH_PRE_IMAGE_TYPECODE) {coverage_0x04be09c7(0x20d223ab4294ae8e30de5cb1bcef4f6bd38d7cca339eb6028f272c93bbe62dbb); /* branch */ 

coverage_0x04be09c7(0x598aa3a159748f79399465d5f8a261b1bb2d8e84c8b51643edbe473011929bd1); /* line */ 
            coverage_0x04be09c7(0x64a7c53dafc4db0478700290f778e7d2a201592f273de6974dcc45a2e45d93e5); /* assertPre */ 
coverage_0x04be09c7(0x558aab1b0ce5057c475ecdc6aa0fdb462364ab2d29d19ab07f5de67723e4ae56); /* statement */ 
require(false, "must have full value");coverage_0x04be09c7(0x107ccb66c0ca14bfa10ce50772ceda412457a8f2495f88b28a5d74a7b51637b9); /* assertPost */ 

        } else {coverage_0x04be09c7(0x3f4dea1bbddde49fbd42047c6f6762140a8497875e60459ca9182bf98ec385b2); /* statement */ 
coverage_0x04be09c7(0xaa8315b94a86554018fd67cd4720c66096ba9df01bf232f7486a558a4d07c3d1); /* branch */ 
if (val.typeCode == TUPLE_TYPECODE) {coverage_0x04be09c7(0x64aed3ca79afa2b5830755f530bbacbf1f4fcf59370ce9a47b43990a0aea7940); /* branch */ 

coverage_0x04be09c7(0xdba404a9098e9ad122aaba3c7543bfda0c0a2aa2354c20e2213942ced009e15b); /* line */ 
            coverage_0x04be09c7(0xfeef635427a3428f4329cd169b7ac49dee7c6ebe1a3180b33635d1b57c009c80); /* statement */ 
uint256 valueCount = val.tupleVal.length;
coverage_0x04be09c7(0xc591b4897ff992a5b6e7b36fd3013a65d7f62738f3d1447b57a2baa1ea6b157c); /* line */ 
            coverage_0x04be09c7(0xea1a2b10c1129b1e2319c4af0ec9770e78b1a1291154faf753cbf6f9a752e0ef); /* statement */ 
for (uint256 i = 0; i < valueCount; i++) {
coverage_0x04be09c7(0x9cc14d008a6ef0896e9f9bd120f96355cf9e0dae18d3995f035e6a75b5317838); /* line */ 
                coverage_0x04be09c7(0x54059208a7cf28d3f5c639a9e236c65e4e448ccee042c5478aa177c27072739c); /* statement */ 
if (!isValidTypeForSend(val.tupleVal[i])) {coverage_0x04be09c7(0x6459a6a3fbb776e1500d903ed96ad5a1cee6633a227549320c793133807789a6); /* branch */ 

coverage_0x04be09c7(0xd192203c1c21ae1078f093dcd15db6704c1e5266b8733873702df79d588a2757); /* line */ 
                    coverage_0x04be09c7(0xe3f630fa56ad5c276957217916df6b6c48323efc32cbdc96f62a30aff4d8366f); /* statement */ 
return false;
                }else { coverage_0x04be09c7(0x0144945288b9fc66ca5e8e58717a024033f880439de3488ea48c346bf56554ec); /* branch */ 
}
            }
coverage_0x04be09c7(0x52c8bb1350aa170be07eff99f76bf1ef81993e491ee2251832355b9443aa410b); /* line */ 
            coverage_0x04be09c7(0x36bff3abcbf801122fd6e3e24e3f94d0fe7f22e5a711eeda9c574f54c1565807); /* statement */ 
return true;
        } else {coverage_0x04be09c7(0xdb938b14ebd24b66084e6117dfa0229456eb0f7f4e596e00f78c9d37c261e9fc); /* statement */ 
coverage_0x04be09c7(0xcb939a67f70f5f5458d08921a142f68c884e8f34d62a482d7913a088d140d179); /* branch */ 
if (val.typeCode == HASH_ONLY) {coverage_0x04be09c7(0xd724abc4856bb7310450ba1e4e28e65a699e0e36d4b6da8431bcb6c897568fbd); /* branch */ 

coverage_0x04be09c7(0x7d2050fb4cc312fdff67886270f190f0a03c96edc563420434412a5ffa72e58c); /* line */ 
            coverage_0x04be09c7(0x744bf149ea3a541d1ef4047b62651ed175b5e270623d7a1fafc4f4238c3bbc22); /* statement */ 
return false;
        } else {coverage_0x04be09c7(0xf3e9157b5348e6a146fb1b1c8313746c952589c41c09a42528dc8900f764df60); /* branch */ 

coverage_0x04be09c7(0x11fab9150c1f97abdabb0ef3f5929c1da2ead724dcb38fc2c0790ed519f3f5a1); /* line */ 
            coverage_0x04be09c7(0x548cb7f2007ac427bed67b6b5fa7fb59a16c6f86e8be9241d1d0f14e7fb3dded); /* assertPre */ 
coverage_0x04be09c7(0x30ac642715f7ed49d49859891215647655ab583c271898bf4208c124c070ca82); /* statement */ 
require(false, "Invalid type code");coverage_0x04be09c7(0x1ce5f43fb89f49eed0a9b4373f3e8138b11dcc54ecb1db30f477778eca19ffdb); /* assertPost */ 

        }}}}}
    }

    function newEmptyTuple() internal pure returns (Data memory) {coverage_0x04be09c7(0xdb83ccc9b0e47c209243d8008dbabf0376a1765678e11e03f2d2768b2394382e); /* function */ 

coverage_0x04be09c7(0x883487fe06b6f9e86e9b372720bc844e8651d55d7a70fd5e60a74e252e8e5c1b); /* line */ 
        coverage_0x04be09c7(0xebdf76e2b24e81c972d71e2568e15d9855ee6afa90df72e3f6944079e1184592); /* statement */ 
return newTuple(new Data[](0));
    }

    function newBoolean(bool val) internal pure returns (Data memory) {coverage_0x04be09c7(0x6406a5eaa7f4fbb9b5fc1fbc8c052fd1740ae7f155c387f309f1525eed32a2ee); /* function */ 

coverage_0x04be09c7(0x9c08342034d15eeb27750df8f505e9805413e0d39b0fbd2fb8029c28f8b614b6); /* line */ 
        coverage_0x04be09c7(0x6a9885083cd14eb24a0c4da40003cc525d73639d6d481d92680bb8564654118c); /* statement */ 
if (val) {coverage_0x04be09c7(0xdb783db42fd3a564dc36ef7298c53e9d29499aa7b9c1e25a665c9b34cbd8a22e); /* branch */ 

coverage_0x04be09c7(0x10292eb1cde2fc1566cf6f0f97884d115b44cabb8f21758c57aeb7078a37fb75); /* line */ 
            coverage_0x04be09c7(0x789710f1f54ad7f2ace683f9b2dc52ae8f215cf33745b03e50be3b500f7a5a95); /* statement */ 
return newInt(1);
        } else {coverage_0x04be09c7(0xa7e7900898a5c8d265557f386899396ced5f4c26b325d3757122a1d295a23ac7); /* branch */ 

coverage_0x04be09c7(0x1ab2ad6878ef9b5bc3f9b8c616364fb17bffa964855c21e23fa2872b3063ec8d); /* line */ 
            coverage_0x04be09c7(0xe0dfb96c2941595991b6ba467e4c3d2c1faecc9237840acbacddd24e27d259d4); /* statement */ 
return newInt(0);
        }
    }

    function newInt(uint256 _val) internal pure returns (Data memory) {coverage_0x04be09c7(0x34863474f175119669da93162f2b1f5e4a057bcbb31e2fcff2c6f901dd1caa6a); /* function */ 

coverage_0x04be09c7(0xf19d9e70401fb4f0658435b2e527a7614d4d5eabaaf32afdcd2589bf36fe2552); /* line */ 
        coverage_0x04be09c7(0xb9464b8aede3ba3185a1043f1773c50669e0f0852fd99664cb28c9408832131b); /* statement */ 
return Data(_val, CodePoint(0, 0, new Data[](0)), new Data[](0), INT_TYPECODE, uint256(1));
    }

    function newHashedValue(bytes32 valueHash, uint256 valueSize)
        internal
        pure
        returns (Data memory)
    {coverage_0x04be09c7(0x0f8a3366eae04721a64a833858f491eb31b0cbea62e018ea2bb5b2c797931f68); /* function */ 

coverage_0x04be09c7(0x137e2ef1ab8989102bd427643f70bc0d0d8f4b21e54a32d88e4e579c3ab3d22e); /* line */ 
        coverage_0x04be09c7(0x3f135af3e96de3c3ca6a5cbaa7532dc5942fc6d7ad6ea58ef74e59389b256be4); /* statement */ 
return
            Data(
                uint256(valueHash),
                CodePoint(0, 0, new Data[](0)),
                new Data[](0),
                HASH_ONLY,
                valueSize
            );
    }

    function newTuple(Data[] memory _val) internal pure returns (Data memory) {coverage_0x04be09c7(0xdd48495b7d492acd22053e8be09f18eccd8ffc88321d07a85ba6351624b957a5); /* function */ 

coverage_0x04be09c7(0xdb916a76a8c5a5e976dc8edd04128a07ab99506bfc130cfe2a9636068eabc9ca); /* line */ 
        coverage_0x04be09c7(0xa02820caa1db7c57672dfce2b8a7415b16f23404c69c8f1043acfaf0936eb12c); /* assertPre */ 
coverage_0x04be09c7(0x13ecd886a8ff296c9be33669a44e59fda261ff16af7c7ee092a2ea66c0220cf6); /* statement */ 
require(isValidTupleSize(_val.length), "Tuple must have valid size");coverage_0x04be09c7(0x2a2fff8ed251fa8c9508c63c0207202dd2f0d00ce85214444fe34b4afb136d48); /* assertPost */ 

coverage_0x04be09c7(0xe455e827bc639b953beb6b89f5049221f9313d42623790122d91efff58a41138); /* line */ 
        coverage_0x04be09c7(0x8e3e381ff63effcb267de359f227e30f80d08c6704b175a4a0ccac93a0f2c5da); /* statement */ 
uint256 size = 1;

coverage_0x04be09c7(0x5ac8f0b0997ac618159239e99ddea873834711844d7de9d539f8bbb6fbb2e8b0); /* line */ 
        coverage_0x04be09c7(0x24c531d7f49fb0fb7d52225d93517f5258f006932cf2b1be9f5f17fa2fb72ed8); /* statement */ 
for (uint256 i = 0; i < _val.length; i++) {
coverage_0x04be09c7(0x8238eaf4d35e555d053951e3fa7faae7f5585ca24622e98da081626ed62b20ba); /* line */ 
            coverage_0x04be09c7(0xa4a3dfae7968d308a1faeb9e6811bd7fb80608fa7d984863d8a017b6da5470b4); /* statement */ 
size += _val[i].size;
        }

coverage_0x04be09c7(0x785cb25b20180b2dc6f018caa136d94ca20edf5c2ef59d3d191fd275fecfa76f); /* line */ 
        coverage_0x04be09c7(0xdccad9b47c64278a98b04bdeb13d9d69e61c2b8e2e5950d5a41182dfecc456e3); /* statement */ 
return Data(0, CodePoint(0, 0, new Data[](0)), _val, TUPLE_TYPECODE, size);
    }

    function newTuplePreImage(bytes32 preImageHash, uint256 size)
        internal
        pure
        returns (Data memory)
    {coverage_0x04be09c7(0x4d56ef44a24b83643084a88921e880ab89de646f9802a52bc710412e3be4967f); /* function */ 

coverage_0x04be09c7(0x872620c5e00e2371a4f6c02002531a980ad551d1fdc729a1ba52acf1e588bab6); /* line */ 
        coverage_0x04be09c7(0xe00b320ca9a7bbe091bd73ae89eca5ff3f492868e2591a5e4ebf0e86c902f523); /* statement */ 
return
            Data(
                uint256(preImageHash),
                CodePoint(0, 0, new Data[](0)),
                new Data[](0),
                HASH_PRE_IMAGE_TYPECODE,
                size
            );
    }

    function newCodePoint(uint8 opCode, bytes32 nextHash) internal pure returns (Data memory) {coverage_0x04be09c7(0x428374565f7f79dc64b66db69433bdc1d0f4a6c1789935b895a2bdbef04c07be); /* function */ 

coverage_0x04be09c7(0x2beb93e32aad63e6a8a10b51c573dba66240c440c9c2701b751ae67208f320fe); /* line */ 
        coverage_0x04be09c7(0xfa99c7631c8c08b84188b1534efee669f72eae169d7ab329059d283828fed079); /* statement */ 
return newCodePoint(CodePoint(opCode, nextHash, new Data[](0)));
    }

    function newCodePoint(
        uint8 opCode,
        bytes32 nextHash,
        Data memory immediate
    ) internal pure returns (Data memory) {coverage_0x04be09c7(0xd5fc9f92deaf42e086a69d586d616b5ae0ef32dac6e6a0dc064e45466ae63968); /* function */ 

coverage_0x04be09c7(0xb670070c787d7f067da3725b27e43b9cd6474e5f6b1cc9a0c3405188c4b7b524); /* line */ 
        coverage_0x04be09c7(0x0e789f96fa2b50306efcf732b3dbf1f850a4c128527b3ad97693989610ee6e21); /* statement */ 
Data[] memory imm = new Data[](1);
coverage_0x04be09c7(0x57e92ed2101a4099a494f713530b6059996640d6d765f2467c75e63b79dedd1d); /* line */ 
        coverage_0x04be09c7(0x96ce3a4ebe49503e16757af803748d0c67b1bdf7b65d3a32729f8c8b55e7eba7); /* statement */ 
imm[0] = immediate;
coverage_0x04be09c7(0x28a6399854eaa441b1a10c94f4260e924122364fd89b33d792bf39a14f8545fd); /* line */ 
        coverage_0x04be09c7(0x00ed17eba585883e935460c052e4662c42d4a0e5a052663bcdaf3abb3ade23ef); /* statement */ 
return newCodePoint(CodePoint(opCode, nextHash, imm));
    }

    function newCodePoint(CodePoint memory _val) private pure returns (Data memory) {coverage_0x04be09c7(0x5a90f3f8386a3f717406a2a27d61854d3cb2fd00e53f8a9638762cda14124ddb); /* function */ 

coverage_0x04be09c7(0xcc7f9bc1bbbfd30a28f7e1642f720790b0d56ac69191305b80cabbc3e5622223); /* line */ 
        coverage_0x04be09c7(0xbd3aa6ef14d0009aac411a0f6544bb5db27f0cdeff7322137f55eaa8a307ae6f); /* statement */ 
return Data(0, _val, new Data[](0), CODE_POINT_TYPECODE, uint256(1));
    }
}
