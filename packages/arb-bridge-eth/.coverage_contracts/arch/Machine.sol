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

import "./Marshaling.sol";

import "../libraries/DebugPrint.sol";

library Machine {
function coverage_0xeb9aabe7(bytes32 c__0xeb9aabe7) public pure {}

    using Hashing for Value.Data;

    uint256 internal constant MACHINE_EXTENSIVE = 0;
    uint256 internal constant MACHINE_ERRORSTOP = 1;
    uint256 internal constant MACHINE_HALT = 2;

    function addStackVal(Value.Data memory stackValHash, Value.Data memory valHash)
        internal
        pure
        returns (Value.Data memory)
    {coverage_0xeb9aabe7(0x140bf63545439d52be90129b1ab07cf58a3883a083f6ba72fdfed5a099c7fcb6); /* function */ 

coverage_0xeb9aabe7(0x3c91ce565394260e08e8fcb9f66d319ea5fe5f1a7c79e5fce9f8a0e0823331a7); /* line */ 
        coverage_0xeb9aabe7(0x2024a9d923b47af1138cf26048e475a729638aa9c75a345ac6d9435030f64421); /* statement */ 
Value.Data[] memory vals = new Value.Data[](2);
coverage_0xeb9aabe7(0x0ef3b502b79045a2a19d8e14610b406eeb7d98dedfcbcf2a437067c46e87a733); /* line */ 
        coverage_0xeb9aabe7(0xdb0c0ef7e743759373e51162b8be774ba2c325ed16e2b45ea79917a993eda258); /* statement */ 
vals[0] = valHash;
coverage_0xeb9aabe7(0x17cbe11d54efcf360ebc1149824e87ff8125b4371fc195ce2e611ca92afa4d7b); /* line */ 
        coverage_0xeb9aabe7(0x68b34c05c157e9664289e2e472f23f0716fa68ff1e17600d1336938ef598ce66); /* statement */ 
vals[1] = stackValHash;

coverage_0xeb9aabe7(0x6bcae2ca0bbeacb91215588b10e72626c7a52ae3a7ff2c360138847efcade84f); /* line */ 
        coverage_0xeb9aabe7(0x165f88fa0f8d5573b00b13b1af0b9566a28c54d075257fbb0a676685f9e58a3e); /* statement */ 
return Hashing.getTuplePreImage(vals);
    }

    struct Data {
        bytes32 instructionStackHash;
        Value.Data dataStack;
        Value.Data auxStack;
        Value.Data registerVal;
        Value.Data staticVal;
        uint256 arbGasRemaining;
        bytes32 errHandlerHash;
        Value.Data pendingMessage;
        uint256 status;
    }

    function toString(Data memory machine) internal pure returns (string memory) {coverage_0xeb9aabe7(0xa6974d32e0c606116e7f65d42830df1c8569970364afb6a9ea06d4e99f4ef6ed); /* function */ 

coverage_0xeb9aabe7(0xf3eac890931917fe39142c97ec7d5b1ab5728f6185534ed58a651caf64715cf7); /* line */ 
        coverage_0xeb9aabe7(0x32abd1218e5637ba7ae9bfcf5df85fb5023dacfa9c75bcd43828ef8e32d9be9a); /* statement */ 
return
            string(
                abi.encodePacked(
                    "Machine(",
                    DebugPrint.bytes32string(machine.instructionStackHash),
                    ", \n",
                    DebugPrint.bytes32string(machine.dataStack.hash()),
                    ", \n",
                    DebugPrint.bytes32string(machine.auxStack.hash()),
                    ", \n",
                    DebugPrint.bytes32string(machine.registerVal.hash()),
                    ", \n",
                    DebugPrint.bytes32string(machine.staticVal.hash()),
                    ", \n",
                    DebugPrint.uint2str(machine.arbGasRemaining),
                    ", \n",
                    DebugPrint.bytes32string(machine.errHandlerHash),
                    ", \n",
                    DebugPrint.bytes32string(machine.pendingMessage.hash()),
                    ")\n"
                )
            );
    }

    function setExtensive(Data memory machine) internal pure {coverage_0xeb9aabe7(0x74a968549f49b92e88249e19ad3283d0d2406d082859b4155f9d9b3ff3203af7); /* function */ 

coverage_0xeb9aabe7(0x17086b4d8d15f3c13d8a7621cd8e6f3075d4101b395d97b1bd12db5bedf49595); /* line */ 
        coverage_0xeb9aabe7(0x02e599f911d2bea42817128c43e6e5e97b0113c14ee793788fef40fd3dac6b4b); /* statement */ 
machine.status = MACHINE_EXTENSIVE;
    }

    function setErrorStop(Data memory machine) internal pure {coverage_0xeb9aabe7(0x525eb06249d8106fd8537b54beecd323b5879321b3227881bcb163ae442e965f); /* function */ 

coverage_0xeb9aabe7(0x34f6b5d8143df0004f064000babe625b31d678d6464f28ae716a8ae79bccfc9c); /* line */ 
        coverage_0xeb9aabe7(0x0b278d43019357bd372baffc1cb7761c2fcc4711efe7ee7754bda0d591bc1e5d); /* statement */ 
machine.status = MACHINE_ERRORSTOP;
    }

    function setHalt(Data memory machine) internal pure {coverage_0xeb9aabe7(0xcee4361a7382399e536f043f03bda5b6193f551b17bbf6fb23600f63bf257810); /* function */ 

coverage_0xeb9aabe7(0xe923e49e2b1e69a7eb8579e80494f90d17741a59881d0865f6d339053ba56e70); /* line */ 
        coverage_0xeb9aabe7(0x75da2dab13d9799ed8f0b34dff21523544098b53c48cd9d90906a98e34b2c52f); /* statement */ 
machine.status = MACHINE_HALT;
    }

    function addDataStackValue(Data memory machine, Value.Data memory val) internal pure {coverage_0xeb9aabe7(0xdc7254ff8c7a1cb3a6a7b72bc57bbb286fa1e5140e9f6ae9a534dd6131628da8); /* function */ 

coverage_0xeb9aabe7(0x755f560283729e1877c6fd3737426957e3b35ff8e39c9e6290ab299ae664ff27); /* line */ 
        coverage_0xeb9aabe7(0x4a25325a385849c6ea23a7959b458080563a6a7e78eeb4df559b7b50b054ea50); /* statement */ 
machine.dataStack = addStackVal(machine.dataStack, val);
    }

    function addAuxStackValue(Data memory machine, Value.Data memory val) internal pure {coverage_0xeb9aabe7(0xe30db6d49819acb14a98b63e1fd6f12f974678055b2928790fe25804b15412fa); /* function */ 

coverage_0xeb9aabe7(0x4389261afd27dccafc5bf288f9bb0eafdba48625785f62a01d08a8d90a0e7d8b); /* line */ 
        coverage_0xeb9aabe7(0xb991124d053973c7f3f56cc0ba1094a1a645f954ef3bb153189a08a7b5ce479c); /* statement */ 
machine.auxStack = addStackVal(machine.auxStack, val);
    }

    function addDataStackInt(Data memory machine, uint256 val) internal pure {coverage_0xeb9aabe7(0x32b51809cb9caa829afaee1c9b228e72818dbc673fa0d0217fa44049069bb121); /* function */ 

coverage_0xeb9aabe7(0x734ffad39223c276d4da7c9144a4bf44b7986fcaf264483914d5ed0f4a3dd8b3); /* line */ 
        coverage_0xeb9aabe7(0x908cea4958a92da25eafb3ffaec1b16f62fc47d78e784286513670489e369fb7); /* statement */ 
machine.dataStack = addStackVal(machine.dataStack, Value.newInt(val));
    }

    function machineHash(
        bytes32 instructionStackHash,
        Value.Data memory dataStack,
        Value.Data memory auxStack,
        Value.Data memory registerVal,
        Value.Data memory staticVal,
        uint256 arbGasRemaining,
        bytes32 errHandlerHash,
        Value.Data memory pendingMessage
    ) internal pure returns (bytes32) {coverage_0xeb9aabe7(0x7527c31a57b884ae9285cc8ead0f8d9d437ec14a33881f424e4e2c59661793e1); /* function */ 

coverage_0xeb9aabe7(0x276594f97ee4f72cf4709cad9dbfe4c8c8e229488dba1b55b3184b20fcd95cb4); /* line */ 
        coverage_0xeb9aabe7(0xb477cb7decbf9fef45a3e0f8b467a85000f0560c1c64dd886df90ea2f1ffd147); /* statement */ 
return
            hash(
                Data(
                    instructionStackHash,
                    dataStack,
                    auxStack,
                    registerVal,
                    staticVal,
                    arbGasRemaining,
                    errHandlerHash,
                    pendingMessage,
                    MACHINE_EXTENSIVE
                )
            );
    }

    function hash(Data memory machine) internal pure returns (bytes32) {coverage_0xeb9aabe7(0xfaaee930fec70d053fdcb522155b65cb873cf4763fc907cad36a294651aad18e); /* function */ 

coverage_0xeb9aabe7(0xa1b941f80d2b64cfea36a7d27c7a446b4236090fad53680ad70d8141f4bf5804); /* line */ 
        coverage_0xeb9aabe7(0x59a33e5580c9510fade7468e96f70b84c4dd2e6d62ef9c0988ebc8ae042b4492); /* statement */ 
if (machine.status == MACHINE_HALT) {coverage_0xeb9aabe7(0x508b303fe7e151e1117fd47e5ee9496e921477fb17836489411190449e679d90); /* branch */ 

coverage_0xeb9aabe7(0xae11013e9ec69f4c3f04fcf8bda63d41edbc84704e49faf6fc204d23d1133fc1); /* line */ 
            coverage_0xeb9aabe7(0xaea292104a928d93f2cf910953e600fe2f5629f084e28da82c22e62334ae2280); /* statement */ 
return bytes32(uint256(0));
        } else {coverage_0xeb9aabe7(0xb43ef0ceb20cb8e37bd30636683f1bbdd19753ed7fe5a795ad78fdc68932f545); /* statement */ 
coverage_0xeb9aabe7(0xa2792d82978cd80f2b4b77480d4ef6c6b0faa052eccfd375cafc41611b974be0); /* branch */ 
if (machine.status == MACHINE_ERRORSTOP) {coverage_0xeb9aabe7(0xc2609f3386834e66e37794b35a5c8dee4c2b221abaaf1334eff94b0f493c3d04); /* branch */ 

coverage_0xeb9aabe7(0xb1169075adbe834060dd54eb259452e92862b8bd1665b01283dc48de8ac42cb0); /* line */ 
            coverage_0xeb9aabe7(0x659015196ea99caa7f50dc12d8e8cf8ce59f6199590e5ce9410ba82f0964d68c); /* statement */ 
return bytes32(uint256(1));
        } else {coverage_0xeb9aabe7(0x4b3db796891d5415e1b2ef167cd7df16b35602a8821395771930abeca2a03d26); /* branch */ 

coverage_0xeb9aabe7(0xb5ac16584b43f9d12ded91e2531d52fa74e2a777b0fabd2118e5accc0e5d5fbf); /* line */ 
            coverage_0xeb9aabe7(0xb9bdd713c263ea9e4d76259bbb159162251bf32a580ed78a769fb61822db795c); /* statement */ 
return
                keccak256(
                    abi.encodePacked(
                        machine.instructionStackHash,
                        machine.dataStack.hash(),
                        machine.auxStack.hash(),
                        machine.registerVal.hash(),
                        machine.staticVal.hash(),
                        machine.arbGasRemaining,
                        machine.errHandlerHash,
                        machine.pendingMessage.hash()
                    )
                );
        }}
    }

    function clone(Data memory machine) internal pure returns (Data memory) {coverage_0xeb9aabe7(0x376c82f15b4f978ddbfaa52c958c5b66463d46a574e0d9d58914fdadb04920ec); /* function */ 

coverage_0xeb9aabe7(0x45a53d7dad9c2200eb75eeeccd22f351fa8088a709d879d9b1773f57ce729ce8); /* line */ 
        coverage_0xeb9aabe7(0x8f20ae819f256e775b3562873b1a190fe0b4c4efc2bdf6bb54a08b6a59df8d23); /* statement */ 
return
            Data(
                machine.instructionStackHash,
                machine.dataStack,
                machine.auxStack,
                machine.registerVal,
                machine.staticVal,
                machine.arbGasRemaining,
                machine.errHandlerHash,
                machine.pendingMessage,
                machine.status
            );
    }

    function deserializeMachine(bytes memory data, uint256 offset)
        internal
        pure
        returns (
            uint256, // offset
            Data memory // machine
        )
    {coverage_0xeb9aabe7(0xb6122bae5d304d3d2f70775919476f82ea083bfff32d13d46d52d72dece732b0); /* function */ 

coverage_0xeb9aabe7(0x23cb18f7d16feacecef2582e4bd1ce6789b500138eb92f2e9829fe7d87d0c5b5); /* line */ 
        coverage_0xeb9aabe7(0x752fe58c6c45ea793bf4ca3884d09983e0de9da592efb8b41ada8be51d905f07); /* statement */ 
Data memory m;
coverage_0xeb9aabe7(0x71c9433c5f18e447d867e4659ec07efa5d1ec0ade899b1a59d94339123ceea49); /* line */ 
        coverage_0xeb9aabe7(0xb47ed0228a05a3258d396ea2f38ce84b358ae63e7b2b3b3e238565fae9f7d58f); /* statement */ 
m.status = MACHINE_EXTENSIVE;
coverage_0xeb9aabe7(0x44122bdd1a447824c4ef8c31b3a8d1a9a5be399cad2525996b236205f95a121b); /* line */ 
        coverage_0xeb9aabe7(0x0918cd2bc70ac2d63fd00fe8be94e566ab301c8891aa490a389c502c9f86723c); /* statement */ 
uint256 instructionStack;
coverage_0xeb9aabe7(0x2cd734b6bd038ce4107db7fe0bd71ae2145d295bc83b1dc5eb57d6be25a77603); /* line */ 
        coverage_0xeb9aabe7(0x161070ff59e571d581dcca6d098922c7760d953e6b0ce4a38e852d08a8c8bb6a); /* statement */ 
uint256 errHandler;
coverage_0xeb9aabe7(0x5fedc8255c60cdc269a181153bfa3629efa46d765e011578f6a972b21d4a1024); /* line */ 
        coverage_0xeb9aabe7(0x341c7889d01c479c4b2378ec2e74abe5146c6bbd170dcb79c4964a3542c1410e); /* statement */ 
(offset, instructionStack) = Marshaling.deserializeInt(data, offset);

coverage_0xeb9aabe7(0xa0bac3eac466e81cfd7a6cef380453a581e6b09b8a2f3cbfffb0d61b3cf08739); /* line */ 
        coverage_0xeb9aabe7(0x52b426c88760b362480ec6e61dee9c9378bedec6ce4a4f974223fceeb8a5106f); /* statement */ 
(offset, m.dataStack) = Marshaling.deserializeHashPreImage(data, offset);
coverage_0xeb9aabe7(0x4ab091b13e6fb8483ef079cc6e15ec6645309a0844550833ecb004dada4f70fd); /* line */ 
        coverage_0xeb9aabe7(0x50efd1bb3c9f9bc68192f5f82a6f1a7c2d1a1f72f8411ce2223323a404eda04b); /* statement */ 
(offset, m.auxStack) = Marshaling.deserializeHashPreImage(data, offset);
coverage_0xeb9aabe7(0x7656196aed62dd5f41ec51ad6263a242bcf5fdf143aaaa2afb4847f338a94a6a); /* line */ 
        coverage_0xeb9aabe7(0x89c65c7fe8fe55d042cfcc15cad6c7585a816ff2162b003d4d57baa24e66ba14); /* statement */ 
(offset, m.registerVal) = Marshaling.deserialize(data, offset);
coverage_0xeb9aabe7(0x551aa4228bc535943f288574a42efa8cbf19c0a532708df31bc65a26925c78f4); /* line */ 
        coverage_0xeb9aabe7(0x6093e0193579f06420e84074376fa1dfaaf002460d57ee482e1d4366142d25b0); /* statement */ 
(offset, m.staticVal) = Marshaling.deserialize(data, offset);
coverage_0xeb9aabe7(0x49f3143209e5246af3c2b86f452ebaa5abe156820085531eb2c561aa69e12d3a); /* line */ 
        coverage_0xeb9aabe7(0xbf55cf8a0d569e61706f69383e2c3e1923bc66741211a66e5456acfe0d08216d); /* statement */ 
(offset, m.arbGasRemaining) = Marshaling.deserializeInt(data, offset);
coverage_0xeb9aabe7(0x4114e36c15a03909dab9e27026d066501519a91de3f3ce114edc06f10472472e); /* line */ 
        coverage_0xeb9aabe7(0x8fedd69c1eb76769c2500fb3d17bc15a41e028b4a0da7fc8b772b41562c52f55); /* statement */ 
(offset, errHandler) = Marshaling.deserializeInt(data, offset);
coverage_0xeb9aabe7(0x776e1649a106d87a42be518d9b83a01ae1522373ce655d3712e9d34d5d4b4723); /* line */ 
        coverage_0xeb9aabe7(0xa2035d48f145d790eae1a1db9fde4fca08f92294f06da623f343c65e0b4a7f8b); /* statement */ 
(offset, m.pendingMessage) = Marshaling.deserialize(data, offset);

coverage_0xeb9aabe7(0xdb54e1e38261fbe0d5fdf0b7fbd42542fa72890455a052f050c10f11b0091572); /* line */ 
        coverage_0xeb9aabe7(0x9b755527bcd6ee3ccc6e9d5d21325ae4e5662c7c7ba02494c332a97bcaad52d7); /* statement */ 
m.instructionStackHash = bytes32(instructionStack);
coverage_0xeb9aabe7(0x0b10b44a50ffd326a9f4f70f7e51215ea1412eda116432ca698df213ae7a3a35); /* line */ 
        coverage_0xeb9aabe7(0x6bc37e12450205e2e0118491fc5425154725d5fc3d85a6ea97a4bfa34b3b01a7); /* statement */ 
m.errHandlerHash = bytes32(errHandler);
coverage_0xeb9aabe7(0xa42e45f85af03c37ff1136f8eb938ca3021e7c8b2927e100dbfbba82a32b684e); /* line */ 
        coverage_0xeb9aabe7(0x514e3a90a81a75ec92886aca17c5e99da2714ca097dea2023071c2ddf35bef0d); /* statement */ 
return (offset, m);
    }
}
