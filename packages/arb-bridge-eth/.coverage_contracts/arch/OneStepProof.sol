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

import "./IOneStepProof.sol";
import "./Value.sol";
import "./Machine.sol";
import "../inbox/Messages.sol";
import "../libraries/Precompiles.sol";

// Originally forked from https://github.com/leapdao/solEVM-enforcer/tree/master

contract OneStepProof is IOneStepProof {
function coverage_0x0dbb89fa(bytes32 c__0x0dbb89fa) public pure {}

    using Machine for Machine.Data;
    using Hashing for Value.Data;
    using Value for Value.Data;

    uint256 private constant SEND_SIZE_LIMIT = 10000;

    uint256 private constant MAX_UINT256 = ((1 << 128) + 1) * ((1 << 128) - 1);
    uint256 private constant MAX_PAIRING_COUNT = 30;

    string private constant BAD_IMM_TYP = "BAD_IMM_TYP";
    string private constant NO_IMM = "NO_IMM";
    string private constant STACK_MISSING = "STACK_MISSING";
    string private constant AUX_MISSING = "AUX_MISSING";
    string private constant STACK_MANY = "STACK_MANY";
    string private constant AUX_MANY = "AUX_MANY";
    string private constant INBOX_VAL = "INBOX_VAL";

    function executeStep(
        bytes32 inboxAcc,
        bytes32 messagesAcc,
        bytes32 logsAcc,
        bytes calldata proof
    ) external view returns (uint64 gas, bytes32[5] memory fields) {coverage_0x0dbb89fa(0xd9252c666037fae79282cc1bb16928f9e3c4f6aaa5eb364b6773cb87c070b9c9); /* function */ 

coverage_0x0dbb89fa(0x2af394f6fe0541c6288a39921c576c99c7b79de2cce840f91d7b685fa2040929); /* line */ 
        coverage_0x0dbb89fa(0x63f4af9a26dbf2ad9aa65dffdef7a39c50bacac5478dc58aff1f212648e85f58); /* statement */ 
AssertionContext memory context = initializeExecutionContext(
            inboxAcc,
            messagesAcc,
            logsAcc,
            proof
        );

coverage_0x0dbb89fa(0x5554199226b9324156a7232608b7d60c459829e553090beae6599e6b9b89922a); /* line */ 
        coverage_0x0dbb89fa(0x370b9a552b4da943e8297105f5a49c64b970a45f194d30c1a67e9149d2168fe1); /* statement */ 
executeOp(context);

coverage_0x0dbb89fa(0x0484233d3be097b155a49697fe9011f4508e6d78b99fc1f70d3c8146798351a0); /* line */ 
        coverage_0x0dbb89fa(0xba23da8b92aa5d75bb1b89e20f0206a833c28eb2b7344f8de6363bbbb7de070b); /* statement */ 
return returnContext(context);
    }

    function executeStepWithMessage(
        bytes32 inboxAcc,
        bytes32 messagesAcc,
        bytes32 logsAcc,
        bytes calldata proof,
        uint8 _kind,
        uint256 _blockNumber,
        uint256 _timestamp,
        address _sender,
        uint256 _inboxSeqNum,
        bytes calldata _msgData
    ) external view returns (uint64 gas, bytes32[5] memory fields) {coverage_0x0dbb89fa(0x194a5db7bdc639f70fd59b5bd8260bcc907fb222a522ab4d4bc95b458c7e0d65); /* function */ 

coverage_0x0dbb89fa(0xad3024283a50e0ec64881caa063a5a0f3ffebc76b380483e3684b2425c999d6b); /* line */ 
        coverage_0x0dbb89fa(0xafba6e41476b331e43ba58fe00afa576dc9d55400169d099180144017c531115); /* statement */ 
AssertionContext memory context = initializeExecutionContext(
            inboxAcc,
            messagesAcc,
            logsAcc,
            proof
        );

coverage_0x0dbb89fa(0x80fd75bbe80c9c6ba5341659283462ec09e9de6d97254ac1b99c2d364c53819f); /* line */ 
        coverage_0x0dbb89fa(0xfa911a0c2dd42e0e1689532a7735113f46b1f1eeb93c345d02f747c547e11b95); /* statement */ 
context.inboxMessageHash = Messages.messageHash(
            _kind,
            _sender,
            _blockNumber,
            _timestamp,
            _inboxSeqNum,
            keccak256(_msgData)
        );

coverage_0x0dbb89fa(0xb1f2413b4248feb0e13b0a6a5d0794238c150bac5dba18f57d49afb861c092a0); /* line */ 
        coverage_0x0dbb89fa(0x89d7b16ec512ccf527a25bcef0d6b7af57278292e240484ccf2a1a7f9a375d34); /* statement */ 
context.inboxMessage = Messages.messageValue(
            _kind,
            _blockNumber,
            _timestamp,
            _sender,
            _inboxSeqNum,
            _msgData
        );
coverage_0x0dbb89fa(0x12645001adbfc6d79365a8e1b141be96596ac36d043364826fdb7a69e51f6ea2); /* line */ 
        coverage_0x0dbb89fa(0x01ec743e977adb23983a0c2d83aab767b37fd03f2284fbc64c8fabfd14e8cf89); /* statement */ 
executeOp(context);
coverage_0x0dbb89fa(0x5bb1bc46caf995fe61ee8af2d558cb9e92bf703d7c4a3362885c80a1145942f4); /* line */ 
        coverage_0x0dbb89fa(0xa744717efdf0fde06cdc4f2fb79173ad2ad6be1d7ce8ece8ada3745a7a5be437); /* statement */ 
return returnContext(context);
    }

    // fields
    // startMachineHash,
    // endMachineHash,
    // afterInboxHash,
    // afterMessagesHash,
    // afterLogsHash

    function returnContext(AssertionContext memory context)
        private
        pure
        returns (uint64 gas, bytes32[5] memory fields)
    {coverage_0x0dbb89fa(0xf00f1baa90b98a60036dfadb109f23a7824e64a7aab159aa9986ab0e8669eeff); /* function */ 

coverage_0x0dbb89fa(0xf777a580fe39eb0e82140fde8876f9d90d917093a852c8c869128cb7de42e224); /* line */ 
        coverage_0x0dbb89fa(0xad0f8f6ed5ef5ab322cb3896f43d602febb8fe3f185cb4c41f99fd8cec4b13f8); /* statement */ 
return (
            context.gas,
            [
                Machine.hash(context.startMachine),
                Machine.hash(context.afterMachine),
                context.inboxAcc,
                context.messageAcc,
                context.logAcc
            ]
        );
    }

    struct ValueStack {
        uint256 length;
        Value.Data[] values;
    }

    function popVal(ValueStack memory stack) private pure returns (Value.Data memory) {coverage_0x0dbb89fa(0x22e57e688476760bf048a004212d298e8c9745aca0c97d5188388f7c5586ecc4); /* function */ 

coverage_0x0dbb89fa(0x40c9419851baa7da4b034b206ffbea14206203388dbd7fa8a596db58c7ee2602); /* line */ 
        coverage_0x0dbb89fa(0x95ee4b55d42b65510439c57fee0ab6e5d992f27d0b2edcd8e2828ae52baceb4d); /* statement */ 
Value.Data memory val = stack.values[stack.length - 1];
coverage_0x0dbb89fa(0xb4e2396c31fde8c514f667d56a773c2838868b71516d1e0bf4aab3684240c0de); /* line */ 
        stack.length--;
coverage_0x0dbb89fa(0x4022b1c8e486249f267f6e62db4cc806aa273123067ca86f7532737882995a38); /* line */ 
        coverage_0x0dbb89fa(0xef9d4343e8b0b7e1444bd9a0407a298340c16095b5ea223a13ce1853bbcb1d09); /* statement */ 
return val;
    }

    function pushVal(ValueStack memory stack, Value.Data memory val) private pure {coverage_0x0dbb89fa(0x7cb58d4f9d2039ef71f81d40bebd196296f4887e8d328f28ea6c9572e0f277af); /* function */ 

coverage_0x0dbb89fa(0x868e137be6e331d1429c9d49028d03189314618137bf9e1d43a2059c3e3ed609); /* line */ 
        coverage_0x0dbb89fa(0x8f2938cd1a8a751cbfe425cf2cf4c90580aea5c60e1339b122111ee19ec57c7c); /* statement */ 
stack.values[stack.length] = val;
coverage_0x0dbb89fa(0xe80ae0661eeb9f3f6f3051c9722507ffa6d129042afba2c05f885712e631e6a5); /* line */ 
        stack.length++;
    }

    struct AssertionContext {
        Machine.Data startMachine;
        Machine.Data afterMachine;
        bytes32 inboxAcc;
        bytes32 messageAcc;
        bytes32 logAcc;
        uint64 gas;
        Value.Data inboxMessage;
        bytes32 inboxMessageHash;
        ValueStack stack;
        ValueStack auxstack;
        bool hadImmediate;
        uint8 opcode;
        bytes proof;
        uint256 offset;
    }

    function handleError(AssertionContext memory context) private pure {coverage_0x0dbb89fa(0x4e7298bda719656eee7fd197910432705623fc161a1dfd2d37c3c75e7de4566c); /* function */ 

coverage_0x0dbb89fa(0x8320ed2b14b13f770251635a3d03306339fc0b739acd93b11c1a825365dc3ece); /* line */ 
        coverage_0x0dbb89fa(0x0e6c863cdf63e4c125e125b0687c4e5e13022e3ea317730983b7651de90d039d); /* statement */ 
if (context.afterMachine.errHandlerHash == CODE_POINT_ERROR) {coverage_0x0dbb89fa(0x42cec730457544ad7f40518c09e445baaf0da9f66e6982d95bef837bbb9f0ee4); /* branch */ 

coverage_0x0dbb89fa(0x876c9ecd93c2c294d909d743746651e798c8bb048b4b6a02ac0de996471f5d46); /* line */ 
            coverage_0x0dbb89fa(0xefa52fed81938eceb3902fab89170fbe3936e29c57445750d6d0d861439b0517); /* statement */ 
context.afterMachine.setErrorStop();
        } else {coverage_0x0dbb89fa(0x1714d190787a48f44f4e8066557d22206a17b61f192a412cb328ea1e35dadbed); /* branch */ 

coverage_0x0dbb89fa(0x0f2c16be568f395a3f253d193e0bb5d81d5ed1b6564bec612adabe4950145a2c); /* line */ 
            coverage_0x0dbb89fa(0x2a571727dc31db9fac115b826e252659f14e74e7b18a1ad2dc51f18365e439e5); /* statement */ 
context.afterMachine.instructionStackHash = context.afterMachine.errHandlerHash;
        }
    }

    function deductGas(AssertionContext memory context, uint64 amount) private pure returns (bool) {coverage_0x0dbb89fa(0x9b5fce6d2182eedf47283e2e9f12214cafe5439e00c6a1c03945f8a62198f140); /* function */ 

coverage_0x0dbb89fa(0xbc2ef32010219a1a41d467dffe0e043ba63fdc670476dee671c087d566b9a748); /* line */ 
        coverage_0x0dbb89fa(0xca9b5d0c2e979b1d60325113aa4c8a6ec5812fffcaa61bfe18001476e4b8525a); /* statement */ 
context.gas += amount;
coverage_0x0dbb89fa(0x312b6b9d6b3b7f40efb03e827ed525f11b049ff77d7fb199465b33b0a9af3f93); /* line */ 
        coverage_0x0dbb89fa(0x4d5fa66301e591f5b8a02c2298c68cfc982dd0d48545d9e953aae5f5679efbd5); /* statement */ 
if (context.afterMachine.arbGasRemaining < amount) {coverage_0x0dbb89fa(0x2dad5dc294a2c13199e5e8ab8954668ce6cb22c3edf8e5714acb06eca6e175e4); /* branch */ 

coverage_0x0dbb89fa(0xbae78b608f4a6fa4823580caaaedceea2623c5e3009e188acae7af53951d97ab); /* line */ 
            coverage_0x0dbb89fa(0xaf640ffbe3832c5d9f2e12607f23f18ac1947d9fe99ffc95b98afdcf102f4a65); /* statement */ 
context.afterMachine.arbGasRemaining = MAX_UINT256;
coverage_0x0dbb89fa(0xdd4b22456567cc68b1024067f6aa0ee730660f4d71d4b3daa394a62ee41701e2); /* line */ 
            coverage_0x0dbb89fa(0x006cebab8c158ae473cc379ee885913bcbe3906d0bdfd796ff7bf1c29cf0110d); /* statement */ 
handleError(context);
coverage_0x0dbb89fa(0xe9f81d99f51b14ee64eaf3a0e711579ac659f545b1086d94a0fd0f984348b060); /* line */ 
            coverage_0x0dbb89fa(0x38fdac45d5c4fd98c7308f93786b8ec49fe7dcc424a5aaeb684a4f701f52899b); /* statement */ 
return true;
        } else {coverage_0x0dbb89fa(0xb38f1445efed94e619a41c9a72e817c9182eca87fba45148934ffcc3b652bcce); /* branch */ 

coverage_0x0dbb89fa(0xaf0ef45789e469d3b53094e0a3643bb38d4f08d41cde97437455fcd48133f8b4); /* line */ 
            coverage_0x0dbb89fa(0xe169ce7ac37c524f815ea1ddaf272a5b7078b5b8b7f12255116b2cc72b8a4b6f); /* statement */ 
context.afterMachine.arbGasRemaining -= amount;
coverage_0x0dbb89fa(0x7db6601fb69fbfa1e09716eba7c85ffe873db51abac938a17958462b26aad8e5); /* line */ 
            coverage_0x0dbb89fa(0x04e02bc06a291c28120ca7fd96c714c77f6696163aa0e9e1916a626d166c08da); /* statement */ 
return false;
        }
    }

    function handleOpcodeError(AssertionContext memory context) private pure {coverage_0x0dbb89fa(0xd466cbffc565836a0a809db329d44610712429d825dd6bb55e503dedf8309e27); /* function */ 

coverage_0x0dbb89fa(0x85d8a8bed175470cee1db59deaa525367331e580e652d9e4fdce2437b68a35e9); /* line */ 
        coverage_0x0dbb89fa(0x7f8387d27cd7a6f6666238e6d707ed0064607120bf3bf376270720ab37e15b69); /* statement */ 
handleError(context);
        // Also clear the stack and auxstack
coverage_0x0dbb89fa(0x72c80bfbe103e0ca37375727291517ab56bd8a2d6c918e1417f5ebb16ddc8e9d); /* line */ 
        coverage_0x0dbb89fa(0x3231e94535833bea32a998fefc6d03ed82f4842e4fde22e3430d312a9c07eb96); /* statement */ 
context.stack.length = 0;
coverage_0x0dbb89fa(0xe7830bf841192cb352c5b8cd0ea9d62c44a7486ffa49e265c7d0ebf947a31683); /* line */ 
        coverage_0x0dbb89fa(0x6973a0b76d1e4532ef67030123496d1e59de4129fb3c1c9eca13cc87cc7443c8); /* statement */ 
context.auxstack.length = 0;
    }

    function initializeExecutionContext(
        bytes32 inboxAcc,
        bytes32 messagesAcc,
        bytes32 logsAcc,
        bytes memory proof
    ) internal pure returns (AssertionContext memory) {coverage_0x0dbb89fa(0x30ef52aefd5987e5a0bfbc7f495b32ab6d2c53fb2e69d5a26490005788f5fb81); /* function */ 

coverage_0x0dbb89fa(0xa340810bbbe34149a4ae7b152c76a9a71f0ccc0a1be92a322f89f5985e51d692); /* line */ 
        coverage_0x0dbb89fa(0xd3ad0bc508a964d911c46bab154a65d7ca545ca891f6900ef6efb4ac4493e490); /* statement */ 
uint8 stackCount = uint8(proof[0]);
coverage_0x0dbb89fa(0x4b3c7a16753c7c7ae6a30998fcc9b5e9b126d27024f30cb5dd29c67c938aac88); /* line */ 
        coverage_0x0dbb89fa(0x011af525b824256042e688004d6a662639bf456beb357469cf7d6291517ea400); /* statement */ 
uint8 auxstackCount = uint8(proof[1]);
coverage_0x0dbb89fa(0x126a62dbdf28166c39296c8492f32b556369d5298b78a06fba02f60f15918cd6); /* line */ 
        coverage_0x0dbb89fa(0xae1ff5a501b924e6c8e5c658e8cb9db563ca393302839a613fc6301a52db3d54); /* statement */ 
uint256 offset = 2;

        // Leave some extra space for values pushed on the stack in the proofs
coverage_0x0dbb89fa(0x9f0abd70e683f8cc1d91c596c155e8fb190f9faa953f99e2c59509a6aa258bc7); /* line */ 
        coverage_0x0dbb89fa(0x0106dc20595994b969a0f9857cab3b8cd06099c058a495fbc5e9ae05212c8a54); /* statement */ 
Value.Data[] memory stackVals = new Value.Data[](stackCount + 4);
coverage_0x0dbb89fa(0x7715aff3cafd3c05e0a050bd87fe98ec63c31592bf625bbba88e6206a8c6c015); /* line */ 
        coverage_0x0dbb89fa(0xdaf75b77f508284fe5ad26818592d81d4d0d9befab7d38063bc7839219e0cc95); /* statement */ 
Value.Data[] memory auxstackVals = new Value.Data[](auxstackCount + 4);
coverage_0x0dbb89fa(0x45d5243b8b4a07e628cddf5fbe34dedaf7631f76bfdc2a05ef08bff488f2db54); /* line */ 
        coverage_0x0dbb89fa(0xcf20b0d1fb43b42290bf86e72326db6b1f22214f43a225d2308820c1ebe6a9e9); /* statement */ 
for (uint256 i = 0; i < stackCount; i++) {
coverage_0x0dbb89fa(0x08b4b76f2bb6a6ba70cafe4ce36e4d4b3c6a1e6b06484b152c6f911d7d9b1e25); /* line */ 
            coverage_0x0dbb89fa(0x2ea8120ca7aac4276d6507fb182381d2462e5f62afd2e8a3d3c8137310953f67); /* statement */ 
(offset, stackVals[i]) = Marshaling.deserialize(proof, offset);
        }
coverage_0x0dbb89fa(0x29845f4e7581285b72fd2e3a07548297c3348769dd4e775ac97e88d809f4bf60); /* line */ 
        coverage_0x0dbb89fa(0x00569a34d078d941ec46f78fa38b0d39e20eca8d3621c9293c5f28f2404dd578); /* statement */ 
for (uint256 i = 0; i < auxstackCount; i++) {
coverage_0x0dbb89fa(0xf4b952b7d53a75c2e690cc29358961a77c5f7e29a40c320c67229e1f609f1c49); /* line */ 
            coverage_0x0dbb89fa(0xd98641b681b6a592c5032fac933e90540882ff4d0da5280b7a5d0a5c3cd16052); /* statement */ 
(offset, auxstackVals[i]) = Marshaling.deserialize(proof, offset);
        }
coverage_0x0dbb89fa(0xff8109aae38b8d90ae74010279bda76ca891c5af3fc8b1d740d6602f3d6cf3b5); /* line */ 
        coverage_0x0dbb89fa(0x04d69e02ff507792b391baec5294bd2717f791519ec4999a2c21a6df13041499); /* statement */ 
Machine.Data memory mach;
coverage_0x0dbb89fa(0xead90c14fa71212b2401f8ef1188cbe8b0a42d2c8f81936b947cb1b911d47272); /* line */ 
        coverage_0x0dbb89fa(0xac77a2d4791bb1d3e120a669773ef85ed75dc7a30bf1b8af16fdc612139988b3); /* statement */ 
(offset, mach) = Machine.deserializeMachine(proof, offset);

coverage_0x0dbb89fa(0xe90ad5431fe82ffe534c7fdb05e7cd7bae3c719537201c6ef68b4ea63adbed68); /* line */ 
        coverage_0x0dbb89fa(0x9c0d68daeabaa12abb449f410d46f7126e34806cbc468cb05ff1574ec5da1c1f); /* statement */ 
uint8 immediate = uint8(proof[offset]);
coverage_0x0dbb89fa(0xa71b4cafbefc32ee5c092869b12223fd76bb8761f8207e96c4a83fb867f63201); /* line */ 
        coverage_0x0dbb89fa(0xfe95b98d0b4ab9ae2fd8f59f12c5d7c7ca3353c82926046d9ac027df8287e54b); /* statement */ 
uint8 opCode = uint8(proof[offset + 1]);
coverage_0x0dbb89fa(0xad7517e4adb8fcf6e81635fc90cba8b0181c81eb52fc6bbee4b0c7929d3e2151); /* line */ 
        coverage_0x0dbb89fa(0x706938b519dbd7be8a4f0d5719354ce3b50733a48fa27fd9bc5898adc123955b); /* statement */ 
offset += 2;
coverage_0x0dbb89fa(0x39b80a4507a0115a0ad4ab697d3dcd02da9d539d0ff00010203d05a332b25f38); /* line */ 
        coverage_0x0dbb89fa(0x6259e3eec9d78dbf48203936f202dddbe096d797fa61acf6ef1d6898e67a4bea); /* statement */ 
AssertionContext memory context = AssertionContext(
            mach,
            mach.clone(),
            inboxAcc,
            messagesAcc,
            logsAcc,
            0,
            Value.newEmptyTuple(),
            0,
            ValueStack(stackCount, stackVals),
            ValueStack(auxstackCount, auxstackVals),
            immediate == 1,
            opCode,
            proof,
            offset
        );

coverage_0x0dbb89fa(0xe0148c7e365e0f27893429050da5f487fe69500bf58dd72c759e3aab045b5a65); /* line */ 
        coverage_0x0dbb89fa(0x421b2dc9a27bce4cfe395d879d8846da5392ef9aeeea5a0fb903044b1c5a9f49); /* assertPre */ 
coverage_0x0dbb89fa(0xe10dd035fb1fe890307000883e5baa1109aaeadec39d10a0621d74b8018ad308); /* statement */ 
require(immediate == 0 || immediate == 1, BAD_IMM_TYP);coverage_0x0dbb89fa(0x187030b6040ed22de4a06dc7cfc97d86f870adecc17cf07a27dcad8633015e38); /* assertPost */ 

coverage_0x0dbb89fa(0xba12c1f6b65c6049f78329c41662ffa10889441d3c1a359da6c765017b97827e); /* line */ 
        coverage_0x0dbb89fa(0xea844c7aca64c6ffca8de4e9f684a9fd103d4a5def4b7c7aad430bfa492a63df); /* statement */ 
Value.Data memory cp;
coverage_0x0dbb89fa(0xcd5c26e1af0e2504c26603b8dee6407a56be064879bb70d8b4de3f6b7d877e82); /* line */ 
        coverage_0x0dbb89fa(0x18235725b305c62ccc148857bd3a603d4dd66ea8c856dfc6c854463558d52671); /* statement */ 
if (immediate == 0) {coverage_0x0dbb89fa(0xdd1329c70c08f71d519b5a83cc9279a9f9899de6181018a6b826f3f2546298dc); /* branch */ 

coverage_0x0dbb89fa(0xd5a33c5baddbd2de25a6303317fc36e7846e4e8314c99a582704f344cf4ae1cb); /* line */ 
            coverage_0x0dbb89fa(0x1e8f899750ce4074cf42bcf0fa7402d420677075a57000e05f8b17e8728ab1fd); /* statement */ 
cp = Value.newCodePoint(uint8(opCode), context.startMachine.instructionStackHash);
        } else {coverage_0x0dbb89fa(0x600d71654999fc38efa2d02e353ab4dd71a5dd7b4aab193e70a1397f3ca9db62); /* branch */ 

            // If we have an immediate, there must be at least one stack value
coverage_0x0dbb89fa(0xd7b5e33995169b41bb08fd4d43470e0fbb38afd347203accd630ce2a5878731e); /* line */ 
            coverage_0x0dbb89fa(0x1196bec8263b14827f30aa140a49025832e6dc816c87dcbe57af6ddc338659dc); /* assertPre */ 
coverage_0x0dbb89fa(0x256c017a25e5be040833ed5bf6fab34d880220b2275bc0e17efa7c24e9e4062b); /* statement */ 
require(stackVals.length > 0, NO_IMM);coverage_0x0dbb89fa(0x172c10c0ba0e7a22b4248c7712e880f60276d8122ee820dd692b1bc2761d94a6); /* assertPost */ 

coverage_0x0dbb89fa(0x929c21a92e3142fdb0302ab788a4dcb9405a76eb483591cfeaab11de515f4fdd); /* line */ 
            coverage_0x0dbb89fa(0x64ff3fd095b5cd7aa650f091fe5e25f13355cc1c9bd0e05a61a08c075e18bd32); /* statement */ 
cp = Value.newCodePoint(
                uint8(opCode),
                context.startMachine.instructionStackHash,
                stackVals[stackCount - 1]
            );
        }
coverage_0x0dbb89fa(0xc878df4efb4a8ea3f34b65f0a3886b61a8adee83a5d7478a51292b9918fab877); /* line */ 
        coverage_0x0dbb89fa(0xe8325587c15ec363fed4a25f5273ba272b591c1f5294887d04118b32f5cfe61c); /* statement */ 
context.startMachine.instructionStackHash = cp.hash();

        // Add the stack and auxstack values to the start machine
coverage_0x0dbb89fa(0xacbfb726933fbb55f65e04f927520d1803ce7e9b05295faf4f1423883ab51aac); /* line */ 
        coverage_0x0dbb89fa(0xa4261226e2cd56936f45fec850468195c8579d21f6e1537cc7833436f7487012); /* statement */ 
uint256 i = 0;
coverage_0x0dbb89fa(0xde4c3535b844fca5f3cfd141aa70844febc75782705f4990c1c222602b0e5356); /* line */ 
        coverage_0x0dbb89fa(0xc23fe3459526e9503a784a7ff373c20c9e1abe9985d7fe7e2d75d780256df948); /* statement */ 
for (i = 0; i < stackCount - immediate; i++) {
coverage_0x0dbb89fa(0xe847c63107d9a6f42bf77ed1317427607384ed9d37b345111a71577a77a5f4f8); /* line */ 
            coverage_0x0dbb89fa(0x4b54b1a7e460d4cecff98f5fea12c33be727ced0e00984615d77952cccc65b53); /* statement */ 
context.startMachine.addDataStackValue(stackVals[i]);
        }
coverage_0x0dbb89fa(0x5f41dece5c1251c4f85b54db4edc3d76f6870b11429c22cf0fc433105ecd2ea8); /* line */ 
        coverage_0x0dbb89fa(0xd225cfc9e93cab7d0d997ee32f0f63460ef568444c31d9845783cf60859cd15e); /* statement */ 
for (i = 0; i < auxstackCount; i++) {
coverage_0x0dbb89fa(0x4b4a735e5aa3e23862f5a209a0a19c6abb8fc982aea1795231197723f67183aa); /* line */ 
            coverage_0x0dbb89fa(0xa1a588daca5813b70016d36d7375b886b7648324fca58ffd63d91d58f877abe8); /* statement */ 
context.startMachine.addAuxStackValue(auxstackVals[i]);
        }

coverage_0x0dbb89fa(0xe864eeb2e24b54eff3d33b681882ae0d50d5d27213717cde393bae61fc3d4a58); /* line */ 
        coverage_0x0dbb89fa(0xbfcce250cec227b03db4efe8c1af8f1d8f8f29411b6cd85947b00fc8dc9949ee); /* statement */ 
return context;
    }

    function executeOp(AssertionContext memory context) internal view {coverage_0x0dbb89fa(0x7f254297724620c83ff3153905718edf1fecb776324051e29f6f69c65ec1461a); /* function */ 

coverage_0x0dbb89fa(0x61df26372d09bb86df67dff2f8a4777720ab9435dc19b5c752e764e71e12329d); /* line */ 
        coverage_0x0dbb89fa(0x383955538573f8d544e586e0494aff620e886a7f904535a9fb78dfb0f6fd5295); /* statement */ 
(
            uint256 dataPopCount,
            uint256 auxPopCount,
            uint64 gasCost,
            function(AssertionContext memory) internal view impl
        ) = opInfo(context.opcode);

        // Update end machine gas remaining before running opcode
coverage_0x0dbb89fa(0xe1ba62d42620652f46e67f2fb213294ddaeeddc74cedc8d3e0eafc498a018bc0); /* line */ 
        coverage_0x0dbb89fa(0x6296916bf0c9817e2e03e04dd11c6fba3923e4948efe5026eb42ede45f11052a); /* statement */ 
if (deductGas(context, gasCost)) {coverage_0x0dbb89fa(0x012536335d069ab8b4b7b3e81f32a187b4abccc9659c9049d7ee7def0f96f6ec); /* branch */ 

coverage_0x0dbb89fa(0xccd9aa5a6a8d40c287ae2045053564dba8e96e8a463b6d6a0da13e337109f0c1); /* line */ 
            coverage_0x0dbb89fa(0xc1913986c9da0d41b5822fa9df7df008ae127024054f92f115433f257710204c); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xddf7254b70cfd503708b6cfeb225216430a8b21cde4e15ce48e42d9371b15ad5); /* branch */ 
}

coverage_0x0dbb89fa(0x4929eb4e5951b38bc2fa1f3df2999116d4a361d6584347773a93ce7cb06831f1); /* line */ 
        coverage_0x0dbb89fa(0x345548107729cada5b9b801611f67828530ed226d14992f8ed89fc441f3aaa06); /* statement */ 
if (context.stack.length < dataPopCount) {coverage_0x0dbb89fa(0x9609de8934878cd9ff3b538d45c84f085d6fe2b4fda9342c76b769473d6314b6); /* branch */ 

            // If we have insufficient values, reject the proof unless the stack has been fully exhausted
coverage_0x0dbb89fa(0xbe6b03fb1196f49c454b5406d791613cf157328055e7ae78c90276f42360a1c7); /* line */ 
            coverage_0x0dbb89fa(0xcf4dd7797016fb5eb6491199f0136ab18e68728e05d61a4e079c9f35c968b5a4); /* assertPre */ 
coverage_0x0dbb89fa(0xc81f1b1c0b2fb57015a27538fb4062c6469900590f22dcac7b85fa48b94bc8a8); /* statement */ 
require(
                context.afterMachine.dataStack.hash() == Value.newEmptyTuple().hash(),
                STACK_MISSING
            );coverage_0x0dbb89fa(0xf80627c0158f02a9768b3cea1c3d926ed402434794504f0d16bb6e1b030a23e9); /* assertPost */ 

            // If the stack is empty, the instruction underflowed so we have hit an error
coverage_0x0dbb89fa(0x8d0d2bd105fc86bb6c141c17351481f06e0ab807a450a98348ab311321320596); /* line */ 
            coverage_0x0dbb89fa(0xe58167149fbf8f73716628865ff3ff35323ba4c7517a8ccaa5541f3a83967367); /* statement */ 
handleError(context);
coverage_0x0dbb89fa(0x916f8434b8f5d4296733419cdeb752375969dd9321acfe1eb14036a9ac040d01); /* line */ 
            coverage_0x0dbb89fa(0x72fe31e7819fbb6cb96cc012c1fe76c9fbf30c29372b281244014fb47fefc747); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x82c91bd1ed34370f6c444672ab4bb9f5b25bc3ce7c26093ce29f9e3427148717); /* branch */ 
}

coverage_0x0dbb89fa(0x1f2d866ec8a5734733666d3b5be7f0b9ca7f410258b1ff633b5ec264050fb554); /* line */ 
        coverage_0x0dbb89fa(0x110927f906688e01b05adb93eccd1e8a3703010818392bb110c3d7a662487945); /* statement */ 
if (context.auxstack.length < auxPopCount) {coverage_0x0dbb89fa(0xb7022f9701d01760da80fbe5818160fd1cc85e0b38f24c097ce8c3ecba8afdec); /* branch */ 

            // If we have insufficient values, reject the proof unless the auxstack has been fully exhausted
coverage_0x0dbb89fa(0x2bf97e562fb55c0fe84882f960e3f5fad64368fa8c623d166adc94b64c04ef47); /* line */ 
            coverage_0x0dbb89fa(0x7fd4a506a4c0f0fb6a58317bf5c96c677780049c0cfbd2381f425190d0514af3); /* assertPre */ 
coverage_0x0dbb89fa(0x8a3fbac30e1d7f9d338d42ed1b9a342363c652d3ea41e10427cfc7bfe4738da9); /* statement */ 
require(
                context.afterMachine.auxStack.hash() == Value.newEmptyTuple().hash(),
                AUX_MISSING
            );coverage_0x0dbb89fa(0xaa8b8390707ddb60f16c9bcf47ab887f961f921717d3db7a80f49faa36064f40); /* assertPost */ 

            // If the auxstack is empty, the instruction underflowed so we have hit an error
coverage_0x0dbb89fa(0x5981ee70568a9c716f2e8a1ce59a4d9af3182e29382f4ba2148447bb8d48de14); /* line */ 
            coverage_0x0dbb89fa(0xf0c3a092f51883710e46416df22bdedf3af8fcb1d122f7df09a27f8d5c3a0d04); /* statement */ 
handleError(context);
coverage_0x0dbb89fa(0xe5119f0e614c178e96fc27f45e8828f35051d21722278e2a73ff796878a1cca9); /* line */ 
            coverage_0x0dbb89fa(0xc49635691b0d2a71e801a5c3b48aaf689dbb83079bbca770f395beeab235216d); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x8f85cc295853f5f8b2fe3344e55185bc5ce87e446e1a0bcca98391479aae36ca); /* branch */ 
}

        // Require the prover to submit the minimal number of stack items
coverage_0x0dbb89fa(0x4ab9e7c9bc291b23d2a41d3d3f9df872e14e9c5d704faf4b867641030755e961); /* line */ 
        coverage_0x0dbb89fa(0x3a50c9a6d7822783f72d11e57523477710d4885f8bd870544128fe71a2574784); /* assertPre */ 
coverage_0x0dbb89fa(0xfa9a830bd0507650abe67b9b8cb739bf69d89387d8c4d9df8965ff48930d5479); /* statement */ 
require(
            ((dataPopCount > 0 || !context.hadImmediate) && context.stack.length == dataPopCount) ||
                (context.hadImmediate && dataPopCount == 0 && context.stack.length == 1),
            STACK_MANY
        );coverage_0x0dbb89fa(0x7c5bb35f91f9f9562573e87eb23bec7bca1a4facdec92aa41a6dc616fc354328); /* assertPost */ 

coverage_0x0dbb89fa(0x6bb94f5ba31be53a9f97a54ac1efa66fa4b0490cb7de0817dc8bd4049b40513a); /* line */ 
        coverage_0x0dbb89fa(0xb66927c8c30a672caed3482b3c857f5d67599bc9ada2ea1f637da4cda11c3c01); /* assertPre */ 
coverage_0x0dbb89fa(0x63da5142cc2c7f70634c17fcdbd1ee97d97a2ea721c153abfd07064583f1abb8); /* statement */ 
require(context.auxstack.length == auxPopCount, AUX_MANY);coverage_0x0dbb89fa(0x2251f114a7e0f2c8959cc470b2bc117a8047f595c0fdc81d352476c0fab36622); /* assertPost */ 


coverage_0x0dbb89fa(0x59d2400d4923570eeb26b9de4aa65903e15da880c8707e17d76c044337b1210e); /* line */ 
        coverage_0x0dbb89fa(0xfd44a96611abf3a342d05b03a66d44f3b7fbec028e4ccedc34391c76269e72d9); /* statement */ 
impl(context);

        // Add the stack and auxstack values to the start machine
coverage_0x0dbb89fa(0x46728719c8eff3a804cb3897c681e0f5c711a5be81d182d2abb510c846489e60); /* line */ 
        coverage_0x0dbb89fa(0x2c3f8c0b1367a44423917738a17166510fe4d53a9090a26b207aef472828f937); /* statement */ 
uint256 i = 0;

coverage_0x0dbb89fa(0x8580413623cb4f127db4d550f1cd7b2c4a9d0a5f9e15c666e4e9dd0e4863f497); /* line */ 
        coverage_0x0dbb89fa(0x635b543304eddfc9e016496d6b54252e91984bc361406adc8a1a61a9e6d2e682); /* statement */ 
for (i = 0; i < context.stack.length; i++) {
coverage_0x0dbb89fa(0x73d2b1ff867bbaacfd0c025f5ceece5eba755bf2292d493ec02c33bbd9c3edd2); /* line */ 
            coverage_0x0dbb89fa(0x04db0f46225b6dcc55edab396bd1e81ada9192b0c2744183f883160143533699); /* statement */ 
context.afterMachine.addDataStackValue(context.stack.values[i]);
        }

coverage_0x0dbb89fa(0x629ebf5fe16d37f632d1cac99d2daed257878c434218043d90f83f30b42ce856); /* line */ 
        coverage_0x0dbb89fa(0xa17bdc3fe4901ee64b0280522568576051f61dc44c4f3f28631bd0f0a89ff9e3); /* statement */ 
for (i = 0; i < context.auxstack.length; i++) {
coverage_0x0dbb89fa(0xe3712c39df78d8f0c5957087b50a20ff00be654ca1467de8f68d07e363fa9154); /* line */ 
            coverage_0x0dbb89fa(0x4c093043129921c0ef9037d3de4a9531115975ea291a308e524379c3795b35b5); /* statement */ 
context.afterMachine.addAuxStackValue(context.auxstack.values[i]);
        }
    }

    /* solhint-disable no-inline-assembly */

    // Arithmetic

    function binaryMathOp(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xfffbc81e0b49f5889dfffae5aef19d66d6c723ac49f73ad75599a52c17dfb997); /* function */ 

coverage_0x0dbb89fa(0x562b13b9f873e6d3a9a728698e40c0112d32de95381a5677adcf21bb7d4694ae); /* line */ 
        coverage_0x0dbb89fa(0xcc9920d67521567053958ff1b08bc59cbee6b2e743bd3e5c4e77e836702bcb1d); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xcf61ee9d81cc053fa04fda864497ea321c82457e1507d6f2e7659a6d5c03dfcd); /* line */ 
        coverage_0x0dbb89fa(0xfee16e6fcabd5f4801f65946835b1e1a8c5f9b7469414d6aa6aac7d9638cca9e); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x1e469de6d01cf2f468bcf8b94b9244a91740e352ceaf42a1fcc8302cb8676ee2); /* line */ 
        coverage_0x0dbb89fa(0x02fd822273301498f4d15931805f543a1c0946f471420bdaeedcf994a7828c46); /* statement */ 
if (!val1.isInt() || !val2.isInt()) {coverage_0x0dbb89fa(0x84585d3b3e5b00904b9bb19dd621067089877ca085d1de951d328d20afa81510); /* branch */ 

coverage_0x0dbb89fa(0x2713f1e8c5b06a4e9cebdc56ad529ae9a4bbf946d67dfdc7e5a0eab2d09f3091); /* line */ 
            coverage_0x0dbb89fa(0x8611bbea6e14c10df845ec05799ed900979e35296ace90ebcf5e5e29bd4063ee); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x041062c8b905dfa9b3962d5943ea1f8b05a420fb818cbd0150a50f5450048ddf); /* line */ 
            coverage_0x0dbb89fa(0xc8bc6fdcb0eee9dfc6bd3b0c17251caf8d1dc0f742980d6112126cc057151f7e); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xc0e246df463c1db7948b539fc45309064826d0d998674d815bebf2318b63f345); /* branch */ 
}
coverage_0x0dbb89fa(0x057378b51c290522559d66551bcc880921ed7a2b6484ef6a31dfa883f89951e6); /* line */ 
        coverage_0x0dbb89fa(0x5b99e5a8132fe3d274c3e615d4381ab77752cb2a5053e69a6f85185f72705907); /* statement */ 
uint256 a = val1.intVal;
coverage_0x0dbb89fa(0x501010855978fecf201c95f79fa3d6895fe0011e61830432cfe28df7a7cce91d); /* line */ 
        coverage_0x0dbb89fa(0x96ed9d6673506a25a283ff2a3a379327a90193145259a318188ed99576c4f34d); /* statement */ 
uint256 b = val2.intVal;

coverage_0x0dbb89fa(0x6d09eb4ffc26d12e7787c11c36e713d222692d82cdb6d74dca07e97d0136020e); /* line */ 
        coverage_0x0dbb89fa(0x4be95d028a90244b8246fe27ca45944016f7890819e9939e7b4fd9791c9937f6); /* statement */ 
uint256 c;
coverage_0x0dbb89fa(0xc827e0313864f056b92be899b8f5acb1c2b41a62eb3504bc8301dcb0374635b7); /* line */ 
        coverage_0x0dbb89fa(0xb5c1d9d9b8eed4924914128f67b3642d0c6be15bfbc46ccbb71a32a803b2653f); /* statement */ 
if (context.opcode == OP_ADD) {coverage_0x0dbb89fa(0xce6c0e3298f2751e8dd3452ec07c00e7d9101f90c733db7f60b26ae009508995); /* branch */ 

coverage_0x0dbb89fa(0x1288ca189bb95957a3ffdafb3e6c59a4e8468188bbb422ab147067d9b03ae55d); /* line */ 
            assembly {
                c := add(a, b)
            }
        } else {coverage_0x0dbb89fa(0x1c25888ee2b5e450bb7796440e6a56c24d59b5c744722365fadab53d8d9cc53a); /* statement */ 
coverage_0x0dbb89fa(0x4d55a4c0bd345cd32436b0a49121d2409335bf13ef3186860120f9915106dcd6); /* branch */ 
if (context.opcode == OP_MUL) {coverage_0x0dbb89fa(0x4bde41dc6241d0692f6ac882de2240db91854754a27fa4189fb7700eeae57f20); /* branch */ 

coverage_0x0dbb89fa(0xf164ea22889eae6e70356054b88b4d9f6ccd7cd04d1fdcb06deec3ace1c3c5c3); /* line */ 
            assembly {
                c := mul(a, b)
            }
        } else {coverage_0x0dbb89fa(0x2220d179c284ad6afe6ae652abe308b2f214ad68f4d8473a66e8a9a1575fb8d9); /* statement */ 
coverage_0x0dbb89fa(0x93fcefcc476c4f5615fd7480eebce8627241786a73bd684310f68734019d8a61); /* branch */ 
if (context.opcode == OP_SUB) {coverage_0x0dbb89fa(0x52880c712e7c56ba61ed833d1a1d800be53789d03d762d694cdee2888ac7791b); /* branch */ 

coverage_0x0dbb89fa(0x59afeccf093c2cb1922448f77ca2bd9c375e7d964b57b1e5b51f8441056fbc8c); /* line */ 
            assembly {
                c := sub(a, b)
            }
        } else {coverage_0x0dbb89fa(0x4db4bf816116a9edbdc534a7c323765bac50984df8e78abf9f3be634d8e98a0d); /* statement */ 
coverage_0x0dbb89fa(0x6ad083594aa804769e7abfdf808a666dfbb78eb7f00a543ba4713ca41514217b); /* branch */ 
if (context.opcode == OP_EXP) {coverage_0x0dbb89fa(0x0f18900ed9808546c4cab9224b02bbfef1f031aa021fb0088ae9bad44b668286); /* branch */ 

coverage_0x0dbb89fa(0x4e0b2cafbccce3b1a40f1b95ed61a8626803ac4c4b4d072fc32f01f78fbd0500); /* line */ 
            assembly {
                c := exp(a, b)
            }
        } else {coverage_0x0dbb89fa(0x7b3ec2904035bde7eafc3ce32036c2f657f0842151d63ab75dde9669836c11f7); /* statement */ 
coverage_0x0dbb89fa(0x5bc48b278e28e77489874b55cd0bc5b1b7fcfdf8cace32a364d95f06b1a253aa); /* branch */ 
if (context.opcode == OP_SIGNEXTEND) {coverage_0x0dbb89fa(0xd1251e05f73a544f59de2b02bde9902e8db2192de01134cd3c5ce096a86a6956); /* branch */ 

coverage_0x0dbb89fa(0x1250791a9f93da0e130acde336a0fa142b2dfe456c8ebabf98240439f66b02ce); /* line */ 
            assembly {
                c := signextend(a, b)
            }
        } else {coverage_0x0dbb89fa(0xf71e2b8a376531446650ee9dff020f9a88fbff1b2797886bc99e9631a049e76a); /* statement */ 
coverage_0x0dbb89fa(0xd79d2efacd6995d05559c717c9eabcaa62711115753d1b4cd1b3cf737fad16ed); /* branch */ 
if (context.opcode == OP_LT) {coverage_0x0dbb89fa(0xa6bed60d59b0e8bae648ef4fd8aeb27619bf21907b8cf2399d8d9ee07e79b1e0); /* branch */ 

coverage_0x0dbb89fa(0x2d02fb9ccb90d65416776bc1acb02465fbde2ccd408e5f530e82ca8c707409e6); /* line */ 
            assembly {
                c := lt(a, b)
            }
        } else {coverage_0x0dbb89fa(0x99180d19322d41a9d3db789fb3d9edf7d4861616df510a23e7020f325b0d0c9c); /* statement */ 
coverage_0x0dbb89fa(0xd2aafc03289414fea7b9cfc86fc71bb39c40275bfd36554495e4f2d29c8dea33); /* branch */ 
if (context.opcode == OP_GT) {coverage_0x0dbb89fa(0x1cd6658886b9f484ebef5c2fa05d8e307751427ac9392cb9711b0f42fadb9a1b); /* branch */ 

coverage_0x0dbb89fa(0xb927ebe66f4f198472ae33b97d75e81fd5035aaad1460f98fc9d191a9d99f8cd); /* line */ 
            assembly {
                c := gt(a, b)
            }
        } else {coverage_0x0dbb89fa(0x85ced4a9505587b76687b7d86df95d64537e839277fc6d17c3203f99b892bf38); /* statement */ 
coverage_0x0dbb89fa(0x1327ca0ad909109028700b5f5d24f0a859b0a10b00ccbf70117cd970928fdd85); /* branch */ 
if (context.opcode == OP_SLT) {coverage_0x0dbb89fa(0x954429637ab847c31048434040307bfc16d80f1c456db9700678bc9374599c68); /* branch */ 

coverage_0x0dbb89fa(0xb024b6327fb0819b669b113dd100c963a2b260d5d6198676d9b467e2d73b3280); /* line */ 
            assembly {
                c := slt(a, b)
            }
        } else {coverage_0x0dbb89fa(0x664d1db36d3ed1e68f0bbc9968a965232d0adaf82a4faa0e8e87211ceb53f774); /* statement */ 
coverage_0x0dbb89fa(0x669e8745c7b514677b577664f41db4ae0a4968449fde7b1ce8a7dde54a3b060f); /* branch */ 
if (context.opcode == OP_SGT) {coverage_0x0dbb89fa(0x603eb29465d70d71e07afe57ceb3e8d1e71d05cb19505ea74d8e4aac01ab7aa7); /* branch */ 

coverage_0x0dbb89fa(0x99f72f603c97d5541ab9861f1c0c5529dcc452effdbfd50c16a271eea978abca); /* line */ 
            assembly {
                c := sgt(a, b)
            }
        } else {coverage_0x0dbb89fa(0xb9e101cee5594cf0476775e2acd5b4865d50bc99e3db2476a0d04de3ef9c91de); /* statement */ 
coverage_0x0dbb89fa(0xd28e92993af19e97fef443aed60de0ff3804b656db971a5679b30201b79ac3dd); /* branch */ 
if (context.opcode == OP_AND) {coverage_0x0dbb89fa(0x63177bdf843dc47b0513416857d67cdc2e4ff75400810936b5e2f77ef77296af); /* branch */ 

coverage_0x0dbb89fa(0x2655c320c829050ae400c60271bfe42f51f40749081d95fe9a0ee1a9f3995fb2); /* line */ 
            assembly {
                c := and(a, b)
            }
        } else {coverage_0x0dbb89fa(0x4c0df0c5eeb7279f64e789aebeadd6ba24edf3304dc22b63550c18d12294ed84); /* statement */ 
coverage_0x0dbb89fa(0x9316ffa04ef0132eb3ad3ab84471c41edc45bc49574d9562f23d4f9b4c7a9905); /* branch */ 
if (context.opcode == OP_OR) {coverage_0x0dbb89fa(0x429d064e95c5140c1c817465e1e6efd9bdb2ecd4f164d9856ae2eb582f2ab654); /* branch */ 

coverage_0x0dbb89fa(0xf29c71421538c662490195a840ceb3abfde6bcc934d6b821bcfbe22473847e9e); /* line */ 
            assembly {
                c := or(a, b)
            }
        } else {coverage_0x0dbb89fa(0xc8dbeefef7ceeeb0f8edbd42e5eaf68a32a52a0e862dacb7a82935b2f29533a0); /* statement */ 
coverage_0x0dbb89fa(0x687789a58c8afc1cb0afe6169d1d6b1f6b09b5364ac0e756101db2ed2e1c1171); /* branch */ 
if (context.opcode == OP_XOR) {coverage_0x0dbb89fa(0xa490a1f4a545b9fd3aa285b8399f22abce3fa123597537844d1420e5a20e95c2); /* branch */ 

coverage_0x0dbb89fa(0xc502a8ee581fc48ef8021d9cb192268312df7fc3d3a19dee76c4793810af2fac); /* line */ 
            assembly {
                c := xor(a, b)
            }
        } else {coverage_0x0dbb89fa(0xc52f7624c646db7773eedb001e544365691bee3b9ff77aff86eef1b3fa72c939); /* statement */ 
coverage_0x0dbb89fa(0x14f19f2b14b627f259e23df7aab5fdfb6c933d754de3ea795b8a1aca68f70fde); /* branch */ 
if (context.opcode == OP_BYTE) {coverage_0x0dbb89fa(0xfc2acae67513fc12cbc5606eceed9d62aa3b218d6d01a852cd4926c81ed151da); /* branch */ 

coverage_0x0dbb89fa(0x738a6cfd7c3ffc789a495fa996300327d66b89f83b593a8710ef20d5c1b08ebc); /* line */ 
            assembly {
                c := byte(a, b)
            }
        } else {coverage_0x0dbb89fa(0x2b130b479e4feda247366432757b73f22cd784b6c812b5b851914521a322cac7); /* statement */ 
coverage_0x0dbb89fa(0x957bedd305bcbc1d13f670a2f66b214e4107cc2aa5b278fb71fe98e77b005177); /* branch */ 
if (context.opcode == OP_SHL) {coverage_0x0dbb89fa(0xaada3a2ec15fcea66478cd669fc1f9dd4f45cf8891daaa1b551acff6b6d9c437); /* branch */ 

coverage_0x0dbb89fa(0x00ff8c5a58735c581c5ef7bfea83400cb104865a2689616cef2f9154e378d818); /* line */ 
            assembly {
                c := shl(a, b)
            }
        } else {coverage_0x0dbb89fa(0xcb888498b3d47f2a768b0d5e28be7b65991b127cf0d960729aeb672cb146dce9); /* statement */ 
coverage_0x0dbb89fa(0xae44105af61ed08173ff4fa2548c5347fffb0968dd3b84b4c6f1704b7f9dc211); /* branch */ 
if (context.opcode == OP_SHR) {coverage_0x0dbb89fa(0xfd015b564aca48d29087d39893ca8c247e28fd40fdf2242958a969642f2349ed); /* branch */ 

coverage_0x0dbb89fa(0x210cacbb70a460a96b121ade459b7a463bef6b59a54dccff459bd0f4b7f69a54); /* line */ 
            assembly {
                c := shr(a, b)
            }
        } else {coverage_0x0dbb89fa(0x1ff014ee6f3ec03286b602b543252d851265d32259682bb6f1dcac8c0848aa8c); /* statement */ 
coverage_0x0dbb89fa(0x382fdc0d6b8dd44d153cd06c4a393ae183e07c9ed1c0c2523f012884d34d1d64); /* branch */ 
if (context.opcode == OP_SAR) {coverage_0x0dbb89fa(0x82de5c0020297b306733897dc912732fa877a78291c58d68b975a3663fcd2563); /* branch */ 

coverage_0x0dbb89fa(0xe5931ffcc46b6c62afad5e01ee818dcd78c1214f7ebed55d4a1a392f916e30fe); /* line */ 
            assembly {
                c := sar(a, b)
            }
        } else {coverage_0x0dbb89fa(0x6c4a6c3bb068e92c3cfe67d1233c0c4f39b89e34505eee369cb5f8449e0b4e3b); /* statement */ 
coverage_0x0dbb89fa(0xf6f694266f5af31d5ad94730c422e219525fa404c2e894064a4f2f14a3d676f7); /* branch */ 
if (context.opcode == OP_ETHHASH2) {coverage_0x0dbb89fa(0x3516f769ddcce42fc3d3aa63bfc01301dd99c66448bfe743a632d330be41dfd1); /* branch */ 

coverage_0x0dbb89fa(0x60286d65f262e7e7162354b889d309ee8bc370361bb9fceb3de2b4ae1b640574); /* line */ 
            coverage_0x0dbb89fa(0x0b6ace95b9bb983c52a6026945667b02010963b3a5e7aae6142eddbaad1c3a03); /* statement */ 
c = uint256(keccak256(abi.encodePacked(a, b)));
        } else {coverage_0x0dbb89fa(0x1559e0e20405f248b754db0fac734a991c10b045f10b7c8357508380c98587c4); /* branch */ 

coverage_0x0dbb89fa(0xfbadb325502bb04453f2f1deff6e045c106efd5ba1eda2ea4fd8e53c1db6b8d4); /* line */ 
            coverage_0x0dbb89fa(0x412edda92c492eda8484de718d8255bfbaa75b312f77ff994681662a53f0147e); /* assertPre */ 
coverage_0x0dbb89fa(0xed081fb90d34a14301bebfb314e20e6ddc09f5f481a2efa6331e05da45fa3792); /* statement */ 
assert(false);coverage_0x0dbb89fa(0x10c5bfafbdcc0fb731809d0b099e715d45210d24bf4c2ab052cf1fe14a0f5aa2); /* assertPost */ 

        }}}}}}}}}}}}}}}}}

coverage_0x0dbb89fa(0x6c7c66c47372016305e1a183fb62f9cda12e0222a31b8c3804dd7c3a692de73c); /* line */ 
        coverage_0x0dbb89fa(0x8103434a190de97978b2cb671cbece80cd2dc2e297e2a47a950d78caf6a64830); /* statement */ 
pushVal(context.stack, Value.newInt(c));
    }

    function binaryMathOpZero(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xb93c5d33ad3aad0b891e5dd8bb7774b24e7f922ceefd9ecdadda46ae4dae4a3d); /* function */ 

coverage_0x0dbb89fa(0x673a68da37b643c6c4734d9966ae103e36e45212a4f99c32ca3d4dae012ce025); /* line */ 
        coverage_0x0dbb89fa(0x952ed3a02c8e26b3626f4a4d5461550145e7cfab92f990a49e8da8d5b8a80640); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x1aad3dbf85b85f4e27164f5a60b093b6e3f22fc7bc978d68a8de414a9b1b39be); /* line */ 
        coverage_0x0dbb89fa(0x70b966670a29fea6ae7ba4fba8254e27547544749d90a8506d63ea4307873173); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0xe83e0eab74c544377e5e3c9c8ae9fcb15a6e2527d1695122cb8a10ac0662d4a6); /* line */ 
        coverage_0x0dbb89fa(0xa7b1cb8bcc0d15fca5ff2e155abfe0eb5a5a11883115f904890469ea58fe00fd); /* statement */ 
if (!val1.isInt() || !val2.isInt() || val2.intVal == 0) {coverage_0x0dbb89fa(0xa7c18f6d399b7a3eeaf425b158f703a2ddb516006a36be35fc0da5c838429d51); /* branch */ 

coverage_0x0dbb89fa(0x6db006a09afd2386ee2a6eb68b77bb715bf9555e518b0f88d4b58b31ca95078b); /* line */ 
            coverage_0x0dbb89fa(0x299780434c7c6a50419f761b51f2182f4a9357042d450c874b891b5b3667b7c1); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xbf29d047e1d4a7579fb4e995184f92bffb2b4d89d04bfd1fb8e323ee2b56b3c1); /* line */ 
            coverage_0x0dbb89fa(0x3f5302ee010ce28f4696f0a41e8ba2e03bbafe3ae2059c6fc08c2edb2119cd1e); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xa4b0e1a26c49ecea1fb840dee76a2d471cbe6c1155dee7fdfa7ba0f9df5987de); /* branch */ 
}
coverage_0x0dbb89fa(0x64e996a3ff16d86c59863181d605bcecca6f1d0879fcfe6bb272b82e58a4c57b); /* line */ 
        coverage_0x0dbb89fa(0xea7b5fe6daf4ca1f1b70952e359d6c3de52680fb51687637cc6d3f48fb5534a5); /* statement */ 
uint256 a = val1.intVal;
coverage_0x0dbb89fa(0x056b2476daa8dbeaf3b463251342a05faed182d234b7d7c91dcc2cf3542309d8); /* line */ 
        coverage_0x0dbb89fa(0xf53e792b7852797af1941a84e1f4b0af95d077aeb0da284e33b9b405dec9c9c4); /* statement */ 
uint256 b = val2.intVal;

coverage_0x0dbb89fa(0xf28b4e4153ffacf9f744e87a41b84557cce9c5af7ca2910cbc9fd71188b04bfa); /* line */ 
        coverage_0x0dbb89fa(0x62cee15afa18be9776ff113a002e1e34fab80c8c0c8d43fca139e480a08a6355); /* statement */ 
uint256 c;
coverage_0x0dbb89fa(0x169a2e8dcd196db7992ddd937cda229b3018ce90d8d04408929d1a468efb631d); /* line */ 
        coverage_0x0dbb89fa(0xe03b47fa51142fb614aae167813db1437a11375e813690ea6063adc7c5015e98); /* statement */ 
if (context.opcode == OP_DIV) {coverage_0x0dbb89fa(0xfa9fec4172bf55e9e07d44c0ad2bec2693a397e1ec3decf647d78c7638dcf1a9); /* branch */ 

coverage_0x0dbb89fa(0x424054095a5620d75b203e6236ef02508278732c9bc34cc093fa4fa50971b976); /* line */ 
            assembly {
                c := div(a, b)
            }
        } else {coverage_0x0dbb89fa(0xa09a829b0af023a7f387c92df4091ff44325edb4638fb75d8bf3da9dd8917fd0); /* statement */ 
coverage_0x0dbb89fa(0x7f6b59d356cc77ed3ea3f399e39fd8aeee8a05c26c81db5fdff9866c61efac73); /* branch */ 
if (context.opcode == OP_SDIV) {coverage_0x0dbb89fa(0x0919f76f7c2e5b22605e9307cd2169c34708c48981358685c658b3d03057b325); /* branch */ 

coverage_0x0dbb89fa(0x1a81abb1be8f50d355269be4ee69aefc000a2cc6b57a32bb9d3eba0cd36cc639); /* line */ 
            assembly {
                c := sdiv(a, b)
            }
        } else {coverage_0x0dbb89fa(0x649c6eea19f577c7a0960a37ed6756aa25b39c2f37ab307c2070e6a5f6d74db8); /* statement */ 
coverage_0x0dbb89fa(0x6aafe0e2682f9c432264d12b22c463c7bdf1d6ec54305eeb4ff8f5e92d5d954d); /* branch */ 
if (context.opcode == OP_MOD) {coverage_0x0dbb89fa(0xeaac924633921b5a93cc9c9b835803824d409a0971274eb19609bd83d155ff9a); /* branch */ 

coverage_0x0dbb89fa(0xfdc92fc55d2fdac87935f3dd6132b5e6d9987483d0ced0f5db4485e2fc898eba); /* line */ 
            assembly {
                c := mod(a, b)
            }
        } else {coverage_0x0dbb89fa(0x2672a0c99b90e26e62b3f9851258c7e1b74c9ddc132bcb3a8937da2cb1c4fdec); /* statement */ 
coverage_0x0dbb89fa(0x022cbb505955fd81dd5a6c9d5ffddb318157b7031d3399f13d74e748ab41f96c); /* branch */ 
if (context.opcode == OP_SMOD) {coverage_0x0dbb89fa(0xbc61e3b4a3e997e22224086b96570a4f30bbeb538328137521078151401ad9e1); /* branch */ 

coverage_0x0dbb89fa(0x265c6c3846e3b275507bcaeda37d44092113bcd53b36a81c9fb887efaeb3dbb5); /* line */ 
            assembly {
                c := smod(a, b)
            }
        } else {coverage_0x0dbb89fa(0x9e963cfc39d2bbefa016e7789fdeec2118b98b66c1008cf164f2a451c0e4c992); /* branch */ 

coverage_0x0dbb89fa(0x34686f4c7b4f8a2f8f79278eb352906e8ac9344f7e38918a34fd5ab872faaa85); /* line */ 
            coverage_0x0dbb89fa(0x5d57662ef83363a24d020fc71b36c765b18a16cea032ab3cedfa9666d8f7cc52); /* assertPre */ 
coverage_0x0dbb89fa(0xc1ddda58a9b1b7a2489fade981d4631c131817378e7f9102c4f283c34511c17e); /* statement */ 
assert(false);coverage_0x0dbb89fa(0x8503cbc21a0d53fa9c86103f738a85d5ace1f9043b128fd9f50addea92de1215); /* assertPost */ 

        }}}}

coverage_0x0dbb89fa(0xe59eb6445dd94902ca62c336bb7e3e621105460a0e7434bddb9f50c346e90172); /* line */ 
        coverage_0x0dbb89fa(0x4a34b9a31312574a45552641e044d50bf1eb5cdfda4067326823c682064465eb); /* statement */ 
pushVal(context.stack, Value.newInt(c));
    }

    function executeMathModInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xf0c6253b56e82891dc10473bde7c82fae885c85579405b670825f2585984154d); /* function */ 

coverage_0x0dbb89fa(0x8650dfb4c26cd1cd465a00f6fae4d083ea88192b21f0f928cc9a701a89907c72); /* line */ 
        coverage_0x0dbb89fa(0x280aee4dba506ba9e711e36635a12888e33e983993823ac243265a9d038949c9); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xc4654579337a00396e21d02ee8a3c651bc253fef6440da73ad79b61c9df8c250); /* line */ 
        coverage_0x0dbb89fa(0x80a392d575ecd3ef94edb94fafebdc50fc1356c66cc3d7631952bfdd8d5e06a2); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x08f6f724084bd10c62797de1c3e43a7ccee27f3b1629e8201e0f695059846610); /* line */ 
        coverage_0x0dbb89fa(0x03f11e83a05926468443d8242394151873e38da417dc0eb21eb84d4e668e090d); /* statement */ 
Value.Data memory val3 = popVal(context.stack);
coverage_0x0dbb89fa(0xa8dee0e7fefc93ba465762f710976208e422a97819e6648416b47f91388d6447); /* line */ 
        coverage_0x0dbb89fa(0x0845b7bfac6ccb7058a93688ffa8e95303bd7f76f4e585b61c57cdcd0188f7de); /* statement */ 
if (!val1.isInt() || !val2.isInt() || !val3.isInt() || val3.intVal == 0) {coverage_0x0dbb89fa(0xea83866a3f9b07b55314bbc04ce9621ab9f5a2f642894aad88442825e5ae31f2); /* branch */ 

coverage_0x0dbb89fa(0x0597919d23a5a6c98821816605478327b8c3b3c0bc8624132703fa8ca1803423); /* line */ 
            coverage_0x0dbb89fa(0xbed357702737d719ce2e80aa868407a9b1936c83522af5d2af62b5c0818ef20f); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x294a06cb91115a0e14cd8e3a0921fab4d7b6097a7e7ad6498e890d846c6259e0); /* line */ 
            coverage_0x0dbb89fa(0xceb1ce0e1ce71f1838dc094c3c1c309f9b148985b2c51116b8ab5a97d59e23ef); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xd660ad726b585386a0286e945a38419622a0ff50cc9c113f4aeb10612bee7469); /* branch */ 
}
coverage_0x0dbb89fa(0xe46f3f086a6269eafd29f84bfece14741029a49ec94e5867e0ddcc0af298adb9); /* line */ 
        coverage_0x0dbb89fa(0xb5e67cf3171f4a8671fda64fca2d703d3f82befb61fef92f35ac58e4030266cf); /* statement */ 
uint256 a = val1.intVal;
coverage_0x0dbb89fa(0xed94fd917d7f0adc2757f6b35a6968e47270a2b1e3d0cad533493a38d2ac990d); /* line */ 
        coverage_0x0dbb89fa(0xd361d7651e70ab5d3e8c3b727dc5ad7c1eefb2984d4706a75a96c14dfd475c00); /* statement */ 
uint256 b = val2.intVal;
coverage_0x0dbb89fa(0x174d4eb2900fade6cf33ae2d0b6157f30321fb51c15e8d35d0bfbf2e53f38b2d); /* line */ 
        coverage_0x0dbb89fa(0x0cc85aae8bda055679133c0b487295a6b7332cc01d7da818e911a452391db113); /* statement */ 
uint256 m = val3.intVal;

coverage_0x0dbb89fa(0xcd381629a322f7b89cc2c2ba8f3beaf2721de1b16c0a11a7e3e5527cd85d04ae); /* line */ 
        coverage_0x0dbb89fa(0x7aebbfd02c209877e89fd3b5060ad8e8e1d5203cdb8064d7f570caf53cbf6d7d); /* statement */ 
uint256 c;

coverage_0x0dbb89fa(0xc75f0cfb4c77a93d25da204e41ebd6e886f0d72d46f52dd202b7849214d2e699); /* line */ 
        coverage_0x0dbb89fa(0xcedbe06ad54b96869206b0f892e3a8640eb317d56454d413b174f112d97bc003); /* statement */ 
if (context.opcode == OP_ADDMOD) {coverage_0x0dbb89fa(0xe3c75dbbb57711ae92008b30cee11f5c5bcbec96ec4113612d905548fd32bb4a); /* branch */ 

coverage_0x0dbb89fa(0x72b3b5a40178bb97875f414a05b32781f6de6e8793f492a1a700c86836f61b7c); /* line */ 
            assembly {
                c := addmod(a, b, m)
            }
        } else {coverage_0x0dbb89fa(0xa6fc305a6354526930a310710fa97c2b2d44d04f20bea2cfcd9b033793e641f0); /* statement */ 
coverage_0x0dbb89fa(0x0aac48e1c4cdc73f842175e7c3838b70294d289db2cbdac912a63616108a9630); /* branch */ 
if (context.opcode == OP_MULMOD) {coverage_0x0dbb89fa(0x3b5d1a0b5da65cd156971ff25515bfec81491387fe60ccc6157bdfaf1153e3bc); /* branch */ 

coverage_0x0dbb89fa(0x6a016e6e333ded524934e15b0c17016f9f92a739a745c0b5831c88a40425f325); /* line */ 
            assembly {
                c := mulmod(a, b, m)
            }
        } else {coverage_0x0dbb89fa(0x7517d1269d86e63aa5042e2de181b9bc7f27b3ef92ecca406c31e535bdbafaf0); /* branch */ 

coverage_0x0dbb89fa(0x02283861172ba5afebf1f29276d2f26532de499f9a76e263eabb961fbde927d6); /* line */ 
            coverage_0x0dbb89fa(0xdfa94b9be81169f0056da582bc88d66b9dad5d7eeb173114dc8d1b1c36f1b128); /* assertPre */ 
coverage_0x0dbb89fa(0xf5ea88cd1f94e4e90185e82248348f71c179b6a87cbe91b5bac34a87ec2c99d8); /* statement */ 
assert(false);coverage_0x0dbb89fa(0xcc6aa6d5b1ed16aa9a1dbba844e9c5d6143396b480bd160a867ffc2fd8104453); /* assertPost */ 

        }}

coverage_0x0dbb89fa(0x93d799efa5bf510ea257f2081e6ac63b43c894c5e233555ad050300b79be87a2); /* line */ 
        coverage_0x0dbb89fa(0xe5be931b22f115d27762afa4d0d1b47c1ba4e18a6d5b0d6bb4ddfb8a0618235d); /* statement */ 
pushVal(context.stack, Value.newInt(c));
    }

    function executeEqInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xb2f450add9df7be6ed5225635c5e18c24bb1ea90bd0a3faa93d3acc415eb6c8d); /* function */ 

coverage_0x0dbb89fa(0x3aa955ba8a32f7a51feae290d04a97e46d38e57ede971e7d563b8cf0e2c404c4); /* line */ 
        coverage_0x0dbb89fa(0x5eac054661c15b24075b276794c740c3ec75089c974d3d83d90ffaecef9d9428); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xaf194f2df3152120043160d3a8f2896059fbc4737cfb0f6aa8b5e90793aff5a1); /* line */ 
        coverage_0x0dbb89fa(0x0a5b2f39d65e4d3ef52315aafa6638d5f8f206aee447d1d193681e8ad049d67d); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0xfe9faa94108bc15c1a20b5af8929b2ffa0fb53a7cf9911a3811014ab2530a924); /* line */ 
        coverage_0x0dbb89fa(0xcccea03548363692c2721675fa9516a9a8cb1742c0a3b13f1fea5c032a8a0ace); /* statement */ 
pushVal(context.stack, Value.newBoolean(val1.hash() == val2.hash()));
    }

    function executeIszeroInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x24963e208c4565c49a5a1781164fe7d0b249fe22cbfb21a3a21fadc1a1395808); /* function */ 

coverage_0x0dbb89fa(0xb0425e2e355c0c5fea527809d49bb4747531aa6e423a6620d8e0310eb03fb4b5); /* line */ 
        coverage_0x0dbb89fa(0x5df6e9c39a77c76adf2a09717bf29449e2a53a0a9aeb70da3bd2475fcb8fdbfa); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xab3af49d216e38daa077c085fb30bbcfb67e8b2d07bcd54cdd2885aad4805ef1); /* line */ 
        coverage_0x0dbb89fa(0x09fd70b9d6e401f7b00a4f12d3efe0ec11f7675a11a9aab680cf16db9e569137); /* statement */ 
if (!val1.isInt()) {coverage_0x0dbb89fa(0x146069262882ebf25f1fa8c31ca7f3d8b44a46dcf4c7c37f2e68573a13a30176); /* branch */ 

coverage_0x0dbb89fa(0x5a8a385225c658f7e19d82e94218c76dc24c486759bbec3534372536b1521796); /* line */ 
            coverage_0x0dbb89fa(0x7530a0022e9ccc13e127510f5552d5dbfbeac177f00dc51bad95b83d65f08ef8); /* statement */ 
pushVal(context.stack, Value.newInt(0));
        } else {coverage_0x0dbb89fa(0x35a18c8c1b244866bbb2d9e2618c97021955cc08ed6e5b4b5a6b4738e6f39141); /* branch */ 

coverage_0x0dbb89fa(0x13303c0eab80588df50fa9c84c6f785bdc837120a53600cde6b226341cb405b1); /* line */ 
            coverage_0x0dbb89fa(0x995c730c4191d8fb43090066f65e57c711b45d49f2457548237171448c16bf0b); /* statement */ 
uint256 a = val1.intVal;
coverage_0x0dbb89fa(0xb71f3c88c0b58b5e9101ac6b310d6ee5654e9e6306cd59e6a366c10247eb7468); /* line */ 
            coverage_0x0dbb89fa(0x3220d19bb748922e9d48c6e87295b75f3e327d641f86c671e9a75904e6f929e5); /* statement */ 
uint256 c;
coverage_0x0dbb89fa(0xfbd62a9e1decd9fa60e2dc234503463304577a0bfa19ffbcd81b7677eceaacc1); /* line */ 
            assembly {
                c := iszero(a)
            }
coverage_0x0dbb89fa(0x0c8a8428b31863e69ed5f63b6648c117207db09aaab8b512b9f59d57f96a254e); /* line */ 
            coverage_0x0dbb89fa(0xa4a28281c5540f69e1e08a63cf164c7366b0ded8e862b6c99cab1a44e7614ebd); /* statement */ 
pushVal(context.stack, Value.newInt(c));
        }
    }

    function executeNotInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x5e2648f754b03b59ff9f2802df984addc49112b07effc62bc3e4b56ff5490e3e); /* function */ 

coverage_0x0dbb89fa(0xc040ba5b46db6a89f9aa2b8b45a37dbda559f908522597ce9efa4835c42d1bc3); /* line */ 
        coverage_0x0dbb89fa(0x70f77504b246095f4334d11210ce9644be8f9d370780feb6837a093922ea11b6); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x67c2ed086786305cd5cfcfd6281c79c2ff896b2ca474050fe5364cece7cb406f); /* line */ 
        coverage_0x0dbb89fa(0xb4cbebec93343663347eb1160a85c2569e96e5694f53c61cf056d9b488202e15); /* statement */ 
if (!val1.isInt()) {coverage_0x0dbb89fa(0xe2d643f55414894bd7151b65b27af005db6cdefcd70d04d90506e49b528ac975); /* branch */ 

coverage_0x0dbb89fa(0x2988386ff07717bb8addf0c75629983ec79ce44ddd99698e6333bb154e7b7e01); /* line */ 
            coverage_0x0dbb89fa(0x24669c01a1d9adeff128212e2d1f03f8fa8c51032747384304579d6391d05d85); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x8547e72f97aef3b13f45f63e4ede36bf4bffb925116ab9054e412b362aec211d); /* line */ 
            coverage_0x0dbb89fa(0x3e0ba59ac44aa061d4add9795b8a96ab27bb45f82a06afa60ed2034d2f84f065); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x06d865dd27bb27fb5061a09745058ae7eaf575a05381eb2425124449ae7b6ec2); /* branch */ 
}
coverage_0x0dbb89fa(0xb3da9f6e59e63b848084ac91b3e65aef4bacc778f268f4272af9ce6725e504b7); /* line */ 
        coverage_0x0dbb89fa(0x6877625fd41914c67369a804aef0688cfa89688f20b3c92231f6fd9f523acc30); /* statement */ 
uint256 a = val1.intVal;
coverage_0x0dbb89fa(0x7dced97588c1676cf8e6de474c0d52a775e3f448451e4971e100dd4d6c862a39); /* line */ 
        coverage_0x0dbb89fa(0xeca66f7f8024e24fd9c7f506fcedeb014f054bfc963d766cb5453be80d70ebb6); /* statement */ 
uint256 c;
coverage_0x0dbb89fa(0x35591992be491d4b2faf8f2b029dbeb6969c1ce6fef5ef3ae32c39bf0159cd89); /* line */ 
        assembly {
            c := not(a)
        }
coverage_0x0dbb89fa(0x56a105b683d88b399a2db4938d3aefce85122f19f31781c1f1a4ce24564fac05); /* line */ 
        coverage_0x0dbb89fa(0x50123cbabe022d80304042baab36a0a75201f2ec30a0aa6c5acd4596b7485250); /* statement */ 
pushVal(context.stack, Value.newInt(c));
    }

    /* solhint-enable no-inline-assembly */

    // Hash

    function executeHashInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xd6fd5e7be147164112e70d0d260bb681f76caf53eb957f031dfb4e8047c6c201); /* function */ 

coverage_0x0dbb89fa(0x958e6e5bae6e6e99272dbe18767f16f1ccdb9453f58538cdd86d805a93b6bd12); /* line */ 
        coverage_0x0dbb89fa(0x6ccdfc71839a20a22dab427273baa3a2f002190098ee9b84b9012e68025de6fe); /* statement */ 
Value.Data memory val = popVal(context.stack);
coverage_0x0dbb89fa(0xa252a67302e8cfa03ed5284885c57e81ee0c2c1013190f75f956b8c3b8818217); /* line */ 
        coverage_0x0dbb89fa(0x37eb96929b5e9053cd5f2eb0286694996ec5e6c5ca6cabe62dd520a98592cbe2); /* statement */ 
pushVal(context.stack, Value.newInt(uint256(val.hash())));
    }

    function executeTypeInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xd0db037ea3b1c20fc09e73bf23e890ec0d5e1e0b3f36fea7a28a3a89a447f10e); /* function */ 

coverage_0x0dbb89fa(0xc078a6e3b8067fa76cb25026c0e9056ec79eb069ce450e5769bd42c534d0c0de); /* line */ 
        coverage_0x0dbb89fa(0x61c3700a4f98f5d1c5596cb362a0f51da59130f0e0e0aa2ff60a82ba34759d1f); /* statement */ 
Value.Data memory val = popVal(context.stack);
coverage_0x0dbb89fa(0x234b5319a550564717bdfe71e2ea8c92445b36c35fc0a977b122103682be6a5c); /* line */ 
        coverage_0x0dbb89fa(0x8c656981ea72f579199911eaed854ff19190c23b325e549e20b41780cc879ad5); /* statement */ 
pushVal(context.stack, val.typeCodeVal());
    }

    function executeKeccakFInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x2358e9cc1b6072a17bd2b8ab5bc879095ee64902bde1b0040a87eb98eda44726); /* function */ 

coverage_0x0dbb89fa(0x9fc7ef25d19eceeaaf220a5a71a5e4c823a3cedcba8545958fb1b0ae99f6f1f9); /* line */ 
        coverage_0x0dbb89fa(0x085e689b51dc3ef39374ffcdb25127aa79a57928266414cfecf7679dcd90ca37); /* statement */ 
Value.Data memory val = popVal(context.stack);
coverage_0x0dbb89fa(0xe3c2adc08ae341a3340fc1c1adbb1fbbb56166459c5094c778ef3488ce401c2e); /* line */ 
        coverage_0x0dbb89fa(0xcaa08ccd20f6fcf174535d088e6d12e2d6814c44f509eab3b89736291743095e); /* statement */ 
if (!val.isTuple() || val.tupleVal.length != 7) {coverage_0x0dbb89fa(0x188a71db2b40a756c8ffe440b5e591e8aa80e0652b4ae9703ea1f5cc4739e471); /* branch */ 

coverage_0x0dbb89fa(0x61c49f0ddf3a3dd49a404605c9314c7e48725b31210b20ebd50bc78e33a55e07); /* line */ 
            coverage_0x0dbb89fa(0x74a6e4c81036af36c6cf13e5788a06a7675c75458f67955ce21256a25543492e); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x82a5538d338d5983d66fec66c5b62e6de67ad851bb90485bf29438d23c7f91ac); /* line */ 
            coverage_0x0dbb89fa(0x470bc4f189741383e75c50166a526d432a9eb9f3182cecf6e4dfe9fa55e15453); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x776c882df8d6a44a2cf4f033cdd09f13d3717537c3c6cd6387e7a310c9087318); /* branch */ 
}

coverage_0x0dbb89fa(0xc59c3bb258be1204bc75329c907c105b94c707550dfd929963fc8ebe761c0619); /* line */ 
        coverage_0x0dbb89fa(0x7b23a86f4acd07b3d43fd09c71af8283521f4b3320fb2bf8b7aff98d285a6ad9); /* statement */ 
Value.Data[] memory values = val.tupleVal;
coverage_0x0dbb89fa(0x7422d39ec0b2f3b69306defec5200760637253f4d46e2df0aa45247ab3d88a2a); /* line */ 
        coverage_0x0dbb89fa(0x3e7295ced593ae73aa295b83c0919783516fe4d6b196035df2bcebff6ee4ac5d); /* statement */ 
for (uint256 i = 0; i < 7; i++) {
coverage_0x0dbb89fa(0x07d23432040c8aabf510b7412d96c49cd3fe87231d7e8ff4137eb4b50ef1e50d); /* line */ 
            coverage_0x0dbb89fa(0xfc0cda4f78bd03cb3b5672f2c76ca1b3c09d52cdad9d6c95ce1af53f7d9f0c5d); /* statement */ 
if (!values[i].isInt()) {coverage_0x0dbb89fa(0x1246115cd45f8ec6c98a99676881a19b925c9680aa665362afa72f3a76efaafc); /* branch */ 

coverage_0x0dbb89fa(0x1e1aa32aee19dd7e8cdd6310a6b1940a7e68a01f1703bfe9b4aa935f20c5d495); /* line */ 
                coverage_0x0dbb89fa(0xdf12a056c2d77d586ac14867f5edd138ccb787ac57312acb4d313147dc788b00); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x5762b8d255c685cc4d40adbc3cb3b4450dacf7b532025f463c276d34dd6dbb2f); /* line */ 
                coverage_0x0dbb89fa(0x7122ab9bdff52759dad5557488ca5dfa8b206bf8b57d58009c5e3ab6d6c80d86); /* statement */ 
return;
            }else { coverage_0x0dbb89fa(0x3656ab0baacb998480f3c72ef454015b6d13c53d74b35e77d84359868a267155); /* branch */ 
}
        }
coverage_0x0dbb89fa(0x8b3a362cf7c3ec1ea5bdca62b1fc07e68222ab16f23b1c9c894d31eab9f89a23); /* line */ 
        coverage_0x0dbb89fa(0x53058a070de5a999cfa8f9860b59d64751717f5bbf596b4beb04305a82fd6210); /* statement */ 
uint256[25] memory data;
coverage_0x0dbb89fa(0x5a2f8ec1dcdb2a8cfab742cf2dcefa77aba989f1019528d875dba53fd2a0c892); /* line */ 
        coverage_0x0dbb89fa(0xed716577fb659587668b11516c17dd35618800fba494a5c06eae65a1c5b3b352); /* statement */ 
for (uint256 i = 0; i < 25; i++) {
coverage_0x0dbb89fa(0x373c5d2bc359130dcbe6bf1eec45fd2a876b0eaa53b6ce9cb284e0d76d0261d4); /* line */ 
            coverage_0x0dbb89fa(0x36ae53d9b0f9ca66c037b2a31df3a54fbae0d88bce72ba15ba89fe864e500af1); /* statement */ 
data[5 * (i % 5) + i / 5] = uint256(uint64(values[i / 4].intVal >> ((i % 4) * 64)));
        }

coverage_0x0dbb89fa(0x13db45922d33bd0de10f81cd8420fd37ba4476b8f0a33443c166820991deea23); /* line */ 
        coverage_0x0dbb89fa(0x97734977437bb10498c92d20f9ea48fda1be25bfafc3648040f03bf3be46df50); /* statement */ 
data = Precompiles.keccakF(data);

coverage_0x0dbb89fa(0x73f1476133766be3d7797c87e3fbf011f02561388084171b723a3555633a8832); /* line */ 
        coverage_0x0dbb89fa(0x1bfe01686cf57ccc888796a2d0a0f3e537a14a4f007b1449633f614a90b1012d); /* statement */ 
Value.Data[] memory outValues = new Value.Data[](7);
coverage_0x0dbb89fa(0xe8830eba8eac0248a28bc12736764a02770022e8142e031943fa54e9fa101383); /* line */ 
        coverage_0x0dbb89fa(0x3e2d72ffc15f1ae25350771d52ad9d8580c244f4f3276405f0d7d9beb2a0ed15); /* statement */ 
for (uint256 i = 0; i < 7; i++) {
coverage_0x0dbb89fa(0x5003d69162c9b2c6809ace0d9ffa829b3f69a16c84c37fb0086ed02ea8f8486d); /* line */ 
            coverage_0x0dbb89fa(0x85e06bd6fd1a81bc0cd90e4c3f79031ff1c26c51260866a59f8b0b6e21d823a0); /* statement */ 
outValues[i] = Value.newInt(0);
        }

coverage_0x0dbb89fa(0xe1c94829d583c7320a4b2a9058f9f8a203974641e15ad3cf54835bc452afd808); /* line */ 
        coverage_0x0dbb89fa(0x898c3957d3565e41f618d4e469e9a6acb551583dab42c04e1057fb471077b678); /* statement */ 
for (uint256 i = 0; i < 25; i++) {
coverage_0x0dbb89fa(0xeadd376f4980cd27185e609333cbc945592b10c3b680633a732cd1af09fd111b); /* line */ 
            coverage_0x0dbb89fa(0x77791496ffe0241c8e5faf9f6d52a5d8c03c06baa62ad2ef97167421797f05b9); /* statement */ 
outValues[i / 4].intVal |= data[5 * (i % 5) + i / 5] << ((i % 4) * 64);
        }

coverage_0x0dbb89fa(0xe76dd31a6c394ea5ee5ea03e02e5c57046c7cb3e88ecb04576d869aabd021030); /* line */ 
        coverage_0x0dbb89fa(0xb253108b887b21d9f0bc5f27524a48b3347761a69f97dba9754b6eced68175a7); /* statement */ 
pushVal(context.stack, Value.newTuple(outValues));
    }

    function executeSha256FInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xf7f01c378fc53b4d2a77c2972ee68db49869f844603ea68eea0400eb85b85dd6); /* function */ 

coverage_0x0dbb89fa(0xc2b10b6dd124ab4ffec7760aef10194d6d3614de039fd53d2fd45f104772cf9d); /* line */ 
        coverage_0x0dbb89fa(0x82cb5bccb17e009d00b564116ae1abfcb6f3ef8617b9b4a60e37b1460d804413); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xefafefa3a0d4a909f36163cb38076c8ba507f680c0bc194920de0515b9d9d1f7); /* line */ 
        coverage_0x0dbb89fa(0xf6f1b3d588397293410f0f3f451670fda67c7c53defc03da1712917fd183ad6a); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0xa8aed090b6a095dc8a132500eedf19983330ff0eac07f907ff7c93178d149fbe); /* line */ 
        coverage_0x0dbb89fa(0x4dd6f3bf72eee8db53b9df121672a1a21a59cde4ce8b0c9fc0f59ebc340516ab); /* statement */ 
Value.Data memory val3 = popVal(context.stack);
coverage_0x0dbb89fa(0x777529aa3ff532c18d09431d2b69d1bb381575140d39dcd767759f7b0623efd8); /* line */ 
        coverage_0x0dbb89fa(0xf17186e532b5276da0b6b29262038b15ae3fa88aabef5c70d5777c90a89fb7f9); /* statement */ 
if (!val1.isInt() || !val2.isInt() || !val3.isInt()) {coverage_0x0dbb89fa(0x18f25435d607f98f0dd9b33947016ce32f2b9895e00350938c914d2a62c3a5f8); /* branch */ 

coverage_0x0dbb89fa(0xc05d26c80ac56140d7dd39e9f48739e7a8e7009d64dd5fbb4a9fafb5d54bf311); /* line */ 
            coverage_0x0dbb89fa(0x6977715703b25413c00a609e043fd106deadf8fc92a1271243961c195179cb2c); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xdd8ee88b9582501cda3d7e1cf679552ed0e2cb0cecad31f7b14177b3c7275d6e); /* line */ 
            coverage_0x0dbb89fa(0x4b0c8bfadc53ec080ac6f19b8638c1dd65bd366216769c588a826d582d45023c); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xb78c37c8dadda3511b663fcbf8ed65a797a0e5a5eeb35f05a079f9f34e6cccde); /* branch */ 
}
coverage_0x0dbb89fa(0xeb7290d99147bc2dd9c72d575c596ee954454ce8d970439e400c060ac1e28496); /* line */ 
        coverage_0x0dbb89fa(0xd9bc1f1e6c2f11cf06a5d1eb50bd0c4e4ca3242f972645a7812018bb4a441bfe); /* statement */ 
uint256 a = val1.intVal;
coverage_0x0dbb89fa(0x24181d6839875b28ffc05cd5b2bcbbdc9f4f16b545333ae3f0aa367db5717c3d); /* line */ 
        coverage_0x0dbb89fa(0x94f51f5887b641308a15a9b1c144687ef14a5bfe5f52ee24b5c9ae2f12287042); /* statement */ 
uint256 b = val2.intVal;
coverage_0x0dbb89fa(0xd4cffd3306d58f11e9b5341f0ddfaf91a099be36dca874f98060eda1c4024855); /* line */ 
        coverage_0x0dbb89fa(0xea28e669b0657fe6f8cef3c1e12308cb9c0fada5d3a3de4ebc21c7064337522b); /* statement */ 
uint256 c = val3.intVal;

coverage_0x0dbb89fa(0x7b9907b84b15d1f2d27a7858167bceff12ce9015fd07dd2a704e136b2aad3940); /* line */ 
        coverage_0x0dbb89fa(0x0fa69f68b9e19db6694c8dd67c59a6fb9cf5038ebbd13d6530eb43b7d1298f53); /* statement */ 
pushVal(context.stack, Value.newInt(Precompiles.sha256Block([b, c], a)));
    }

    // Stack ops

    function executePopInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x29da7b5e960802e978a55e90c5fa2f7ab0a1f6aaed3a1c442cf3dba193141dc7); /* function */ 

coverage_0x0dbb89fa(0xac83e1f1483000f14ee214e42c1c1b3c0ed2f992f4aa747fe8641a14f87bf853); /* line */ 
        coverage_0x0dbb89fa(0x7455110fadd878ae257022003e8c0580c7622c3d2fe3814d49fb1357debb9575); /* statement */ 
popVal(context.stack);
    }

    function executeSpushInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x03428f66096236b4b9343be88847749504fb31af3e934082b2220b5324e1ef7b); /* function */ 

coverage_0x0dbb89fa(0xadc43e8dac4263d31a9596c6457ba821a8a24ea4e8187f3c91cb1df2d6518558); /* line */ 
        coverage_0x0dbb89fa(0xc33969ac464bcb8676036b74542748c179b4be9caf13368113c82a3eb4f28282); /* statement */ 
pushVal(context.stack, context.afterMachine.staticVal);
    }

    function executeRpushInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xd693c55951c34a5d9b6ecae7df1ebed42ab6b148de02a48fac808710d8c8976c); /* function */ 

coverage_0x0dbb89fa(0xf8e518dcf1882084cc39bce05a6bdc3f833ecdc7931c0f23c3562859b0bb232b); /* line */ 
        coverage_0x0dbb89fa(0x1f0f1ff515a7908cb7e36d34c3321632b4da8e5e9bd0831f58b9034852b5759b); /* statement */ 
pushVal(context.stack, context.afterMachine.registerVal);
    }

    function executeRsetInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x65371dd22dfe2114a5601fb77bc97b469c2ee75d6468580150a083721807199c); /* function */ 

coverage_0x0dbb89fa(0x581c0d8c29659c6c14b076b2f4f0fa357c3450368bdc0406e3c99e54c4fab1c7); /* line */ 
        coverage_0x0dbb89fa(0xe49ad2cc46e7656c5838c29c11a58311f546e18d8688aac76d66360938af1c43); /* statement */ 
context.afterMachine.registerVal = popVal(context.stack);
    }

    function executeJumpInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xa95b7479542aa026eeef1d75176c9acc7ff43000c8c869dc5b3a0e00f747bd8f); /* function */ 

coverage_0x0dbb89fa(0xd3da19cee7bfa1658ea61a29d06cf6e3ef73adc8931947d32cc1f6fe251345f9); /* line */ 
        coverage_0x0dbb89fa(0xf677ffa9f9a3ccb866a9168a14842e37b5be0e186ae92b1f0aa496f4edfedf31); /* statement */ 
Value.Data memory val = popVal(context.stack);
coverage_0x0dbb89fa(0xaa51c37a5cd6320f52e1dbc520331e3b70ada8a08ba2d42ef34a7f2afbb1846d); /* line */ 
        coverage_0x0dbb89fa(0x004192818987995dc072569a2d4b2833a8c45e51d4116e143907a4bc55621298); /* statement */ 
if (!val.isCodePoint()) {coverage_0x0dbb89fa(0x306773190cf7c871704ee025e59547bcb06435b65950dc3e83b8f9d268ca3d05); /* branch */ 

coverage_0x0dbb89fa(0xeae64bda4c7d0a9e0772afcf973a4a82965ce2273ba07608ffd340f42aea240b); /* line */ 
            coverage_0x0dbb89fa(0x0604f2994641b3385260274b8dfafb6a17ef468e792784b08a319a472063a907); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xf867469a9bc459c3b7dc71ccd49034e199015f587923457d88e798e0775176f5); /* line */ 
            coverage_0x0dbb89fa(0xb2d2b1803f639376a7be99b5cc700f9b7314c56d2bacc4755cbd57fce2715d15); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xd0f3cd461816b2d78cdf77b40fd23991f5999a387b77ddd5400cdd7602319f1d); /* branch */ 
}
coverage_0x0dbb89fa(0x9b3abddd860696be8966530d0b8543b10a950ce0f2d5106cd4119c7cdbd38dc5); /* line */ 
        coverage_0x0dbb89fa(0x72108e62ad5ad323cfcbad1915dc4e68c2d37128877dc5b5f0325c5bf5c19b5f); /* statement */ 
context.afterMachine.instructionStackHash = val.hash();
    }

    function executeCjumpInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x4e9c2654feb80367629b8806fb65e86792268fbab7f6a92a4dd832b2ec3d5120); /* function */ 

coverage_0x0dbb89fa(0xe23a55ea265d27677ac1f33f33e0da303bf7ec45851ee51771235a760dea6634); /* line */ 
        coverage_0x0dbb89fa(0xdb27c40dad5219661c8086d15e2e42d508514b2448ac96cc8c0a42b44a3f1a38); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xeb329728103ae65c8bbbc927a7a119660e61101264370b9a75a3bef03d004807); /* line */ 
        coverage_0x0dbb89fa(0x0507aef787c125fe85283010b5e091f2d2195f371d80da3d600c73317c28fedb); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x81d8a80bb27de0c4e302080a15696112ca29be250feb4431e8614e9bb84504cc); /* line */ 
        coverage_0x0dbb89fa(0x9f2a702f4f5c9da13d57741abae4363fa2c5367d24f4b4d6296d4393bf1a83dc); /* statement */ 
if (!val1.isCodePoint() || !val2.isInt()) {coverage_0x0dbb89fa(0x57b58ee7b125862923f38bbd5e17ac19b60769d49adb7daffbfc24bd6a74d1f0); /* branch */ 

coverage_0x0dbb89fa(0x2e6d8490fb01fa3c5d19d8ee1aa11d4c6c68acd12c25073ec20086b04733a1bc); /* line */ 
            coverage_0x0dbb89fa(0x52b11a264be274e47bd15b07fb4f4927c566f19be7bf295b36ae4f421a80cd9f); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xa9a6f0a9076efc9d2e904b47b410ae973cec24d1832d61f395ccb1742ec3d945); /* line */ 
            coverage_0x0dbb89fa(0x0d16480d325a6726440eee14f96620fc5d381b51b1a4fcf1fd94fbc587e0cf87); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x027e9c51656fcbfb7c4ace4ec57d3ed254a5166d903d234b218f858b9696bca7); /* branch */ 
}
coverage_0x0dbb89fa(0x4eda3dded69111c4097916a828a85e5e49c42ef7544fdfbb2a99c79f2a884f25); /* line */ 
        coverage_0x0dbb89fa(0x7cde79fb85496694706a21c219ad007df20ba8b22a1094c0154ac65b5d938955); /* statement */ 
if (val2.intVal != 0) {coverage_0x0dbb89fa(0x0dab6be69dad545e735ef0636fe7e9e7eb8e001141577f946d1eeb61671a5224); /* branch */ 

coverage_0x0dbb89fa(0x9c063ca4b3cf57b6ef2fd2c98d4120626390b92d9181df08c76ee1741de53066); /* line */ 
            coverage_0x0dbb89fa(0x39bcc5991d309b6795aeafe158391732c7d7b2ba414c5a479dc0c0028c9523ad); /* statement */ 
context.afterMachine.instructionStackHash = val1.hash();
        }else { coverage_0x0dbb89fa(0x6b8ba7f24d1d6246f86820f8bb3eb4edb2c58f19a89b858339bb74b95175b80c); /* branch */ 
}
    }

    function executeStackemptyInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x3ad5d2d8749569e514ac345e6a9220bf781eaebaeaba6cd72d436556bf6fc76a); /* function */ 

coverage_0x0dbb89fa(0xb0e346dc4c4643204124e71f00076b5534a572cafae27d04f45cc1cc33569fac); /* line */ 
        coverage_0x0dbb89fa(0xd002a2f10b9acffa7aa6bd65999db736f88bb9f571658488afdb84a9fff31324); /* statement */ 
bool empty = context.stack.length == 0 &&
            context.afterMachine.dataStack.hash() == Value.newEmptyTuple().hash();
coverage_0x0dbb89fa(0x12a305dcd1a263bd9fc62ba16d3536cf2a5205fa311b5a7035121dc8e938b7e4); /* line */ 
        coverage_0x0dbb89fa(0x36791fc1479a6fd85d544e654b4e26e44ebc551b0dfec37b3aa8b4c48279406d); /* statement */ 
pushVal(context.stack, Value.newBoolean(empty));
    }

    function executePcpushInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xc44f0b21a42e18181d5a1b0394dc86f0429f5ac8ccac65a3b731b9486957ff1b); /* function */ 

coverage_0x0dbb89fa(0x360a6c4fb5932ec454c61fda38bf3839bcd9ebabd714e25f27096d701b7b8284); /* line */ 
        coverage_0x0dbb89fa(0x9df9a6169204faf3bd462d6c5606f481692748b089754ea7539c4134325074d0); /* statement */ 
pushVal(context.stack, Value.newHashedValue(context.startMachine.instructionStackHash, 1));
    }

    function executeAuxpushInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xeac8de3a868cbfadc09bedebcdfb0fc060535585415c9f387cf03ba391338099); /* function */ 

coverage_0x0dbb89fa(0x06e9ed481b2fa011c9866918f50a8ca932cbf40ae9b094852e2894fdad4925ab); /* line */ 
        coverage_0x0dbb89fa(0xc2a69deca55044ed1ed8c58ed090ec06c12ec97c2909a2db807db32bdd71740a); /* statement */ 
pushVal(context.auxstack, popVal(context.stack));
    }

    function executeAuxpopInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xe2518083ebcf1515fbe125a0ef83baa899e7753042ee3fb96ddf3f8f25661d8c); /* function */ 

coverage_0x0dbb89fa(0x2cb7e0516be84fafff917415a2c1b251e194e43be595669401e03e6e793ffdee); /* line */ 
        coverage_0x0dbb89fa(0x702c6fbcc02c96f6fe6528f827b53b7070cb6b3a0a15d3562446c1974b3eebb0); /* statement */ 
pushVal(context.stack, popVal(context.auxstack));
    }

    function executeAuxstackemptyInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xadb3a5b7cd4128d0642050c1d25b5df7d139811c2c9d2882c09e8930d178d04b); /* function */ 

coverage_0x0dbb89fa(0xb2e31579b880290321ab24f3011cff4eb662a0a8e069d80022678d5ff9b9f5fa); /* line */ 
        coverage_0x0dbb89fa(0x5f34107f778f182f77c741a2458824b44c158b68948e5be324cfa66d548d1a1d); /* statement */ 
bool empty = context.auxstack.length == 0 &&
            context.afterMachine.auxStack.hash() == Value.newEmptyTuple().hash();
coverage_0x0dbb89fa(0xf5b0ac5626bbb1f552e4b041907994fae6d116f0c2a7a3db288323bbe6515640); /* line */ 
        coverage_0x0dbb89fa(0x530a1bd3c44a9bc369ced7e9a6b61aceeb3279cdb27381436357a7cb98d5f7e2); /* statement */ 
pushVal(context.stack, Value.newBoolean(empty));
    }

    function executeNopInsn(AssertionContext memory) internal pure {coverage_0x0dbb89fa(0x3a538d83b00c3a29fca910b039272fd77264e08969fa99d36549a0a7a9b8610f); /* function */ 
}

    function executeErrpushInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xdfef5da7496b6de4e00f8dec38d883951f0f505a7b06408983a1b1442eba7654); /* function */ 

coverage_0x0dbb89fa(0xddb1ff831808960ac7d6bc5a3349c0311043e464e9aec92250b2fe4b71908ab3); /* line */ 
        coverage_0x0dbb89fa(0x4552c352b127895e6a0ceecc8723ab4d28d679b7378f9fc4354a3113e96d16a4); /* statement */ 
pushVal(context.stack, Value.newHashedValue(context.afterMachine.errHandlerHash, 1));
    }

    function executeErrsetInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x697eade098a3e3b66bf74d22c1467e8dfeee2b003e230b6312ea543bdf9a0529); /* function */ 

coverage_0x0dbb89fa(0x5718fb48cdf59680e4897320c411fce4e9f2465af9c45850258048f5b2867fe3); /* line */ 
        coverage_0x0dbb89fa(0x36d3fdc1916b3a129d25a9f10fc9e73489db7e6855fb76016480ee677406b1ea); /* statement */ 
Value.Data memory val = popVal(context.stack);
coverage_0x0dbb89fa(0xdeb93a4c1e641cacbabcbf53729b626111366333165f5947cbeec7f91d5d414e); /* line */ 
        coverage_0x0dbb89fa(0x7d7f4ed7867c947d34bde4af570c5266ddf4d674546d51471bbbb4ac153d025a); /* statement */ 
if (!val.isCodePoint()) {coverage_0x0dbb89fa(0x66554e5a90ae639b67cfc699179e6ca0ca25a500ffdfb5e7d0e0e6ed4fe24a78); /* branch */ 

coverage_0x0dbb89fa(0xc1ef4acbaabdf31ba639a6ab50ac8aff66a71bbe31b5edfbd160ef477eaba491); /* line */ 
            coverage_0x0dbb89fa(0xfb31a4edf7b0a5dd4b581ca194ad1c543abf1886b743df57f10ca70745074479); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xbe4a864dd766ac4ddc10dd6026710e60cb369d97afaed2810ab2864058a3aabb); /* line */ 
            coverage_0x0dbb89fa(0xdba217281a03af46ec0a764fc3c060c03abaa049d100ff15b9cc361be9d50098); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x5acd4eb701f9a14fae04cbb8a61c9000c9855e6d5b6ec4cb2a26d8ab75274f5b); /* branch */ 
}
coverage_0x0dbb89fa(0x052a7dd3d4a7a536a16186942771947843d05de633cfa5009b8bd2ad2ac59da8); /* line */ 
        coverage_0x0dbb89fa(0x2e49944fc1b914fbe64900e26d0ba02d46dc837372dd91df7e93eddd99092931); /* statement */ 
context.afterMachine.errHandlerHash = val.hash();
    }

    // Dup ops

    function executeDup0Insn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x1d886144a7b12891acb813d3190d72256aa218a98e40faa4e545e486a7f3d325); /* function */ 

coverage_0x0dbb89fa(0xd70a533606c6d6f49e2602012ebb0dc49d1ada8aac64e3385cda0e0b90f8fe8a); /* line */ 
        coverage_0x0dbb89fa(0x7affde64071c526399044df05014ed0293d3d9f0616adce46c4d9dc0b08e2d3f); /* statement */ 
Value.Data memory val = popVal(context.stack);
coverage_0x0dbb89fa(0x3d24ecf5b2917fce591e9a138f3e44a19136d48a3619fb2f180c4beb8eeb35b4); /* line */ 
        coverage_0x0dbb89fa(0x357e19298e4d370a6b5327ebb1a107fe8331c332944df511f9241daefa6a7a71); /* statement */ 
pushVal(context.stack, val);
coverage_0x0dbb89fa(0xc3b932b5b333016565b5698b8a27d890aeb7c795be4d2611690394b91c2b5d19); /* line */ 
        coverage_0x0dbb89fa(0xf1ecfb39f6900b9015289f5211f03523286409044331926db73749a3cd5ae8b8); /* statement */ 
pushVal(context.stack, val);
    }

    function executeDup1Insn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xecb32f23befdef59008b841d745d97eee58d201382cfba9a63c7786ea18b540b); /* function */ 

coverage_0x0dbb89fa(0xdd8796f113f923b39a9c2a3e6577419425f8d848cf1756624fb53cf7493cd413); /* line */ 
        coverage_0x0dbb89fa(0x63fbbdd1efbe574754b6bc43159d9d7ea00739eece3b501f66ff693890ce387c); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xb8b211733764222e67644d265fd045573ce342a916699e981893e2fd5e94b522); /* line */ 
        coverage_0x0dbb89fa(0x9827ace3b01d7f60c163a938e2625307fbeabd02fb0632dda9bbc73ce24187ee); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x0d15f714d9375d9e1ddc76254023dbf1f15d848affa55cdfdb8614a3ebfe1103); /* line */ 
        coverage_0x0dbb89fa(0x1becdbe09c8caee87d9a81a6d28a0737ba3a6734ca8d0aeb3c15458bf3f8cfaf); /* statement */ 
pushVal(context.stack, val2);
coverage_0x0dbb89fa(0x531110487c3c012f227dae071123ad73217107d6989b3935b6ab03c246f6c472); /* line */ 
        coverage_0x0dbb89fa(0xb4a86f97673c2e3d22105eedfb8521560e1c1d635bc33bf8f0503346697c8112); /* statement */ 
pushVal(context.stack, val1);
coverage_0x0dbb89fa(0x4a67cfe2e36fcc87ed69f8943332ee7be237ea70765523818c3dd3d7eb65c5bf); /* line */ 
        coverage_0x0dbb89fa(0x08e6152df28312d711429c9374d3f98130d72e9a496599a4284a01fe45d3b366); /* statement */ 
pushVal(context.stack, val2);
    }

    function executeDup2Insn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x117d7f397c016db82712e23f28ba17186a79a4eb9734b3d6cef79ce8d6f0055c); /* function */ 

coverage_0x0dbb89fa(0x4cce5126c691fc78fe54b003ce5e4c691b5d5e9b8f5e341b70579d7a3319e6f3); /* line */ 
        coverage_0x0dbb89fa(0xf8631108ffebfc23010f58f381fec1c9218342c7f8af3031413faeeef93cf94d); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x4ee643f3c34ccaaab397431c6a610d37186e1bc22b46723bb50d93e2421a2e7c); /* line */ 
        coverage_0x0dbb89fa(0x7c27f6c228035e8715a73f2e5dde64b13c27cde4c3106d579ab0ad2ec29df558); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0xc1e90c3b51a43ef28e4f078ae13461f7ac59c551bb51fa1acbabaa2b91dd7fc2); /* line */ 
        coverage_0x0dbb89fa(0xe8c4bdae0681e29b82c6c42bc39a18912c07a04473a248d87cfd4ec131101b69); /* statement */ 
Value.Data memory val3 = popVal(context.stack);
coverage_0x0dbb89fa(0x8c16cd1dc877530d77aa1facb92f68179ef833a1fd4754c0e563cfe99fd0472e); /* line */ 
        coverage_0x0dbb89fa(0x1087c94d54bda9668e5d34b04d74c57ce4eb3b14ec4581a5104dd922be05637c); /* statement */ 
pushVal(context.stack, val3);
coverage_0x0dbb89fa(0xa259999c1b96f5de1e62ba3b6273cf176a3d3d43d4d2d6d08200b2da767a96a8); /* line */ 
        coverage_0x0dbb89fa(0x5f9812e2ea62cd5ec528f7ea4b60ef5b694f4880c9ee2e09e10be95ee29e28bf); /* statement */ 
pushVal(context.stack, val2);
coverage_0x0dbb89fa(0x09ee161355aaa2788f4abae4ec6a606d6fca790c1ce636f48d24ce408b9b832b); /* line */ 
        coverage_0x0dbb89fa(0x4320528c28096a14ae254bab81234509864ba29aaa1e3f64431c65cd5d01b516); /* statement */ 
pushVal(context.stack, val1);
coverage_0x0dbb89fa(0xfa23a02e831767fc4f35c25afb1bff0275f1aee051ee52e9eafc0381f8f7db29); /* line */ 
        coverage_0x0dbb89fa(0x2b99c1f5ac96af6c706e68ae2d5ff65533a1b7bd6cec0a34e304247cccb052dc); /* statement */ 
pushVal(context.stack, val3);
    }

    // Swap ops

    function executeSwap1Insn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xb8e03b3bab730247b9d6c2656cc3a934041553c082f2b19933aa83deca5ddad1); /* function */ 

coverage_0x0dbb89fa(0x13c007128e40b8f4a3f91036671e48327ca425ee20fb364984d0a0b60ba17717); /* line */ 
        coverage_0x0dbb89fa(0x8bc2ae07735e9d10b7b01263dc66ebf02e30ee945b7d068bd6659924bd62fcd9); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xca2318b073b0cffad909e86fa783d2293dc270f653f7f7e504ce0bdc1d73c808); /* line */ 
        coverage_0x0dbb89fa(0x6d0e9fd85cae94d4200dbdd5c7a0ea257c32c20521e760c92996928e93fa9b66); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x0ac2caec199f599e51051e69257d5a0258390a709121d039e3e18bc6fdfb944e); /* line */ 
        coverage_0x0dbb89fa(0xfe4a2150ad116e231e52fd3a32d1adfd9143a455dfb46e90b7c569c70873776c); /* statement */ 
pushVal(context.stack, val1);
coverage_0x0dbb89fa(0xf096669648743d455ff4c7bbd8df5a928fd8f708d53bc2a1c91f4e700ddf0fe5); /* line */ 
        coverage_0x0dbb89fa(0xb9c2a7b4be3dfdb3b79d76a217fda7e530921ea57375438c01145b617a4cdfce); /* statement */ 
pushVal(context.stack, val2);
    }

    function executeSwap2Insn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xd359410c5e49431401e0bf204a65c5144d120aa80ef2dab67d647b6aea620f53); /* function */ 

coverage_0x0dbb89fa(0xe350d4c636edffa5b73c3f01585331eac082c3ae7a1919b500807769f43fd0b0); /* line */ 
        coverage_0x0dbb89fa(0xd8dd2bf598d93e6fc7308677a52111ef78b37ee1ccd451b8d967258a41e2bbab); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xe162a237f82cefcf10395e056aee5ab9f07a90c2d7e7fde2b6920dfa009db0b7); /* line */ 
        coverage_0x0dbb89fa(0x4e4804b16d29ce43ae6a25c714e81a65047d03dae6a9d57a3d7b21b69860e243); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x668a1f6b0909a5e1f6ee039079e0cb4623e460b55ca91d049c5589bfadd1353b); /* line */ 
        coverage_0x0dbb89fa(0x52db9088dfcbe8cac08c7f50c73952620d04a4303d1c5c24cba3bb15e0e65852); /* statement */ 
Value.Data memory val3 = popVal(context.stack);
coverage_0x0dbb89fa(0x899327081ec111ce9bee16e3665f1a71126a7e2447afe6793cf36df2fd0b8e3f); /* line */ 
        coverage_0x0dbb89fa(0xd894ffc157cca26dd44ee884e7dc4b40b78a7b0dc5a07ebbcf7afd2668fcf467); /* statement */ 
pushVal(context.stack, val1);
coverage_0x0dbb89fa(0xe55dea21ec3d7ef7512349156258e4248a046c46a7c2bbb6b1467e24890fa6a2); /* line */ 
        coverage_0x0dbb89fa(0x346d06e0b9a3f23c303e023f53a85e33923fc90f156a68b673c89112f00474f1); /* statement */ 
pushVal(context.stack, val2);
coverage_0x0dbb89fa(0xbb5914ab093695df81b9f368cc58597a9f3fa6b1a6a30778eddc1afd2bf0ff97); /* line */ 
        coverage_0x0dbb89fa(0x7863f16b8c5718ea9e80af0fb97dd4b72a843796d9bbd5b3a2b713ea5ea6036c); /* statement */ 
pushVal(context.stack, val3);
    }

    // Tuple ops

    function executeTgetInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x269df0b62ff57a75b1fa2cc967dfa5434bd9160114f41fb72f2fb6eee171266d); /* function */ 

coverage_0x0dbb89fa(0x1493336e59a753e0215d2d14604ad6512d8900b99eb56e84435c27c932495688); /* line */ 
        coverage_0x0dbb89fa(0x3590e1e95047fac64d7984e4bcd0724c32a6cf44b72855c291b05b8b584964ad); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x1d35fa8e6bf3b2252957460549580e9be63618ada20c9678c8ff372e62800a93); /* line */ 
        coverage_0x0dbb89fa(0xa58e36ba46c4639206e1a94b230572fc6f7b6544ff78e34a8bb4da0b3c6b5333); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0xcb6e481578ee417bf487619d21f3a92ddd08f24ed89cd023811ccfa7c163b61c); /* line */ 
        coverage_0x0dbb89fa(0x4a8a62dd5810cf1f7310fcb54be7edc6308631bb7cb5614a8f38f14719b35115); /* statement */ 
if (!val1.isInt() || !val2.isTuple() || val1.intVal >= val2.valLength()) {coverage_0x0dbb89fa(0xf28ff9e5f866aa73d8ce75645a855f0a8668a1c0d647da07eb367e2ef48bceb7); /* branch */ 

coverage_0x0dbb89fa(0x9540a4983c5cedcb8bea251e335b42c6d98e51afa629a6bf8dddc617d6bd630b); /* line */ 
            coverage_0x0dbb89fa(0x1a6bd86df695a5119952e76a185c2d61c9a0a0e8ade32876138534d74b54b8b1); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x82ac3135fa3a06c1feab68e1842e0bcb09ac3a8aa3167b4abaa2aa132fde5fde); /* line */ 
            coverage_0x0dbb89fa(0xbd77b3b25c3be9f69fb37de1cd799c33edc90957521604c4c1f2b5f48e4270d6); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x8def5033bea76fd3f0c2fc8cfb4f701e11a286a592074d2615410b62d457a0dd); /* branch */ 
}
coverage_0x0dbb89fa(0xdf0073be00dd559969b25b594ef3642031aff2d94e7ef25906478598531cc5d5); /* line */ 
        coverage_0x0dbb89fa(0xf4e742f5b415fa60802cdb7854220df4384bb8e55d385a4eab36ca376fe39252); /* statement */ 
pushVal(context.stack, val2.tupleVal[val1.intVal]);
    }

    function executeTsetInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x2a99df1073969993bf955a2bf088787042c38b81040373ebc74a6d0ca6ddf7aa); /* function */ 

coverage_0x0dbb89fa(0x841f089416d50735ac045022d38b703eb1c162d0d6f6f7353a0e583f5fc5fa73); /* line */ 
        coverage_0x0dbb89fa(0xef8cbcd7b5df0d76b726425757cdd62fda31d1c212639256f6e9089cbc37751c); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x7eb52249e3a9771e2f3d597ae69858df804eaff5e82cb8ed7b85b466d4950e7d); /* line */ 
        coverage_0x0dbb89fa(0x87b766f42f0796f5ff2aacddccc9f0138d893daaee262894396afbbdea8c9d41); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x3f293efa4138b80e1ff53d3deb62504a923a2f96c0fcb83fe395bfc0adc45058); /* line */ 
        coverage_0x0dbb89fa(0xe1a40294512b7182ab37c7c00f36a46b6070da0a3feb4538ec01e6eaf3767e39); /* statement */ 
Value.Data memory val3 = popVal(context.stack);
coverage_0x0dbb89fa(0xe52d10475223d7f18cb423e00be0b5c0c103fe0f458cfd9bc8cd9c52adb17f0c); /* line */ 
        coverage_0x0dbb89fa(0x1260a54f1d764f7c6ec1d4d2d8d40eba4ca8d0f74aba06d65f78ed839aa4165e); /* statement */ 
if (!val1.isInt() || !val2.isTuple() || val1.intVal >= val2.valLength()) {coverage_0x0dbb89fa(0x9853a448f69631f30ad2d40800bdfd02e48afee1f041e6aafd1336a7d6e1dd44); /* branch */ 

coverage_0x0dbb89fa(0x7edb2267e1fabb9646bed7fd930fb1d72142f6855c598f86f68a77fb0437d3bc); /* line */ 
            coverage_0x0dbb89fa(0xb72362c5f1788c4d617d5e8785fac1f34072362b4ee6c3f718c5055749f83780); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x728899e8a90582b6e250ebf4f9f846c91c754fc3e31012ffdbb0fdb3be6a538c); /* line */ 
            coverage_0x0dbb89fa(0xe1683801aef9a56c469e1d0baa71a4fb9cd9c2b34b1e770a29f69de543d8df8b); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x4ac67a1926be7644ec1725b85f513bd54c4e414467c7a22d44c6d19a901874cb); /* branch */ 
}
coverage_0x0dbb89fa(0xe2f0919cb02593a584c8d93b0b2b69584876c751b4e1b681dc044684affcc08a); /* line */ 
        coverage_0x0dbb89fa(0xd2b8086473197e226c63f9d5a5b3ffcbfa1589adb6ed754b2172e1f0cd735ba6); /* statement */ 
Value.Data[] memory tupleVals = val2.tupleVal;
coverage_0x0dbb89fa(0x9583ab9054ed7397747f55fe331f30854eb64af8882bf1523dc396610d2a9de3); /* line */ 
        coverage_0x0dbb89fa(0x71c094fafe8d46aef7e1fb4d1510c09fa5417de5b0baaf930d302f2e0ed268f0); /* statement */ 
tupleVals[val1.intVal] = val3;
coverage_0x0dbb89fa(0x03580dab742acd8f5901e0d1858ef987d082ad087202c4a8d54bb4dae87a156a); /* line */ 
        coverage_0x0dbb89fa(0xe3919fb2f87ac92635dc1d7d7a10302280fab66a8e9a5dd2f198163686aa34bf); /* statement */ 
pushVal(context.stack, Value.newTuple(tupleVals));
    }

    function executeTlenInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x62ba3efa02b19bc1e513cf8123f6d35422912af04daf4bd5f8ab77db12771211); /* function */ 

coverage_0x0dbb89fa(0x6b8f0d6da6a79a34e6dceea075fefacc4226285e0bff5867bb75d2ffdfe350e3); /* line */ 
        coverage_0x0dbb89fa(0xe8958655bd8748247adf3fdfecde53c95b986edfc69d19a94b959af0cf2107be); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xe4e4c58948a82b3732da0df464a8d61793e7243b2696190534775b6794e61302); /* line */ 
        coverage_0x0dbb89fa(0xd0c36937b371f41fef096eba1bea0d7a919a814a8da5405ad6ec368ada862d27); /* statement */ 
if (!val1.isTuple()) {coverage_0x0dbb89fa(0x16e85766bbd7e4a8510436be54e2b02296360b6c3260cbe9a93e2c28189ce9d6); /* branch */ 

coverage_0x0dbb89fa(0x6ff9f94a095d5bf515524156f132cbb5718237ced00df0ad52a52d10e435750a); /* line */ 
            coverage_0x0dbb89fa(0x9ecf6d49460dcd5e26d0c9414d8526ae68c8d3a0cb80f1e6f8ed07bb5c776ef3); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xf6da2fddd775c54f20621571d1e294679ce7c2d56954a171fbed2077cc5fef9d); /* line */ 
            coverage_0x0dbb89fa(0x2f5056374778b640610e01f7c6900ad0b52b7a17576bdf13e37fbeaf97e5fc48); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x34aa21f6cf7a2bcfd9aaaacdb2cde509d51298f8c7b75bbde48fcc4cf7e4e967); /* branch */ 
}
coverage_0x0dbb89fa(0x7e0bcb747a0d5d7d6be6eaa1f32d090b8757c22ab0773df3541377f858278cd2); /* line */ 
        coverage_0x0dbb89fa(0x62f6c1c0057b8271aa709bdd31b8c03daa629baeb202a99abcbca1657447cdf6); /* statement */ 
pushVal(context.stack, Value.newInt(val1.valLength()));
    }

    function executeXgetInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x876ff980cd480dd71c4a8bc4d12f415b3a0eacf58640113d927cb91ef1092b68); /* function */ 

coverage_0x0dbb89fa(0x09225ae7a83d467561e0f07adab72b503bf533e167e7aa178fbe89e5ee18de43); /* line */ 
        coverage_0x0dbb89fa(0x507961efbdeac29c6b589065111cbff395dbc6a7094f4bfd551a6ad61362831a); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x7f983ce7f9035de8df3413b435e5f0f35e2a4c45bc1c63b2337567556ce334de); /* line */ 
        coverage_0x0dbb89fa(0x1d615b4643de4644bac4b75a458ee9700d4753d726897707233bca171950c1ef); /* statement */ 
Value.Data memory auxVal = popVal(context.auxstack);
coverage_0x0dbb89fa(0x1539fdd6bc1f09c55f2cce355f69e51d6f58c6b3eba96363446ad03590497677); /* line */ 
        coverage_0x0dbb89fa(0xe91bf05ad37d2a0612e6869b66fc033f0510f1f45682aaaf124f711f84707723); /* statement */ 
if (!val1.isInt() || !auxVal.isTuple() || val1.intVal >= auxVal.valLength()) {coverage_0x0dbb89fa(0xbf8d1db024358db7c6e2ff8c7030394ed224fcda2ccea54878e3de149c20f5d7); /* branch */ 

coverage_0x0dbb89fa(0xbd5cbd3bb153b59714048053ef23b043b610444714f0fa8ee40fc9f264ccf553); /* line */ 
            coverage_0x0dbb89fa(0xc64ffe4f439f8e193443bc426d449488d00eb52ebd6b122c32c0448923beb6d8); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x0d751983a7c334daa596ff60f7633565ad92b4c6e667509e8afab28fe7240bb4); /* line */ 
            coverage_0x0dbb89fa(0xd3bfbdd1b7f589ef820475bc363cf6992ee07103fd8a94ab773b62e113d1bf4a); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xf00042ec9f2d28a40fbb65f3d60fa54b961c950fceda0e0914552f9ba5bdca65); /* branch */ 
}
coverage_0x0dbb89fa(0x1b70d8f6ec3760b0b916dc4eace9deb4980e59b5d5bd8076942fdb97b4870275); /* line */ 
        coverage_0x0dbb89fa(0x5f8cc7d02c2d6a7c14677ea4086631693860089ca9f1787a0733922c46374f7b); /* statement */ 
pushVal(context.auxstack, auxVal);
coverage_0x0dbb89fa(0x79a2388e1e8eb078f8e49199931e9761eba136f1b498675753915c5d62d01753); /* line */ 
        coverage_0x0dbb89fa(0x4f7c884fde791f149c022d6156a458ad26e1dc1fbdcf03865543f9f68b3fbdd0); /* statement */ 
pushVal(context.stack, auxVal.tupleVal[val1.intVal]);
    }

    function executeXsetInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xb6a435a0493eb345aafddcd03553b083206884786b269cb2d307d2566d198d05); /* function */ 

coverage_0x0dbb89fa(0x4f63219fa76c8e40bd7dd8613a1f1305e638376c223fcc66582bae29ec91ea17); /* line */ 
        coverage_0x0dbb89fa(0x31b71a572ec2246b44cafbf4b9f11bd9d0d2c8d342791bf20b905a57c091edca); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xe78f676737e3e07fcbbd0926badb59aa87c35f5afa4f97b7711472a29f775483); /* line */ 
        coverage_0x0dbb89fa(0x3b283b83216a018d3b0e7a68a84aa32e7f09bcf965db758cf946f5f46dc9d980); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x9a1d4cb7e837545a8d54fa4454225fcf3d2850e9663a09b6bd4539132462d547); /* line */ 
        coverage_0x0dbb89fa(0xb69d3c7566b04dd5990c8c099a881adfdd7ac41e4777ccc440c7d6bfc160c518); /* statement */ 
Value.Data memory auxVal = popVal(context.auxstack);
coverage_0x0dbb89fa(0x41f5785dab1d8495ce425e28fc069ae82a39b9cd83edde5ac2caf1fe61f8dc57); /* line */ 
        coverage_0x0dbb89fa(0x54d2358a0dde1d3287f3de6205f2c345c299812f4ef3afc3a1334f6a6352765e); /* statement */ 
if (!auxVal.isTuple() || !val1.isInt() || val1.intVal >= auxVal.valLength()) {coverage_0x0dbb89fa(0xf632a6e953da14e260acf688d387a61282911c4d71f9f1407563d31cdc0cd7a3); /* branch */ 

coverage_0x0dbb89fa(0x2094b72af0b3f307fd8851f2522dbb4898baa127a6d873482cd8a75dce2287c6); /* line */ 
            coverage_0x0dbb89fa(0xb754b054e1fa860e1b10546392442d1335640f94b9a1f25ea72873bed1231390); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xc51ec69ae2d76f86b1935a639afcc51a6f3e44aaac748ad676d71a4874ecbae7); /* line */ 
            coverage_0x0dbb89fa(0x39c62521cced991aa1bf772604a86d927615b900d21167e43c1bb7a9dd7aab5f); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xa95bbeca1686cb43c01657aa67a579f690a86846b80821efca5d0a65f8cafa42); /* branch */ 
}
coverage_0x0dbb89fa(0x6c4eae577c989b96fc16504e241cf7a57604885e4eb054fe616a0c732b84cafb); /* line */ 
        coverage_0x0dbb89fa(0x03cb9a0867fbace3c8436e235aee08fae76f07d5db4bfb4c127fc94be89c964c); /* statement */ 
Value.Data[] memory tupleVals = auxVal.tupleVal;
coverage_0x0dbb89fa(0x1e7afb70d5fd27f17314de4ddf9c9b61b1a47ad4885388720a9d143cccd8671b); /* line */ 
        coverage_0x0dbb89fa(0xa28f784b60decc31c89f480e48532a0d0b1cdbfc14ea09bb26527f913542e34c); /* statement */ 
tupleVals[val1.intVal] = val2;
coverage_0x0dbb89fa(0x7de1f7e90d95e0b4560c5053a345efeeaa7aaa97c2174c6a519480b83c35e270); /* line */ 
        coverage_0x0dbb89fa(0x15aca6e8dcdfead60c7a2e391dea1d58eaabef659cdb9c5184ee445f351ec9e4); /* statement */ 
pushVal(context.auxstack, Value.newTuple(tupleVals));
    }

    // Logging

    function executeLogInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x0bb66f032ad5d12a4a2719478ed07ca29b4ddb841e8df8a7bf380a1d471a744a); /* function */ 

coverage_0x0dbb89fa(0x0de78957cfae50b8bdbe5c466e8c45a1ed452acbe3c227a79f357d3b63002561); /* line */ 
        coverage_0x0dbb89fa(0x31be1200347b11f5fe0117624a778e2c42f79acaf8b53c398b1ba9662f36b5f7); /* statement */ 
context.logAcc = keccak256(abi.encodePacked(context.logAcc, popVal(context.stack).hash()));
    }

    // System operations

    function executeSendInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x44f45793d5a15be48cbb73cb4373aa661b210fc93ac0c856f3f3c03ab86ba6a1); /* function */ 

coverage_0x0dbb89fa(0x5867bcca5cda79767c5721c7545f2e23be050db05a222761fb1d2a1b374ecd25); /* line */ 
        coverage_0x0dbb89fa(0x1178b446d2d31e8097cf6e3f16b9fa4a6a3eb1a9ac9831bc5144061a5bb3eeee); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x60035d9a05548357bbda843f461165e24dffb51c4045e6f602fa2970e197eead); /* line */ 
        coverage_0x0dbb89fa(0x0fb8dc6b04ef11ba05acd6633676ce455656d35b8c72fefe2259329346e20557); /* statement */ 
if (val1.size > SEND_SIZE_LIMIT || !val1.isValidTypeForSend()) {coverage_0x0dbb89fa(0xdda162a2fec2a0b8add1694ddc685eb303d82a3c6b0ee5c66a09e65e2e952155); /* branch */ 

coverage_0x0dbb89fa(0x71657d6cdc2bf077bef0c60f720acde251dff504131958495906d189c1a64239); /* line */ 
            coverage_0x0dbb89fa(0xc6a993a9b23d306f650931291a31ffce45ba46ac0f27daa85500931d8c8a9fae); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x1ed21b0dd839cce68dd9f80cb0dca8b54b86dfe8a7d108f48150776ad3abacfe); /* line */ 
            coverage_0x0dbb89fa(0x58922a7ef8c46ca8967fbe12903a233f79072b4ebe81b4ceac4703c4c06c7543); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xd08bfe37e6c78c47950dae7db385c0b07cbc4ef5b77d6c0a1ecf0742853e7079); /* branch */ 
}
coverage_0x0dbb89fa(0x57fb17b69339635ff6373210c3163909642e063ee083375668b7461cb573a0fc); /* line */ 
        coverage_0x0dbb89fa(0xe373ca054b28634a19f3aa8313398e52b7d8dc171e2a874fa81c1d2d84ce5b05); /* statement */ 
context.messageAcc = keccak256(abi.encodePacked(context.messageAcc, val1.hash()));
    }

    function incrementInbox(AssertionContext memory context)
        private
        pure
        returns (Value.Data memory)
    {coverage_0x0dbb89fa(0xce0aa790424082c24b1b081b7b939c917a51ac45420338733d5644f31bb9ff97); /* function */ 

coverage_0x0dbb89fa(0xd65c624ff6af461ed02af33d14470b36bfa753cc30f027603da91487a6a6ac6f); /* line */ 
        coverage_0x0dbb89fa(0x06c5016b66e8ed61e2b81dc50688fb0dd991d927af3c19e952077a82bc99dd33); /* assertPre */ 
coverage_0x0dbb89fa(0xfc0bd766da8dc2244f8e9157844ad7b150ef5008d809fe665b5f8e4ee0863ae9); /* statement */ 
require(context.inboxMessageHash != 0, INBOX_VAL);coverage_0x0dbb89fa(0x8bd0c90a830bb6bb4c405fa5bb4d96b8eaef4228b865225e779ba46fa23bb420); /* assertPost */ 

coverage_0x0dbb89fa(0x1f57f519c250938c3a8524bf93d3d790098e5db1365cb5712ac3c078ee0b57bb); /* line */ 
        coverage_0x0dbb89fa(0x2f63a963ff8ef6909a785f9cb92c2575f5b2f59652ebfcb515a58304c7465a54); /* statement */ 
context.inboxAcc = Messages.addMessageToInbox(context.inboxAcc, context.inboxMessageHash);
coverage_0x0dbb89fa(0x4189eda1ea390e2b749fd5d763f70445425bd92da751b69aca355530640ba5fc); /* line */ 
        coverage_0x0dbb89fa(0xb080dd252bd39bf52665ded6e48f051d66578411a8fd89ab965647f9f13b394c); /* statement */ 
return context.inboxMessage;
    }

    function executeInboxPeekInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x5e8555d256015a34b7d603724f846ecd4959557a9a92838c9880290ef8bbc461); /* function */ 

coverage_0x0dbb89fa(0x4b9ebb28ce81b16dfbc9e6fc0ba74d94324e1a247bd916e24fe9d4d26a6e0d08); /* line */ 
        coverage_0x0dbb89fa(0x287a51b330cf57e30d44e4544ec4c5962165d4384f9f71d60a4165ea0596cb50); /* statement */ 
Value.Data memory val = popVal(context.stack);
coverage_0x0dbb89fa(0xb34ccb421736b9b8da31e9ebc33d639bfbe76f7bbd40ef5e8a4e95a74abc0f7d); /* line */ 
        coverage_0x0dbb89fa(0xc4894013192f20541e82aca6ca1e60b8431d6ede9ad4859501461ae44bb47617); /* statement */ 
if (context.afterMachine.pendingMessage.hash() != Value.newEmptyTuple().hash()) {coverage_0x0dbb89fa(0x347d6b6097013a845e432b2eb8cf90fefeb7ea084cbdcdd72a23104be97710db); /* branch */ 

coverage_0x0dbb89fa(0x6d9ecd2e318629044b909c08392666fd6cc5e7781eb16221debf622878c58758); /* line */ 
            coverage_0x0dbb89fa(0x61a02e47bbd0691f3e6b544bc6d8dd70b7942e94b49b975d60501ada623e0b9e); /* statement */ 
context.afterMachine.pendingMessage = incrementInbox(context);
        }else { coverage_0x0dbb89fa(0x3b4c35c79ae3f28ebe5cba9299819e50bade81114ea27b780b8bd21353b73446); /* branch */ 
}
        // The pending message must be a tuple of size at least 2
coverage_0x0dbb89fa(0x0ce768127420bbc9309b03a0c47ea626f618aa50c40527c51e647903d2ca6639); /* line */ 
        coverage_0x0dbb89fa(0xe09c8cdd1caec4207234b3066a6ddbe809cd411fe8bdf2e896222e6497e10053); /* statement */ 
pushVal(
            context.stack,
            Value.newBoolean(context.afterMachine.pendingMessage.tupleVal[1].hash() == val.hash())
        );
    }

    function executeInboxInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x9165788ccc86f07ad0770b5e524bc27ae65407606410de71f8eedcbc0f7787d2); /* function */ 

coverage_0x0dbb89fa(0x4bf149d65f35258970294f0196708730256c3195061a9003e46af77ef41fbdad); /* line */ 
        coverage_0x0dbb89fa(0x623f032f19e30bb670f4dfcea9395d049b90215ddf006affd94b4ab96d936d3d); /* statement */ 
if (context.afterMachine.pendingMessage.hash() != Value.newEmptyTuple().hash()) {coverage_0x0dbb89fa(0x4cdcf826bb28dad2f2c8d504ad4b0acfb574fa6afcfef9a53eea5772faa35a38); /* branch */ 

            // The pending message field is already full
coverage_0x0dbb89fa(0xcd57940ac0189e932c4b7a02a2e2aea35181267a509befa8dedbe92d7eda811f); /* line */ 
            coverage_0x0dbb89fa(0xb0c6f13f80ef18bb9d8dfe4129774daed7abf2c0d3b128ccd507bed3d1b3c246); /* statement */ 
pushVal(context.stack, context.afterMachine.pendingMessage);
coverage_0x0dbb89fa(0x63b37b3a5ccbf0598264bd7cf3fc5e62c83f2f6d57c57b28f77466c4b83ea32e); /* line */ 
            coverage_0x0dbb89fa(0xca703b98a5be71f65f020cbe9846aed0faf7f8a0c93a434c443a0c525e49861c); /* statement */ 
context.afterMachine.pendingMessage = Value.newEmptyTuple();
        } else {coverage_0x0dbb89fa(0x25bbe2486296d937025e83c586df6ae0c0a0237fdb16b0424c25aaf38b0b2986); /* branch */ 

coverage_0x0dbb89fa(0xe5293d961acf364459d14c1af48a0e56ab78a493475f57fac2edd8f28a41f257); /* line */ 
            coverage_0x0dbb89fa(0x86b511cf49836f41fac0379ecbed70b26c9ef4409054b87d9bda7dcbcbd7b317); /* statement */ 
pushVal(context.stack, incrementInbox(context));
        }
    }

    function executeSetGasInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xbb1f3ec131ff2aa33a78f70e1da17780eb3bbbd399768a28237db6b7cebfc939); /* function */ 

coverage_0x0dbb89fa(0x56c1d86de883f8f8794378fbbd7f58589aaa211575d05f31aeb3acba8f27273a); /* line */ 
        coverage_0x0dbb89fa(0x185238e5424c2a99e2798111b4ba584944b290a7d3f82d7b030577dcf54d8f20); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x7640a6118ef8a94bcf9f04333b9c80b7e4dad9d31be4110c6df2899338db0073); /* line */ 
        coverage_0x0dbb89fa(0x44cd61725b7ca19ed37eaae9594f838046448a760331cd712101f8140b6323b8); /* statement */ 
if (!val1.isInt()) {coverage_0x0dbb89fa(0x7ff82c3574890c05f73e199962d9fb18ef2c23771928d02e77cfbd753cf7d447); /* branch */ 

coverage_0x0dbb89fa(0x6177e1504e1f185d30e7ff238b50d0e01b4e9c86b53016846b0ede45d52b60ac); /* line */ 
            coverage_0x0dbb89fa(0x96cc45501256adefff50d02d1ca5efe5409718b451bfa1620680b1ba4dc92bef); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x3a002bcb9e7a1c8d5e69a161299de9e915b9c633b77fe7c8d66fa846a658d1b1); /* line */ 
            coverage_0x0dbb89fa(0x76f7a55f0552d5694458d51980651308645a3dd4b1814f685eaa589469f6aa37); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x76946a77d73e7e14239ec25638783d0e47baa5e0ed56cc0680a06f040fac5607); /* branch */ 
}
coverage_0x0dbb89fa(0x4381e3122c8e9e0649e958453b3639a8fa400840f0b6b9b7600c4e56bb6928be); /* line */ 
        coverage_0x0dbb89fa(0xca9f9cb0eb4078d8cd6d835beb1a07e58e1aebf7dd00488c4ced4ee76816715e); /* statement */ 
context.afterMachine.arbGasRemaining = val1.intVal;
    }

    function executePushGasInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x83c754ed97e3f3ce01d09c972a66e327ed71edc6265011fff71e6809687c4221); /* function */ 

coverage_0x0dbb89fa(0x376a05cf5a0009ce0254b5a30e31182e66de622e181b12f9a33b5162351885c2); /* line */ 
        coverage_0x0dbb89fa(0xd3716c4416ad218bde671c87ff2949581aa455131d3925858a5649a4e0e492e0); /* statement */ 
pushVal(context.stack, Value.newInt(context.afterMachine.arbGasRemaining));
    }

    function executeErrCodePointInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x313ca40cc6c6407ca4ef62401f378c3f219e99c02a31f91bd170c23c67c631c5); /* function */ 

coverage_0x0dbb89fa(0xa621c7b6f0e5b379058e173e3eb7f57c21d65db50f877edd1424a448e7425e5c); /* line */ 
        coverage_0x0dbb89fa(0x38673488d16e1c7380dd73aff7333dcc74c26f1188148d4853d1e1791825e0aa); /* statement */ 
pushVal(context.stack, Value.newHashedValue(CODE_POINT_ERROR, 1));
    }

    function executePushInsnInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x9694802004e63dba15d65dc71d66c06f66aecc1142be8b91ff1a07235f1e8860); /* function */ 

coverage_0x0dbb89fa(0x6a6b4092a168003cf8540622f28120c45d1cfbce39a01e79a09450897d40922a); /* line */ 
        coverage_0x0dbb89fa(0x4a41c6142459575c7ada61b00dc12359dbe7275dc9f5329949b0430cb5e63a9b); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x6150b1a4ca808936e729d63a5aba79dbdb16ace34e51ea0a43fa93e4b88c0a54); /* line */ 
        coverage_0x0dbb89fa(0xfaa4acc01017e771c30971a100c66f4628b0e01ccbdbc4d2ac043540bfa3ea3e); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0xa8e7f8ebf7400082ad309357248d6835cedaa7bc89893e681be0c798817f9e77); /* line */ 
        coverage_0x0dbb89fa(0x49bc6913eb34e453acc4dd0720b5dd1c19fabfd1e4f65417a2c9840a0b29dafb); /* statement */ 
if (!val1.isInt() || !val2.isCodePoint()) {coverage_0x0dbb89fa(0x06559a4967252b520926635a0fbd9a1ca27bd21786775a6da5414b1b11adc4e9); /* branch */ 

coverage_0x0dbb89fa(0x908e7911c43c44478d078284ff4d44e26af87705c5649f85f3b4aa1db71fef23); /* line */ 
            coverage_0x0dbb89fa(0x2b3599f997bffdc0a3148b9ae1b6071c2e34506d54d97c48400dd7b476ca338d); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x43a5528678ed9f1c77fd44b0af32fab9ff79d4a314507eb76b0f8f00c293883c); /* line */ 
            coverage_0x0dbb89fa(0xd411b93f277d5ba2bbc29c28bfe9e35896b8e1c5c6134e66811437e255c50971); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xf7f13dc91826eecb68f5a263e0216d666a6e8cda3dd1d61d5b9f8787ecec0417); /* branch */ 
}
coverage_0x0dbb89fa(0x371bf3a87de02ef49883d871ea78fa557edae9aeb510f3dc6ef9286ebee17c65); /* line */ 
        coverage_0x0dbb89fa(0x2a6d1eda907e3f6dbc67410d1884b85be36ba96b2424238be9be3c7ff0ba592b); /* statement */ 
pushVal(context.stack, Value.newCodePoint(uint8(val1.intVal), val2.hash()));
    }

    function executePushInsnImmInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xefaa555a1a0b316e8320d26d1b22666c0c18dcfb8a5bea3c109510d3095bfd5b); /* function */ 

coverage_0x0dbb89fa(0x0999a7996af605e938ed3aef977939fb163fc6f29431f5bd0f5c9726f09b83fc); /* line */ 
        coverage_0x0dbb89fa(0x02e590e16dec1d00c505657703c1fb9ac5ab13e03fc9e6ff4a5eddb77a12a926); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xd7c600bdf42a45a43ff4f77975ff933a522747f069f3286c4136448847565d9e); /* line */ 
        coverage_0x0dbb89fa(0x811bec633dff96bda07160d80946be71f6eac6732190ab681c00f2e9dacd09e1); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0xc3c2475ef4ebc1d46caa386ecf82881d41a807ef897193c33a7c484f3ba5e6d0); /* line */ 
        coverage_0x0dbb89fa(0xfda08289741be785429a2ecf524b58eea981684b4e71152bc3ff3e8c61bc003a); /* statement */ 
Value.Data memory val3 = popVal(context.stack);
coverage_0x0dbb89fa(0x1800ee4e7d01f795c9e4e094c37c6343df3379fbe209d3d68cf0e10fffb97a61); /* line */ 
        coverage_0x0dbb89fa(0xf9ba50ccb76e0c8f2d89c1d17ebd30f42c5178b64628d08b7a6dfe1794d99bb6); /* statement */ 
if (!val1.isInt() || !val3.isCodePoint()) {coverage_0x0dbb89fa(0x35238123c8795d11a135c563997e072b65cec1e3c00955d1d9bddbb5705fb0fc); /* branch */ 

coverage_0x0dbb89fa(0x698de4804706c7f59ec3254d4c6de13eb474820258cc4592031d48e29e769d07); /* line */ 
            coverage_0x0dbb89fa(0x6124378e18f687b230752676430e816351144859aecb83ecec6e2535cda18660); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x411b2f63c42794759f3256d22f7295f1ad229a571075483a4b4b0664711d8023); /* line */ 
            coverage_0x0dbb89fa(0xb60d2179226c283dfa63c62d6a79ebe0f5ea92fc40aedf51965cf447f7e4eb83); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xf1100f0a3af1202a05cc7e4e7a17522e670d86b9f01daf93d876149bb7f61aec); /* branch */ 
}
coverage_0x0dbb89fa(0x2e5bb4c0199e2ea6b21aedc5102f4f6d19713d2052c7144a6f745232829afc29); /* line */ 
        coverage_0x0dbb89fa(0x75152432f232dfb3df41dd8ee22711ff7abf64c6655a7739577881272c42f770); /* statement */ 
pushVal(context.stack, Value.newCodePoint(uint8(val1.intVal), val3.hash(), val2));
    }

    function executeSideloadInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xa2cf4b598879b33fd324a6f20e861c005cca077b1185139aecf379f21397b30f); /* function */ 

coverage_0x0dbb89fa(0xa0a1082d117015169914eb18f0ec830cdd13e33541c1b319a19e5377d00fe508); /* line */ 
        coverage_0x0dbb89fa(0x5e5887d8d71b4246d13ae2e7214ea71470548d8d12b84777df47c09abfd570bc); /* statement */ 
Value.Data[] memory values = new Value.Data[](0);
coverage_0x0dbb89fa(0x66a62adc16c3ac99a2f00ca34174407e05b2b38dacec220b1807ba0eec951bfb); /* line */ 
        coverage_0x0dbb89fa(0x5ed2f2215df9b3de7c23a5631ce04bc5f8d1994825bae482d313c5c103fa3cb2); /* statement */ 
pushVal(context.stack, Value.newTuple(values));
    }

    function executeECRecoverInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0xdb7dec049b91ecc44c796af04249b7c4023c22a883fe2233128c517644ecefef); /* function */ 

coverage_0x0dbb89fa(0x2ee37828f782ee2c3ad637b34561f07cedc52b99ffc978a9b3d9190e78831124); /* line */ 
        coverage_0x0dbb89fa(0x68fcdf024f18fba6ff57db66d1013d7b7af0201ebf03fed47e71ce08c2d09868); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0xb7a39feb97d3f1c99088b8bf42ae8e43da1ad7d7a945334b9cafd4b12048699c); /* line */ 
        coverage_0x0dbb89fa(0xca25a2d912fef6f67efcf9ba675360e1596a1a0d954f93805f4bafb5e0680103); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x4a29853f386d134be0f1a0d1aa53e4d51e0ccf9a387cec6439bcff48c288bc20); /* line */ 
        coverage_0x0dbb89fa(0xba8cbe75969c06695e3bc681afaa2189905acbee30723cbb60a85b07ad7011eb); /* statement */ 
Value.Data memory val3 = popVal(context.stack);
coverage_0x0dbb89fa(0x672d5c5523e9e9f3ea74be25a782ddf7883ca9760be49043e4eed65144625224); /* line */ 
        coverage_0x0dbb89fa(0xf25b274a92976bd760f694e5067224523e5a653d3f23718d239f8aef2a9980de); /* statement */ 
Value.Data memory val4 = popVal(context.stack);
coverage_0x0dbb89fa(0x6f3669814b08e0eb8fc9e9b63c491982d5cf041bc456131f883b1b9b7470d1b1); /* line */ 
        coverage_0x0dbb89fa(0x396bba3d83ceaacb8acb0c98c949fb2478e44b99a29199120eaeecff81fc7d23); /* statement */ 
if (!val1.isInt() || !val2.isInt() || !val3.isInt() || !val4.isInt()) {coverage_0x0dbb89fa(0x239abdb9958de30c8c15850570611b15def4b1e4c8879426c9fadbb56d6411b9); /* branch */ 

coverage_0x0dbb89fa(0x9c15177da518c12dea6f7838de8ac3be7c42d6baf5062575b5d11154c9cff8cd); /* line */ 
            coverage_0x0dbb89fa(0x705cfa95242d43c78cfccfb5dc4eb560cecd9132b4a43b69678db484d4c6f721); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x4a5830a7ae33c031f334a1187d806c23dd10cf97ce3f2b93734c2f65e683ef5f); /* line */ 
            coverage_0x0dbb89fa(0xdf692da43ccc634271ce8f3ca304192ea51df351a34e3cca4f43132813976fa9); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x1a483ae5e3487cde535e9e26ad8c13089c627c72bce70f30d9696a06150017eb); /* branch */ 
}
coverage_0x0dbb89fa(0x0f32bd20ae93ebbf732611a57ff3175fd7201677bb5cbf16f1580cd60721a63e); /* line */ 
        coverage_0x0dbb89fa(0x9f741d71c1d9aff08920a9b8986c874839642e2277fcdb1cb4e0774f6fecb07a); /* statement */ 
bytes32 r = bytes32(val1.intVal);
coverage_0x0dbb89fa(0xe841d082a7e60ace7afb9f4e17efcefc35ce41ae17ae41a0bda0932fe951a7bd); /* line */ 
        coverage_0x0dbb89fa(0x7353c397e5ddad1cade292fd6fc5d5c0a3ceb6084b145189e48b98eeede7490b); /* statement */ 
bytes32 s = bytes32(val2.intVal);
coverage_0x0dbb89fa(0xa63f640c7b5a4bf22e4a8e3866f5212a85d0c9bf942cb00533aca92b02041b94); /* line */ 
        coverage_0x0dbb89fa(0xadd9c328a7a008a084dbd005ec6db24b2dea29187fd8809fd0a3259b1b3a7a1f); /* statement */ 
if (val3.intVal != 0 && val3.intVal != 1) {coverage_0x0dbb89fa(0x0399782d4b54f083914ae18266c3791b86cc798da81496578c3ec33721b56eb9); /* branch */ 

coverage_0x0dbb89fa(0xdc19227b839eac9b8e89eda3735162846d750775dfb20e04755199dbc878e596); /* line */ 
            coverage_0x0dbb89fa(0x074c35a866d8fad7fa3cb3317420c63a32816a87f0eaeddbee1f11ea6a4133c5); /* statement */ 
pushVal(context.stack, Value.newInt(0));
coverage_0x0dbb89fa(0xa63294e17930747ffb342bd3b5d23ec94eea8e5bceecb2671bb8c4a9b0ade2c6); /* line */ 
            coverage_0x0dbb89fa(0xed6c680e5f5cb4221cf1a18be87142c87ef04f561fd90b38b6a3df95dd718270); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x578e595325789ea112b6c3910cada817a14777a7e2838365cedcc3d84f6e4fb1); /* branch */ 
}
coverage_0x0dbb89fa(0x7f8845cb7a417322c5e1960c9d1bda82f389d0fa0a04abe9058e374a956aaaec); /* line */ 
        coverage_0x0dbb89fa(0x2445fe1a0a49a3ade66c3c2ff8ffd1070d85f39da87c482eea39e0e94d70ff0b); /* statement */ 
uint8 v = uint8(val3.intVal) + 27;
coverage_0x0dbb89fa(0x39ae4a1a028d4e784649525b4319ba7a3a795b839acf6daf0c3ce9b0c9df51d7); /* line */ 
        coverage_0x0dbb89fa(0xa38cec3319a6cfc798206701c0aee1cf9de3f34fb970c63c21650d5f173a3035); /* statement */ 
bytes32 message = bytes32(val4.intVal);
coverage_0x0dbb89fa(0x8ed36137ddbcd77acd7b4a4783fa3a6410c69d812a495348c9684a1fe157944d); /* line */ 
        coverage_0x0dbb89fa(0xb7ac1f726676d391b3aa83a31f56f4c03c504d88a6126c033cc1fd6b6f931db0); /* statement */ 
address ret = ecrecover(message, v, r, s);
coverage_0x0dbb89fa(0x4083fa9a96d7fea960b4e0c1dc81c6a06280f9e45da362a18300751e996f245c); /* line */ 
        coverage_0x0dbb89fa(0x5722b13db371dff6d8b0084d9bc96e7ad63b5858385a2994cc241594e7228d05); /* statement */ 
pushVal(context.stack, Value.newInt(uint256(ret)));
    }

    function executeECAddInsn(AssertionContext memory context) internal view {coverage_0x0dbb89fa(0x834f01b22e35b86fd19865934414c3f13f1c44a712884467ad58ab28ba43a1cb); /* function */ 

coverage_0x0dbb89fa(0xaf63677325ccbe8b1a72ccbdcad0107ca7d74127d438c03024f3dac7d10275d8); /* line */ 
        coverage_0x0dbb89fa(0x9e22eb4aeaecee66adb93e208d2b931d0e91d3b7af1bf6844172a5c56ad696d9); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x0cba7c95abd911cbceb8cea6a3c918116235b732b4bdf09a664deb70f685a070); /* line */ 
        coverage_0x0dbb89fa(0xb36b943e4562b182339647e1d4d4df1879fcab3105439ed860357d65a99817f1); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0xb8dd78db144d0dfff802e9bea5790e081a6ba48df05e5ef176969da07cbe6ded); /* line */ 
        coverage_0x0dbb89fa(0xb836bf7ac171a7a4183f63705084ce58b29ae3ffb93f204c154d6e77294b71ec); /* statement */ 
Value.Data memory val3 = popVal(context.stack);
coverage_0x0dbb89fa(0x6f1d56212b72fa857c55284e363b07256fda4190e584bf0dfddf885b2c13c4a6); /* line */ 
        coverage_0x0dbb89fa(0x969fa67e93e8d1d3eaf2f5e2869c2f80777aaf4c3e3d93ea4e39c3be26f69e64); /* statement */ 
Value.Data memory val4 = popVal(context.stack);
coverage_0x0dbb89fa(0x72cb2b26d486843d33be95a380b5b516960142597d9fa4b794412e1527f5f16c); /* line */ 
        coverage_0x0dbb89fa(0xf331b88bf0140144cf3241b3a6b7c6b48fda65ee46eaf802b2a9adbef6c8fd50); /* statement */ 
if (!val1.isInt() || !val2.isInt() || !val3.isInt() || !val4.isInt()) {coverage_0x0dbb89fa(0xd491ff819a276e3167d6903bd381f11e39a10ed0c6b3a5b15451eafce6fe7e36); /* branch */ 

coverage_0x0dbb89fa(0x927cc671993553c84be8f6c96868867384b075d6e26eb1bba6d906530ab7cfae); /* line */ 
            coverage_0x0dbb89fa(0x6b6a6f974c1f3775b753df3278e67d9ddddaa1531d35dea7550b5b785d4061b1); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xef4a909c6924d1db336dc50e0789399d864f4df020eac3af6d4f8848cd246bd4); /* line */ 
            coverage_0x0dbb89fa(0x381ec53015b7a1fd47f2eec848003bcc64f140af77d66911f988d2f802a0b0ac); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x1987df8ec437515fd01475b71fc5a8d42e375a06fedaf863aa7c3251b2893989); /* branch */ 
}
coverage_0x0dbb89fa(0x018152b296e3657912060706030c9860f5e3aa21253b258536ce451e01b2e082); /* line */ 
        coverage_0x0dbb89fa(0x665862451a20b3f2c58106a0dc1aa951bb0bc30b73a0185d0a63ee79acb3a88f); /* statement */ 
uint256[4] memory bnAddInput = [val1.intVal, val2.intVal, val3.intVal, val4.intVal];
coverage_0x0dbb89fa(0x65273ffcceb3e9ddf94a3591874b3f6d687cb3311735a49749d6234237ef64aa); /* line */ 
        coverage_0x0dbb89fa(0xfb9d7cc4e137a658a736ec2088d6dce8790af075fdbbbc1c026c3090453fac64); /* statement */ 
uint256[2] memory ret;
coverage_0x0dbb89fa(0x9b4d0752fa57de6f528daec24ce43aca5475a227f46c9e56b48e10901fd3d972); /* line */ 
        coverage_0x0dbb89fa(0x901afc34f3b1e1557e32344f480bcc3999ddf63a7fba0058fbfd644cd58a3026); /* statement */ 
bool success;
        // solium-disable-next-line security/no-inline-assembly
coverage_0x0dbb89fa(0x9a9c863abf2960fcf46e3779994216c468d74c598ca5e4bcd132b0ec24363d92); /* line */ 
        assembly {
            success := staticcall(sub(gas(), 2000), 6, bnAddInput, 0x80, ret, 0x40)
        }
coverage_0x0dbb89fa(0x6c71b7fb052c68d4132d4d25b7f620935bd03e52212010d305366c81ce63043d); /* line */ 
        coverage_0x0dbb89fa(0xd206fa7295732e0fe11eb73b8a21e1c5272397fa577008ac2f301f9ebd5c1d63); /* statement */ 
if (!success) {coverage_0x0dbb89fa(0xdfdb401022174c323ddbf89af8c014b559f3858c08410adc4c730e1c36bb15ba); /* branch */ 

            // Must end on empty tuple
coverage_0x0dbb89fa(0x87e7c3c5029384b909af4fd6848cd57d41159408ff1cc8e373ae8456159ee63d); /* line */ 
            coverage_0x0dbb89fa(0xb752661d24b72c1eb70c4fde1ef6e7a39b17d457d81ace587b7d7d5179643947); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x81e640099276151acf46009d2e84a9b71e60764be726df350d4c2996424a5b9d); /* line */ 
            coverage_0x0dbb89fa(0x04856b5f8462800b942d6b8ae664a286994dc3d517237054d3fc709f7b8b3bf8); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x96ae49d183c4e557ea232be8e8a7f3336f38b5325f5caf8f6b6f6277dd45e21f); /* branch */ 
}
coverage_0x0dbb89fa(0xfae6209caeac0f1284b4b7502181cc3a439d8610adcc60146b5656b5e045e768); /* line */ 
        coverage_0x0dbb89fa(0x109af1797615e35b019c2bb543ed838c5796a0dd822c2d9233f11199248e95f4); /* statement */ 
pushVal(context.stack, Value.newInt(uint256(ret[1])));
coverage_0x0dbb89fa(0x46818a5f0a729972b5a5d9b54334f1f87c0b122a6019bd661cf994e44157c10a); /* line */ 
        coverage_0x0dbb89fa(0x9838862cb28c3ddf9918fb741ad019a0567ddde425b97d5abc882603680202ee); /* statement */ 
pushVal(context.stack, Value.newInt(uint256(ret[0])));
    }

    function executeECMulInsn(AssertionContext memory context) internal view {coverage_0x0dbb89fa(0x6fd4e1e078a37223ab702381f66d9fac03c522205093637fd280a877e6b23f55); /* function */ 

coverage_0x0dbb89fa(0x00aa7d20d5056e3652b3a57569b700b0196073d8524f3929cc52aa7e2f049848); /* line */ 
        coverage_0x0dbb89fa(0x600c0bc778de59242b822554b21d462250f12e03028d4e3490a5b7c567ce238d); /* statement */ 
Value.Data memory val1 = popVal(context.stack);
coverage_0x0dbb89fa(0x861ec4a5a479fe55a3f2363aec0c1d0a0ad408d46b67436b796ce36440a2cd07); /* line */ 
        coverage_0x0dbb89fa(0x1c312d65d8aa7247c0396c18fdca381ce4bb67cd6bf533bf6c3dad6930fb7a8d); /* statement */ 
Value.Data memory val2 = popVal(context.stack);
coverage_0x0dbb89fa(0x4b2c787d6f53ed834517d0de105f37a60c700cbc90d637568cd79e171dc398a1); /* line */ 
        coverage_0x0dbb89fa(0xca51e58d7a2c0d349194cbff8d2e9e7573d7554a23bf5b3d290ebb874bc0ae85); /* statement */ 
Value.Data memory val3 = popVal(context.stack);
coverage_0x0dbb89fa(0xeb9f47bbb076e97cf6af4765c5f07e5a6326ad369f75064dbc83b7690b98fe6a); /* line */ 
        coverage_0x0dbb89fa(0x61526678183952d792665bc88b1a607ec84eafaaf9f33a9d308926dd312c1938); /* statement */ 
if (!val1.isInt() || !val2.isInt() || !val3.isInt()) {coverage_0x0dbb89fa(0xaf59d7ad299a4d33ee17b29f9a13853ad4ba6e1c127892c3fa37df6a75e20e0e); /* branch */ 

coverage_0x0dbb89fa(0x6405b01dca1c4f0f76c3536cb6e9667bb795203c24f0c903349aa09a90e41540); /* line */ 
            coverage_0x0dbb89fa(0x008133d43252f9f90fe7f86530abd6d456497feb55a35fb9ad5f6145d49a127c); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x443c3715c85db40acc5b8c13715ef09ac1f1e0804e155107c771317b9e825996); /* line */ 
            coverage_0x0dbb89fa(0xdccf3baa041d824613ee3fc69f3350f01dc1c49be5fc9b964cedae9d649b3770); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x8833f4f9bdf3badf3ede4a0e4da94768b809dea1671ecdfbc2bce524e307d23f); /* branch */ 
}
coverage_0x0dbb89fa(0xd5b1b07982a9e8caf2d82e4225e075c342ce63607f27208b4f3d2846b5b24c8b); /* line */ 
        coverage_0x0dbb89fa(0x38ae75131bb0001939e0220412af8648344f608616e44133a1806aeb0345c4f6); /* statement */ 
uint256[3] memory bnAddInput = [val1.intVal, val2.intVal, val3.intVal];
coverage_0x0dbb89fa(0xa9e488039f2db713bc61c1e55c0a9e304ed6d83915d64cda72b8e56dcdd72e80); /* line */ 
        coverage_0x0dbb89fa(0x8e2ef414ee4a0a31745285ca33a2dd5bbcbc2f35915192c0ca91f5da595afb16); /* statement */ 
uint256[2] memory ret;
coverage_0x0dbb89fa(0x3941c6a6ed490c83b62d5536872339c3b3f960a82015cd09d51bfa63c53b596e); /* line */ 
        coverage_0x0dbb89fa(0x3b5975e8d832e2f0e85ac8c4cb35249afd0f69856f890f479f745ad7fd9d2ba0); /* statement */ 
bool success;
        // solium-disable-next-line security/no-inline-assembly
coverage_0x0dbb89fa(0xcc4ff06aa8f88abd01c7b089a09ab5694b6934ce31599fb205492d4813644801); /* line */ 
        assembly {
            success := staticcall(sub(gas(), 2000), 7, bnAddInput, 0x80, ret, 0x40)
        }
coverage_0x0dbb89fa(0x40fb0bc016d190949a738629ef4c003f1bd4f1b297853ebc0d29fe1160c82fcb); /* line */ 
        coverage_0x0dbb89fa(0x3ae76c811f7079dc5b91ef51dc84d1ea521b31f46a48a8e52069429e078aa79e); /* statement */ 
if (!success) {coverage_0x0dbb89fa(0x24e0af2bebae0375e42dd00d1e5622dc9ad38def2ce46cc97d1db0cf5263df9a); /* branch */ 

            // Must end on empty tuple
coverage_0x0dbb89fa(0x8557243cfa9f611c457268ffa4f371e82a8a1d5a2516159a512d02e33e709b68); /* line */ 
            coverage_0x0dbb89fa(0x8a411313d76fd50e9673ea67cd4a2364938176b7080939e0e32a4a4613028844); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x94d020aeb842b58d7bea378ebe3d711a045a60cc9d3e8a356cf1925135f0e00a); /* line */ 
            coverage_0x0dbb89fa(0xd915e2130728d0153b8bf3b5a123131f12d4b326e20619c35e63eb22ea728142); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x1c91c5ed3563e7fd3110f3c24478600d21d8771348f86751e8073af89629e4a3); /* branch */ 
}
coverage_0x0dbb89fa(0x7ac10f271893bb9455a62719e6347dc44b35cef55fdd8a0394e9c27439f437eb); /* line */ 
        coverage_0x0dbb89fa(0x2fa37f4d1f0b9edf3a9c68f245bcaf32ba4ca5e14f0c7d7e9345283151342936); /* statement */ 
pushVal(context.stack, Value.newInt(uint256(ret[1])));
coverage_0x0dbb89fa(0xdd118acc690a098048569ab7bd1166a6e2ca175e6e89c083a86a10acfe4a8261); /* line */ 
        coverage_0x0dbb89fa(0x13e9a3d09f4ced94d205a72cf78bb5ecab48979f9220d3a09da9e99c7021a8cc); /* statement */ 
pushVal(context.stack, Value.newInt(uint256(ret[0])));
    }

    function executeECPairingInsn(AssertionContext memory context) internal view {coverage_0x0dbb89fa(0x72c45cb2a137df863b9dfef53c40bff6f1fbb80bbfdeefe049bd0cd2b12a0c3a); /* function */ 

coverage_0x0dbb89fa(0x57408d134633f39914abd9ac77c734ef7c0975c8d8af5f17272b64a5aabd63ba); /* line */ 
        coverage_0x0dbb89fa(0x03bd4a62f422cc4de6a5b56e7d8b26d4cec0db2dee56f6982a9d3b06f9bc1868); /* statement */ 
Value.Data memory val = popVal(context.stack);

coverage_0x0dbb89fa(0x05c0e5a591a6d991260b66f68231d0a9e7a7072de882c9563bf5e1645fe41740); /* line */ 
        coverage_0x0dbb89fa(0x64f15cf5bc4fdec3ba5832b7e2920a4bc8f182f2f875a6b675fe89bfa1c53cbf); /* statement */ 
Value.Data[MAX_PAIRING_COUNT] memory items;
coverage_0x0dbb89fa(0xb29bf8bcea3fd492b6101340ed63004164fb414427d75bf630d1b02017eae3a9); /* line */ 
        coverage_0x0dbb89fa(0xbc721439d8e1721b3211b53c0bd186b620dd0bd3ecce27fa4a6fdacc0346c010); /* statement */ 
uint256 count;
coverage_0x0dbb89fa(0x2a37089cdc71edce1faee8e00a7d09da5ef7f8db3852541cb01f5f71404aeb19); /* line */ 
        coverage_0x0dbb89fa(0x805e9919a31e27a0ef6d78600fa9ca4beec4e30245a5d69e4244cd43e319b8d7); /* statement */ 
for (count = 0; count < MAX_PAIRING_COUNT; count++) {
coverage_0x0dbb89fa(0xb162b6b114f110f7247c2394fc9531018dbd043237a69dcd1e090001c6a91eba); /* line */ 
            coverage_0x0dbb89fa(0x93aedf032245c391b017bc7899a07c26dcfd05ef3f7f4777176b9d7cc6542d0e); /* statement */ 
if (!val.isTuple()) {coverage_0x0dbb89fa(0x63cca5e67328df32fe472d210682bfc9611c47c47b1590bc47f99ae3aa564398); /* branch */ 

coverage_0x0dbb89fa(0xf00c3539b24f62fb526ee0ebb72bf87d3b95de00711f822e1ee5c58a8e2183c0); /* line */ 
                coverage_0x0dbb89fa(0xd91fe4ce8c995c8c0bfc2f9167b2b8cc39ec747027c2c1f04977284d84056f1c); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x494332908fbc6a8c6b52aefa7fb70668b8ae6cafae9f2f9d92ed0b99f7ed6ecc); /* line */ 
                coverage_0x0dbb89fa(0xce10e16a3a3685e79ecd2704e9584c99fa9b7923cd945c9f8dee09006d5f0b77); /* statement */ 
return;
            }else { coverage_0x0dbb89fa(0x3b784756134c9b40cc714dd07813b12f45afa322fcbb6cf1139555e4281647a5); /* branch */ 
}
coverage_0x0dbb89fa(0x797bf75245f72a4179ff6502f4d697f9d2d8d4178a60aebd23e08e1cf34a85f7); /* line */ 
            coverage_0x0dbb89fa(0xd7f57e76a0a559d6c716c35721523f55f16483642de3d1603f35a4db7b710461); /* statement */ 
Value.Data[] memory stackTupleVals = val.tupleVal;
coverage_0x0dbb89fa(0xe5f34befeec7f6c1fe2afa3362bc2652dc1f749b0e47bd67bfd1147e021ec6b1); /* line */ 
            coverage_0x0dbb89fa(0x371dfd8d84df2d1385b86580879fa079c697668a33f58cc537b06c66f7378941); /* statement */ 
if (stackTupleVals.length == 0) {coverage_0x0dbb89fa(0xeaa943b31616481fb8c84a5cfc612abb3b6133267977168dc41da9ef86fef1ea); /* branch */ 

                // We reached the bottom of the stack
coverage_0x0dbb89fa(0xd10839518c7136a713b4ca134af75fb6b393592b71a472c2bc18c7e5ae957537); /* line */ 
                break;
            }else { coverage_0x0dbb89fa(0x92345936598ef8d654fb15b3552012641f6050cf7e1d0217f75a2bf6b7e4e151); /* branch */ 
}
coverage_0x0dbb89fa(0x6d8f27ece4bd9dea83f36d66ff81bd44c716d5c29e42b02eb466bfa49cf04b00); /* line */ 
            coverage_0x0dbb89fa(0xfb82197043b448e9ff99109310cfdb07662bd6c858417a2c61903870610c1dea); /* statement */ 
if (stackTupleVals.length != 2) {coverage_0x0dbb89fa(0x4712898bcda3b514a86f8c02c7255dde91019cfc355c8f4cb928c23b68cbd09b); /* branch */ 

coverage_0x0dbb89fa(0x3df3873ba7f34d599164dba2790fe0c4efd8a3488a9e44a869708b4cf6d04dfc); /* line */ 
                coverage_0x0dbb89fa(0x834e21b4e36305ea2eca8e5568989968c50469f4b7fb73cd3a077e1c79a3a391); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x874bf479871b9cc699e958a9383e49d2c1c1dd6ce3ecf2ed1c55097ac6fbf6ab); /* line */ 
                coverage_0x0dbb89fa(0x9dbc258697698fc19a260da1f6c6938b06b1af632be916f0d869f438a4418fbe); /* statement */ 
return;
            }else { coverage_0x0dbb89fa(0xa8603024641604155251c33c9fd354d0ca8e29aeceed88d022beec72930fa451); /* branch */ 
}
coverage_0x0dbb89fa(0x6ec91950213d8c4411dc4bf0655b9e344dd097ffce8a6f42d84771f85c156156); /* line */ 
            coverage_0x0dbb89fa(0x3ccbb4e22dd8ea1f2ab37793965ffa9cd79fdc6db119e1458a2d36b0a77b6d9e); /* statement */ 
items[count] = stackTupleVals[0];
coverage_0x0dbb89fa(0x2c687adae2beb31ae88d89b05573ae045eb97d5c5d82cc1a7b3cb43afc63eb90); /* line */ 
            coverage_0x0dbb89fa(0x7a040da37cd4ae6eb2e096bc023326abbda4716e9d07d0d76566c2c8a06e8ac8); /* statement */ 
val = stackTupleVals[1];
        }

coverage_0x0dbb89fa(0x25a800b7cd0a423015b172e6f156513bd46bab5f1d07667e7cac841fd5bd3c63); /* line */ 
        coverage_0x0dbb89fa(0x1a0e6fb8762f50281da117e75cbfe426c08860d2bea57456b279b2e04c96785e); /* statement */ 
if (deductGas(context, uint64(EC_PAIRING_POINT_GAS_COST * count))) {coverage_0x0dbb89fa(0xb2f3edd9ced7836f31314e748bc24cac6a59510bad149aeef9042238a45dd7d0); /* branch */ 

coverage_0x0dbb89fa(0x5e10701b17e352bd6346b29d6a3ea2fcb3d529bcd84ec4c70f814740be80f930); /* line */ 
            coverage_0x0dbb89fa(0x0ed8851088dec9ebdf27bc8402ce56b000b463ca9b9bae78f2152ea589aaa2c2); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0xdd507f2c1525a6ebb5e3ce0f2efe9a73094a7fb71be7a37830981a2813cffbc5); /* branch */ 
}

coverage_0x0dbb89fa(0x43d6878faf336409e475396033503bc8f927abd69ddd7366d0b175b7a6e6ffec); /* line */ 
        coverage_0x0dbb89fa(0xa525ae055fedfa813ce69c487f71d0f2189a2a5e3dd04e1f76973961b0623316); /* statement */ 
if (!val.isTuple() || val.tupleVal.length != 0) {coverage_0x0dbb89fa(0x224a2e5ab0bf1780848b033f151d0684a131071fc2280f6a9e6e5349cf223873); /* branch */ 

            // Must end on empty tuple
coverage_0x0dbb89fa(0xfae737c0d9e7367a1cd0bdc5f493c44665bdc1c246cada0fe1ae0a06b153fc33); /* line */ 
            coverage_0x0dbb89fa(0x6a9866b4ea06692295aafa8f2713d03fb757a3cfa543fa8b7c70584c7bf145ab); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xaeea21d25489fabc593fd139cd9e9f8d42e2e25aded056a8dc1a0c8cf5eb7ce9); /* line */ 
            coverage_0x0dbb89fa(0xd24011e4a1eb7f38e86666b789987f4f77ca07d55684aecf188a3efb7a69f0f1); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x2dd0e5a4f81ff46e376ccea370b1e928afefcf63a7bdf433f6b9571fd8f86c95); /* branch */ 
}

        // Allocate the maximum amount of space we might need
coverage_0x0dbb89fa(0xf64e1a7f1f6eb31309b30742cee2465d66c513b817aa7eb3de08946227228c3c); /* line */ 
        coverage_0x0dbb89fa(0xf9e5ee58b90d8defc4a0be93ba606afafc3f13961d33f8785bf3a7326f32cbaf); /* statement */ 
uint256[MAX_PAIRING_COUNT * 6] memory input;
coverage_0x0dbb89fa(0xeb13dd812f1c897240f86078e3e516f40a86eaacc9444671bf0bf591c68f6b32); /* line */ 
        coverage_0x0dbb89fa(0xd49ed7f7290355f809940575e37aa758f0a325fd441910e918469f5fb9144e1b); /* statement */ 
for (uint256 i = 0; i < count; i++) {
coverage_0x0dbb89fa(0x87c1b0eb2ec91f4527f667f20a4e88414c083baa9a2e0ba1bbf1bac89b84487c); /* line */ 
            coverage_0x0dbb89fa(0x62f9c03f4a5685e8b5e69c71615d08130d60ee7121374b4815dac95c31567960); /* statement */ 
Value.Data memory pointVal = items[i];
coverage_0x0dbb89fa(0xdbaddb15b8c6bcfd846e1fa55a37a29230bc4cec035ad03faf48d121fff92863); /* line */ 
            coverage_0x0dbb89fa(0xdf4ad020c3e5fe3a3e2b17cd62ce82b4f4bd4c24b6f22d11731decb8ff610237); /* statement */ 
if (!pointVal.isTuple()) {coverage_0x0dbb89fa(0x75ade5e82e55917c037698ea9aa47e50eb168d0cddda78b7c642f56b0b3b0335); /* branch */ 

coverage_0x0dbb89fa(0x9b56ecdf47dc8f6bcf977aa695cb47283aeec1d9fa51d8f812cbf4541825badb); /* line */ 
                coverage_0x0dbb89fa(0x015d4eb31a2c72bcae20aa74f07f2f5fc3765d635eff4f1bd0682985d4f0b9ab); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xfb9e4f7f7032722a213128e3c1bff22dfa10d5bea824309d382efe137b2c7d98); /* line */ 
                coverage_0x0dbb89fa(0x7617414a969fdc516ec6bfa4e4b2dfb865493813a6ae3415f926bd47d394ffb6); /* statement */ 
return;
            }else { coverage_0x0dbb89fa(0xe7f5d6dcaeaf5687362b1562d735cba02673b19645314b8d42163ed130bc8324); /* branch */ 
}

coverage_0x0dbb89fa(0xf085067b2aee4b1c00cdd55a63076d696808964e19b078ef7350666babddaabe); /* line */ 
            coverage_0x0dbb89fa(0x830597dd6522d998431f9947a5526a491bf21ec265a0538c3b728747aa8c7f63); /* statement */ 
Value.Data[] memory pointTupleVals = pointVal.tupleVal;
coverage_0x0dbb89fa(0x10a2b0ff7fc4849d3dafa90f6f13f85e4562a78b291fe756a9ca710cc170eefc); /* line */ 
            coverage_0x0dbb89fa(0xaee45c2f46625e438616725eeea03d3452fd9b980e7368e968eff6bcf6df5752); /* statement */ 
if (pointTupleVals.length != 6) {coverage_0x0dbb89fa(0x1b883947d7fd1f99b3d19759ce8e61415534003ea82182a63f2a031913eef543); /* branch */ 

coverage_0x0dbb89fa(0xc9168c50db2b33f6cfc2fe0bf5382285de3d7edbf5b2c085d68264af066a8821); /* line */ 
                coverage_0x0dbb89fa(0x31d5431a188cf6772d6b7ba33964230e94b83d6fc2da6270a69a2f5fea2c455c); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x73fe35ee37af87b8a2d964ffeb341cc5b609af79bddaedd3034ece4ebb341d75); /* line */ 
                coverage_0x0dbb89fa(0xf063bc111b1b0586ac6828af65be53907662843f284493a5eed2088f1b2f0f8d); /* statement */ 
return;
            }else { coverage_0x0dbb89fa(0xafe326b726fd5d4375f7e0d66658cda18f223c14474179e716efc6e673d0b41a); /* branch */ 
}

coverage_0x0dbb89fa(0xf81a001ad0f5b4a844a881933372735e59914f7bb86c8e9d7e9eda18462e0e16); /* line */ 
            coverage_0x0dbb89fa(0xb8ea8e02c109b7dc2f37b9230fcce7af99cab7b2992bb1b54473a59201bb1813); /* statement */ 
for (uint256 j = 0; j < 6; j++) {
coverage_0x0dbb89fa(0x7d72373c00dde20a94265ee12b0de0c25c52fd060a32d165b8970ca7ba901c00); /* line */ 
                coverage_0x0dbb89fa(0xe16cf150ba9f4208b94a3331ca4786fdae514295ea8610a6202689e00f843d3e); /* statement */ 
if (!pointTupleVals[j].isInt()) {coverage_0x0dbb89fa(0xd9e2519358535fc309fcebe56d15021c041f97a19d9a2ec9eecd7b918e09e2f7); /* branch */ 

coverage_0x0dbb89fa(0x5750e29228cd64471660a5c7b62195208088325eb3abec76b69502d6e48f7ed4); /* line */ 
                    coverage_0x0dbb89fa(0x8bb131040dcbc593b9f23048d30bcab4bb639ea7c12c3ead75c6288fbc86e8fc); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0x2d566c07cfd789a9e99f2a172229d6ec8028d742f8bdfd3f0eb579796816ed3d); /* line */ 
                    coverage_0x0dbb89fa(0x366affb87211a522b5e12c22f9f6008e09c61d38e5c5126cacf8dd1a21b0e05a); /* statement */ 
return;
                }else { coverage_0x0dbb89fa(0xe9a22e3b94834a5412685fa883983e915658fa2f04eb90ba17a9f0920da10c6e); /* branch */ 
}
            }
coverage_0x0dbb89fa(0x2b548bef820ebb900e69e932c703ecf27d02b1e9da877f842472285a306a7948); /* line */ 
            coverage_0x0dbb89fa(0x59dbf1f3b746d4e53866419f4728ddb423bee9f1329557f0b952fd611ea04d55); /* statement */ 
input[i * 6] = pointTupleVals[0].intVal;
coverage_0x0dbb89fa(0xe5235a81966def71bc80e03237762bec39ee978e90fe67c444d2b87e9b37d7f8); /* line */ 
            coverage_0x0dbb89fa(0xea8c5f1836dc2b2cb5e09d4d576bc4c81eba551d2d0478d4f492d122002225ef); /* statement */ 
input[i * 6 + 1] = pointTupleVals[1].intVal;
coverage_0x0dbb89fa(0x8a2432371c2d12f7326bc2f07bcd9efe69f8bf161918d7a614068cd74404641e); /* line */ 
            coverage_0x0dbb89fa(0x2a17f3770792be5655fd9d570bdea195c1c0a7ba1110be3f2beb10e61dc4d70c); /* statement */ 
input[i * 6 + 2] = pointTupleVals[3].intVal;
coverage_0x0dbb89fa(0xd7dba5031158f9979b2deebc4369e1f0b0d37e33fdbb3442ffc91e482e55bf96); /* line */ 
            coverage_0x0dbb89fa(0x18ee3d6a30a3268e52797e557ecdab542cd3cd81296913897c032ca361acd2c9); /* statement */ 
input[i * 6 + 3] = pointTupleVals[2].intVal;
coverage_0x0dbb89fa(0xa8e5cd618f6778b1aaa4fdb9d0c5cabe51296296a968f18d7f85907f03c84bbc); /* line */ 
            coverage_0x0dbb89fa(0xe302824e0974b0f05ea54dfb8a2d0743f94a8e82a7d3526059e3dc4d6bea7f6b); /* statement */ 
input[i * 6 + 4] = pointTupleVals[5].intVal;
coverage_0x0dbb89fa(0x543d630253fe40272605bdd6667ab9eb9c7bc0ea9a54821efb415fa468ae916f); /* line */ 
            coverage_0x0dbb89fa(0x8eaf13b0e5a6a793c95bbcdcd806e72002e81e194b793112de02e8e374030966); /* statement */ 
input[i * 6 + 5] = pointTupleVals[4].intVal;
        }

coverage_0x0dbb89fa(0xb74c5512ba4ac4750c82eae94ee3a6a1abd8fda16a68a9e6267fd61f316d5b28); /* line */ 
        coverage_0x0dbb89fa(0x4bc021343092a5080c824e338b690f0abcd39546f7aeb02169186f1084904084); /* statement */ 
uint256 inputSize = count * 6 * 0x20;
coverage_0x0dbb89fa(0x35298ecbcd8a590dfb70cfad298b107c1b4fa554f37363dadf362856cd33f719); /* line */ 
        coverage_0x0dbb89fa(0xb06bf94e168cf6df55a067647e52cc9bf617c8310b62972a53db51ff0fbe27eb); /* statement */ 
uint256[1] memory out;
coverage_0x0dbb89fa(0xb12b69b7a1c07f99fcf2b997e4a4a1377bc36a7f158e9638e75ed6eac3cf91c2); /* line */ 
        coverage_0x0dbb89fa(0xe9a257ea900eb20b077b21bc42461fa5a8dd4dd1f2035533ec8678688ce29482); /* statement */ 
bool success;
        // solium-disable-next-line security/no-inline-assembly
coverage_0x0dbb89fa(0x8a5325088cd021342fc258030ab1a1450c5764fb9af30128aff132aed8a16d51); /* line */ 
        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, inputSize, out, 0x20)
        }

coverage_0x0dbb89fa(0xf94c8d2d59f1b18b332f890ff40593097248af6e61990df24dca081b368e8c3d); /* line */ 
        coverage_0x0dbb89fa(0x4de07e92d43f912f409ceba18242d1f37d461a7ab5ffc066117ea4641a951219); /* statement */ 
if (!success) {coverage_0x0dbb89fa(0x013b857affd9e97d577956c43caf464283ca3464bd4647c05be2b573b2068e93); /* branch */ 

coverage_0x0dbb89fa(0x8665fbac578abcab4f0c6a220681fed12e78032eb0694ce5b0c9d5e15939a29f); /* line */ 
            coverage_0x0dbb89fa(0x974da7f81f92a4f41c095640ab7082281f54291c6b25f3068fa93d02484857eb); /* statement */ 
handleOpcodeError(context);
coverage_0x0dbb89fa(0xc28a50494dd5d01306a8585ecb4482ae11e5ee3a87793427dc294f297f30b133); /* line */ 
            coverage_0x0dbb89fa(0x82b9374de99137c66997e7398f1276770f7eff0c690efd385fd0fea738bf2db4); /* statement */ 
return;
        }else { coverage_0x0dbb89fa(0x033d8f117defa2a1ffc12c75f1dd2881b8ff6237a9331c19be5e7747dee54f16); /* branch */ 
}

coverage_0x0dbb89fa(0x87e37b59e08280a31539d62c391c799737fd92f503d68d4ea67e6b7892877497); /* line */ 
        coverage_0x0dbb89fa(0xc4528e84a393c286c778aa31a54fea7386bee4a974be94c982e29230df2b03af); /* statement */ 
pushVal(context.stack, Value.newBoolean(out[0] != 0));
    }

    function executeErrorInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x96f1d31abd23f5617d093e208d2365ca49b8cfd17a9b041cb4d7ca639d60c865); /* function */ 

coverage_0x0dbb89fa(0xb7b0eee4e0c3ded72e33ad9bd96b982ac7274282fbab102f309219baa28ee7db); /* line */ 
        coverage_0x0dbb89fa(0xc1f744cbabc696c9b20aa15223cf074a7ff870bb9cb5770b1511a34013e71810); /* statement */ 
handleOpcodeError(context);
    }

    function executeStopInsn(AssertionContext memory context) internal pure {coverage_0x0dbb89fa(0x1e4a87d525a881d5218a55272cd122de60eb2b1db0cc9dd2c63cc9864434ce13); /* function */ 

coverage_0x0dbb89fa(0xa83b6a4ce28c7c676cd4927196762605b7530fe645d9e67cdf1df27df0445843); /* line */ 
        coverage_0x0dbb89fa(0x374ce60986dcf0813f7348a5acfb0e7b9c032d434716bbee352b414d950a2c4e); /* statement */ 
context.afterMachine.setHalt();
    }

    // Stop and arithmetic ops
    uint8 private constant OP_ADD = 0x01;
    uint8 private constant OP_MUL = 0x02;
    uint8 private constant OP_SUB = 0x03;
    uint8 private constant OP_DIV = 0x04;
    uint8 private constant OP_SDIV = 0x05;
    uint8 private constant OP_MOD = 0x06;
    uint8 private constant OP_SMOD = 0x07;
    uint8 private constant OP_ADDMOD = 0x08;
    uint8 private constant OP_MULMOD = 0x09;
    uint8 private constant OP_EXP = 0x0a;
    uint8 private constant OP_SIGNEXTEND = 0x0b;

    // Comparison & bitwise logic
    uint8 private constant OP_LT = 0x10;
    uint8 private constant OP_GT = 0x11;
    uint8 private constant OP_SLT = 0x12;
    uint8 private constant OP_SGT = 0x13;
    uint8 private constant OP_EQ = 0x14;
    uint8 private constant OP_ISZERO = 0x15;
    uint8 private constant OP_AND = 0x16;
    uint8 private constant OP_OR = 0x17;
    uint8 private constant OP_XOR = 0x18;
    uint8 private constant OP_NOT = 0x19;
    uint8 private constant OP_BYTE = 0x1a;
    uint8 private constant OP_SHL = 0x1b;
    uint8 private constant OP_SHR = 0x1c;
    uint8 private constant OP_SAR = 0x1d;

    // SHA3
    uint8 private constant OP_HASH = 0x20;
    uint8 private constant OP_TYPE = 0x21;
    uint8 private constant OP_ETHHASH2 = 0x22;
    uint8 private constant OP_KECCAK_F = 0x23;
    uint8 private constant OP_SHA256_F = 0x24;

    // Stack, Memory, Storage and Flow Operations
    uint8 private constant OP_POP = 0x30;
    uint8 private constant OP_SPUSH = 0x31;
    uint8 private constant OP_RPUSH = 0x32;
    uint8 private constant OP_RSET = 0x33;
    uint8 private constant OP_JUMP = 0x34;
    uint8 private constant OP_CJUMP = 0x35;
    uint8 private constant OP_STACKEMPTY = 0x36;
    uint8 private constant OP_PCPUSH = 0x37;
    uint8 private constant OP_AUXPUSH = 0x38;
    uint8 private constant OP_AUXPOP = 0x39;
    uint8 private constant OP_AUXSTACKEMPTY = 0x3a;
    uint8 private constant OP_NOP = 0x3b;
    uint8 private constant OP_ERRPUSH = 0x3c;
    uint8 private constant OP_ERRSET = 0x3d;

    // Duplication and Exchange operations
    uint8 private constant OP_DUP0 = 0x40;
    uint8 private constant OP_DUP1 = 0x41;
    uint8 private constant OP_DUP2 = 0x42;
    uint8 private constant OP_SWAP1 = 0x43;
    uint8 private constant OP_SWAP2 = 0x44;

    // Tuple opertations
    uint8 private constant OP_TGET = 0x50;
    uint8 private constant OP_TSET = 0x51;
    uint8 private constant OP_TLEN = 0x52;
    uint8 private constant OP_XGET = 0x53;
    uint8 private constant OP_XSET = 0x54;

    // Logging opertations
    uint8 private constant OP_BREAKPOINT = 0x60;
    uint8 private constant OP_LOG = 0x61;

    // System operations
    uint8 private constant OP_SEND = 0x70;
    uint8 private constant OP_INBOX_PEEK = 0x71;
    uint8 private constant OP_INBOX = 0x72;
    uint8 private constant OP_ERROR = 0x73;
    uint8 private constant OP_STOP = 0x74;
    uint8 private constant OP_SETGAS = 0x75;
    uint8 private constant OP_PUSHGAS = 0x76;
    uint8 private constant OP_ERR_CODE_POINT = 0x77;
    uint8 private constant OP_PUSH_INSN = 0x78;
    uint8 private constant OP_PUSH_INSN_IMM = 0x79;
    // uint8 private constant OP_OPEN_INSN = 0x7a;
    uint8 private constant OP_SIDELOAD = 0x7b;

    uint8 private constant OP_ECRECOVER = 0x80;
    uint8 private constant OP_ECADD = 0x81;
    uint8 private constant OP_ECMUL = 0x82;
    uint8 private constant OP_ECPAIRING = 0x83;

    uint64 private constant EC_PAIRING_POINT_GAS_COST = 500000;

    uint8 private constant CODE_POINT_TYPECODE = 1;
    bytes32 private constant CODE_POINT_ERROR = keccak256(
        abi.encodePacked(CODE_POINT_TYPECODE, uint8(0), bytes32(0))
    );

    function opInfo(uint256 opCode)
        private
        pure
        returns (
            uint256, // stack pops
            uint256, // auxstack pops
            uint64, // gas used
            function(AssertionContext memory) internal view // impl
        )
    {coverage_0x0dbb89fa(0x879598f4b5ee277cf128a82b9a3fcc69c2c1454c42af9f9a4ea84d0571869be8); /* function */ 

coverage_0x0dbb89fa(0x12951547e551c92f34e46313623b21b1f69764c7ed8d4b067f1a848cbd4a789a); /* line */ 
        coverage_0x0dbb89fa(0x736be8e75f346f7d01e20fce28e2ad45338e03ef16b9f1678c936f36127baea9); /* statement */ 
if (opCode == OP_ADD || opCode == OP_MUL || opCode == OP_SUB) {coverage_0x0dbb89fa(0x92feb488ebd962d50de5f424e973f48961351529fb7b9f51863c030f7e1854d9); /* branch */ 

coverage_0x0dbb89fa(0xa226887543d9f39d22b6da694afcf1486c12c3830edf70a767c443527498e46e); /* line */ 
            coverage_0x0dbb89fa(0xc284ef4a24c6dc8392470ec4ebc99a50821931d022efdf8164df5451c8b4a98e); /* statement */ 
return (2, 0, 3, binaryMathOp);
        } else {coverage_0x0dbb89fa(0xafcd914532ac2c5202e16a6f100cd6fd4397499c8568daa95d38bd6b01b27829); /* statement */ 
coverage_0x0dbb89fa(0xbc0c085c6365d2d3eaa9911166fdf62dcbd5d9c37026bd733cabde5ddc866fb1); /* branch */ 
if (opCode == OP_DIV || opCode == OP_MOD) {coverage_0x0dbb89fa(0x4207ee2d092090c7feaaae1c42252e1f6f3b188e41be15a3448e8fd886ce365c); /* branch */ 

coverage_0x0dbb89fa(0xb76d5055b0c7f13a125503877dafe896ef4cd2361519552b9dcaaf09d184145d); /* line */ 
            coverage_0x0dbb89fa(0x9bd814509f3fc7cead1d686a2f74f39447c59999dfba1e5979d0aa6b66b35841); /* statement */ 
return (2, 0, 4, binaryMathOpZero);
        } else {coverage_0x0dbb89fa(0x2574f748ffec172c3ae11ca4024bf1f8c405141b536d7ed046361bd8c09fa8c8); /* statement */ 
coverage_0x0dbb89fa(0xf87cdbaec6f8406fdcf31220212af580a5a48312db75426833c296fd0ff7dcd1); /* branch */ 
if (opCode == OP_SDIV || opCode == OP_SMOD) {coverage_0x0dbb89fa(0xa8403d6962cfb03784f8d28a9e13ef229534a374a1666514139565c56e2859a7); /* branch */ 

coverage_0x0dbb89fa(0xecd47b0e686f04d00f36ea43d8f894f476336ebcc08802591c0d43357f12cf12); /* line */ 
            coverage_0x0dbb89fa(0x18f540f7d2cc8cb35bc205af52cebd8316ed92db263ecadbf4a01f2267f4f6b7); /* statement */ 
return (2, 0, 7, binaryMathOpZero);
        } else {coverage_0x0dbb89fa(0x490a38f980b0af4f7e5301939f54701bc470110958f93284e8e32ac096ca121e); /* statement */ 
coverage_0x0dbb89fa(0xf052af04a0d7b594ac23dc21c2f3af8d575a2c8b27fc7958960eb97a41249e02); /* branch */ 
if (opCode == OP_ADDMOD || opCode == OP_MULMOD) {coverage_0x0dbb89fa(0x584d9eef3a2ddb8f91df080727b137fe11d5407ebaf5cb8c1b481dad501efa3f); /* branch */ 

coverage_0x0dbb89fa(0xeac18a6b54a9348b9f57ca8c780ef23b4830ae66ccfde1239445376245d878f0); /* line */ 
            coverage_0x0dbb89fa(0x6dba9d87565af66434c2d754effc155cfd0fda3f953ff1bbad900c20fc3eded2); /* statement */ 
return (3, 0, 4, executeMathModInsn);
        } else {coverage_0x0dbb89fa(0x3350d4be6ccc116231a7136432f87d31fbc46d8980b355029ee8d2e6f5c59e21); /* statement */ 
coverage_0x0dbb89fa(0x72470c1a92c9e6825f8934433658c0c834a4cc13a54c7d37f20365616922c72a); /* branch */ 
if (opCode == OP_EXP) {coverage_0x0dbb89fa(0x75b00eb1e9e1d5da780d810b6c31fa5acd02f17f3cd0e2e6a25ead5575368582); /* branch */ 

coverage_0x0dbb89fa(0x4d91fdbb86c0b64de9ce2cb885ca164f64cadf4558e4c1fac0aec673f745a53c); /* line */ 
            coverage_0x0dbb89fa(0xfccc168ef83bb6c78f25b66ae5acf2e1026e6218f244a2317a5a9db078728c63); /* statement */ 
return (2, 0, 25, binaryMathOp);
        } else {coverage_0x0dbb89fa(0xcd32b8db9c4c3684449abe2b729527fdd6e973bb948a000448e2277db1485866); /* statement */ 
coverage_0x0dbb89fa(0xc36b2ca829ee6be13fcf563bcb7b23634d6aa6c9adc9ac227b150a493eaa4829); /* branch */ 
if (opCode == OP_SIGNEXTEND) {coverage_0x0dbb89fa(0xed8dfe164415f6238522ff0f09640bf3476cf89f7534e73f12b4d9ca70c6fc3f); /* branch */ 

coverage_0x0dbb89fa(0xdf7f409835454dffce1a6cda2bdc256517ecfb6e6e2b005417d87f981594fb03); /* line */ 
            coverage_0x0dbb89fa(0xec213b6c38358eebc9f5fe4d21f725cddf085d6b9e64a997311f7e98c5497547); /* statement */ 
return (2, 0, 7, binaryMathOp);
        } else {coverage_0x0dbb89fa(0x3f21dd8dc991967bd8ce25b51ed2da8004dba3868b9b453df591fb5e3e88ec87); /* statement */ 
coverage_0x0dbb89fa(0x48d1798249538a14c932b82dabf10ea7a33d61bbba1c6e3785a6a8b41bcae52f); /* branch */ 
if (
            opCode == OP_LT ||
            opCode == OP_GT ||
            opCode == OP_SLT ||
            opCode == OP_SGT ||
            opCode == OP_AND ||
            opCode == OP_OR ||
            opCode == OP_XOR
        ) {coverage_0x0dbb89fa(0x6d75ba1544ceb38bedb8f70dd32e4c87c1051ab3374b9453e797161bdaf28fa9); /* branch */ 

coverage_0x0dbb89fa(0x5b13f11169b232e2bdb58c51a91ce624b897987f494a811447ff87b802c96bfa); /* line */ 
            coverage_0x0dbb89fa(0x66c2fdefc7922587ae12c539143b3692af7ffddfe6eb5c071a47afc7b6c80510); /* statement */ 
return (2, 0, 2, binaryMathOp);
        } else {coverage_0x0dbb89fa(0xb89ad877b7af250c650af1519f8525cddc832edd8dfd33a3fa73330f3d7bff21); /* statement */ 
coverage_0x0dbb89fa(0x057e612e1e8ab1c6ae254bf280c9c10a050419a95dcd6e999486598eccfef08e); /* branch */ 
if (opCode == OP_EQ) {coverage_0x0dbb89fa(0x2f4f0bc6c3fdb0a078141d121afc030e13784f0f39f1b407bb4eba2ebfa7e563); /* branch */ 

coverage_0x0dbb89fa(0x4c3bc5162c7f64838f70e73d3397273e02ac06e6410616420c9c7716b95f039f); /* line */ 
            coverage_0x0dbb89fa(0x00fcbbf7bd64ca1cb8ebd84d3e682e900aad9b9c647be2cfc960b6a5d3c0c1d7); /* statement */ 
return (2, 0, 2, executeEqInsn);
        } else {coverage_0x0dbb89fa(0xeb6faa2aedae219190afc4932f753b468296e45670ddcd6a9e468cc574835545); /* statement */ 
coverage_0x0dbb89fa(0xa46b2ec6abfd433aef118269d9a098c47642d72700e737ff7cf1dca42f4628c1); /* branch */ 
if (opCode == OP_ISZERO) {coverage_0x0dbb89fa(0x961de844d6261c0e6ef8a5449b9fa54c4bb48d56afc13f02e6217cd96cae2ca0); /* branch */ 

coverage_0x0dbb89fa(0xedc9753b9c960edee4b96979ce4dbb24d4f82be8f84b07f0ed0b77874cdd6f13); /* line */ 
            coverage_0x0dbb89fa(0xebf517f5f925ef7b6093225a2577095e44c82763f8061d7892c031c022576013); /* statement */ 
return (1, 0, 1, executeIszeroInsn);
        } else {coverage_0x0dbb89fa(0x55edacc5a37237f5ac1a9248d22f34f2cd5d18385bf7b8aef1615cec17dbce92); /* statement */ 
coverage_0x0dbb89fa(0x42543a9baa7aeb5fa3fc23b40e9724a174424887306c3e0b8cd34ac37517ff6f); /* branch */ 
if (opCode == OP_NOT) {coverage_0x0dbb89fa(0x58653786079d8580bcca7aa1aed977250a0369529fbdff07a7bebe84a3ac25b8); /* branch */ 

coverage_0x0dbb89fa(0x967f2fa49d4ad078c92cb56196a19c5f3de618ef7b85ddab3ca945908be13a3d); /* line */ 
            coverage_0x0dbb89fa(0xff5df71a25e43cdc3becdf3f71f24b09ad0dad94163808e378d32ae512eeaadd); /* statement */ 
return (1, 0, 1, executeNotInsn);
        } else {coverage_0x0dbb89fa(0x3befcbb03e7d48e196002228d74fcc5f1c39530fb86656a58916ffb9b8ea6a20); /* statement */ 
coverage_0x0dbb89fa(0xe621045504d27c70e412f14ab2a759362ee96f75d6da3c7372b4c5dc7b5a2b7c); /* branch */ 
if (opCode == OP_BYTE || opCode == OP_SHL || opCode == OP_SHR || opCode == OP_SAR) {coverage_0x0dbb89fa(0x5bdf51ff634bbffc0547b1bdc0872cb3bfd1a5261c61dd9187fd4234729db582); /* branch */ 

coverage_0x0dbb89fa(0xe6f28c91666db6aad8e7e9835fb678f3a9524b0284ebd80e02155c49f434fc64); /* line */ 
            coverage_0x0dbb89fa(0x44a8b3c8fafd7c431f8eb13ede5857ec1b3a94a390f27e028852e610205f113a); /* statement */ 
return (2, 0, 4, binaryMathOp);
        } else {coverage_0x0dbb89fa(0xcd2c67a8b975aebc13576d8f39056e46cc186b9d70e621c021f0dc0f901cf8f0); /* statement */ 
coverage_0x0dbb89fa(0x7f2e2de6b6b14e6d97892d1a058462a2d7c78e248ab59caae7b2a52110a73dc7); /* branch */ 
if (opCode == OP_HASH) {coverage_0x0dbb89fa(0x3816056666cd9904f593b7690110638cb1a5fdac84c8ff59031fd4ec8cccccab); /* branch */ 

coverage_0x0dbb89fa(0xbdaf078dd7c0591bf442c194468ec7e3e92e1cbfaa47cc8b19f03a023de7b9e7); /* line */ 
            coverage_0x0dbb89fa(0xa7447d2309e65725133f5f5dccb6733326cc0eb585a48bbd5b72ea7f70ce1700); /* statement */ 
return (1, 0, 7, executeHashInsn);
        } else {coverage_0x0dbb89fa(0xb1e3fbf2da526b877a0f2d801a714bde6805b731722b2e550723ea355659ee55); /* statement */ 
coverage_0x0dbb89fa(0x6c3047aae9e31be1dde96482ef37416a46d7813903ecbdfe5c96b436933e75d9); /* branch */ 
if (opCode == OP_TYPE) {coverage_0x0dbb89fa(0x4c49707c7770de5fc8b0424c230a2184ebcc6e6504f3c95e07f926b449db6e8b); /* branch */ 

coverage_0x0dbb89fa(0x57d37c7fba741dcf82ef2c0a329fe1b8ec275c3222fcfd5a13a8b968158f47fd); /* line */ 
            coverage_0x0dbb89fa(0x56917ee7419e9942fab921b602186feb2a1ac250a9355f3c597990ac6c39b024); /* statement */ 
return (1, 0, 3, executeTypeInsn);
        } else {coverage_0x0dbb89fa(0x3022680fe5c94c2bb00c3e87d4d785f31109d12b50a73cdba806ff2ec2e0f854); /* statement */ 
coverage_0x0dbb89fa(0x40f5b8a92eb0c1c724575edf300c513d35b4dc6792fff5d196cca697e649aefb); /* branch */ 
if (opCode == OP_ETHHASH2) {coverage_0x0dbb89fa(0x5835872b9bd5a424f2f61785249a34beed4f716aa754ecab2f18f79323d7e6df); /* branch */ 

coverage_0x0dbb89fa(0xbdc29ae41e873c03689bb3b16d437ff779c692184fe790831adf7f94015d2a35); /* line */ 
            coverage_0x0dbb89fa(0xd00d3c6a715fa4f23d2ed5a1ff2c02512cbd21d546b3710597b6eeb5eaab1bc4); /* statement */ 
return (2, 0, 8, binaryMathOp);
        } else {coverage_0x0dbb89fa(0x36c3b682b904ab03bd6d479886cbf98070dd2f8cc930eac8c8f7d379e3988f73); /* statement */ 
coverage_0x0dbb89fa(0xc5d13b611830c7ae6d0f37a9bc361aba53e4e0e1e42eac69f06f7c64b30832c8); /* branch */ 
if (opCode == OP_KECCAK_F) {coverage_0x0dbb89fa(0xe829851e24bc732e03680807f2063ccfbd8825e870357db30b0cfa5b015b7ccb); /* branch */ 

coverage_0x0dbb89fa(0x3759a9eb842094554f07094eded6c646d8822c53ead61eab09781f62dce6cd81); /* line */ 
            coverage_0x0dbb89fa(0xe2f25b9ff94fc1dcef6f2474d735f10fa74ba03db8c9f88157528f45d4153f56); /* statement */ 
return (1, 0, 600, executeKeccakFInsn);
        } else {coverage_0x0dbb89fa(0x7e04da66a2851818b52437bc2d8a9d17da8ff961b998bd7838bf7355f37dfdd5); /* statement */ 
coverage_0x0dbb89fa(0xbb47214a861dece4105c4c3109ec9e512bab43fa4a6a92625ae75ff2a2f6c99d); /* branch */ 
if (opCode == OP_SHA256_F) {coverage_0x0dbb89fa(0x58d4026bfbdd6bd6270bf93eb4f7b69938d6c6ff2336b73540a040487b8f9f09); /* branch */ 

coverage_0x0dbb89fa(0x31a6fcefa263e8c4e085ecd666127288868b65315f1d1f750d7bfa67efeb1a73); /* line */ 
            coverage_0x0dbb89fa(0x92c3a6026a00a9ed96b1494583411dc9c8d39b6f1db4b38f035b10fff20248ae); /* statement */ 
return (3, 0, 250, executeSha256FInsn);
        } else {coverage_0x0dbb89fa(0x4fa48493fef7534a230fd532075adffa03b6ddf8544ea96501eaecff3a43143e); /* statement */ 
coverage_0x0dbb89fa(0x2eaa0ff2ed28088a0e62d2008f03ad4f5bf77414f7241939aa8614c299dd2348); /* branch */ 
if (opCode == OP_POP) {coverage_0x0dbb89fa(0x70f44c9da404a7091006ad8d6244d18a0d9fb86025b759f0e4eb82a2226464b8); /* branch */ 

coverage_0x0dbb89fa(0x6b6bb1e4ba4c8803b0fb438353f48024455d4efcea51484926090281e6640b8d); /* line */ 
            coverage_0x0dbb89fa(0x3c3eb23f1f8516b3f6947945d96d489a91293b7e404eac0cbfbdf1d887d477f8); /* statement */ 
return (1, 0, 1, executePopInsn);
        } else {coverage_0x0dbb89fa(0x716a76227c0be3e8747f934819ac8cf86fbe26de45f106190067a123de7b0b26); /* statement */ 
coverage_0x0dbb89fa(0xf7d3d2526ffe6ecde50966cb2f436aa03251faad4543ec2b4474070370fc913f); /* branch */ 
if (opCode == OP_SPUSH) {coverage_0x0dbb89fa(0x8ed66a2bbd461c74c802bf28a8132adcc1de9e1dc1cfa493120eb1425c1c7154); /* branch */ 

coverage_0x0dbb89fa(0xf956f1327fa35491fea56fdbe9d4222744a6e00cd6f7d2c6e26c335acae8875f); /* line */ 
            coverage_0x0dbb89fa(0x9e555f765ed9ab28a819f03cc4e618faca0cb2b2afb9a9ab6975e58a988c9595); /* statement */ 
return (0, 0, 1, executeSpushInsn);
        } else {coverage_0x0dbb89fa(0x2eb5cbf36b76bc4956ef9deb16b8d327a6780c41a828a22ed7bf5cdaa5a9b5ef); /* statement */ 
coverage_0x0dbb89fa(0xc4385d64ddbd084fead65d6c8eb7dcbc64c0d340eb722b02d4737d5ae3cc3d5e); /* branch */ 
if (opCode == OP_RPUSH) {coverage_0x0dbb89fa(0xadf7132a349d5d6a7efdf7feab0816e01177db75a9900a547febcb3d5441cdcd); /* branch */ 

coverage_0x0dbb89fa(0x8b7b05fe72fbdee52d4647ae0cd6373be834133bd77ade38f312b069eaf586df); /* line */ 
            coverage_0x0dbb89fa(0x446d22aac1c96534489e009ffb6accf007a997d8bfca80f51b633b71a0742bb1); /* statement */ 
return (0, 0, 1, executeRpushInsn);
        } else {coverage_0x0dbb89fa(0xd36310a4bb07f1d7ab93979b245d039b3444cc3d7630bdf0310759715e308e93); /* statement */ 
coverage_0x0dbb89fa(0x04c602e8a7d5f9350d687981424abe92e6bf7390711eaca79dc7dc416aa88989); /* branch */ 
if (opCode == OP_RSET) {coverage_0x0dbb89fa(0x95cdd1fe0b8a23a23e9c147cb8a4164128c572c0d6cb052b324ba37ca486dbe8); /* branch */ 

coverage_0x0dbb89fa(0xf77bc9051b157b7f473a639c4cab0fd8e9f5e6f6aa111acd1332f55ebdbf43a5); /* line */ 
            coverage_0x0dbb89fa(0xc8b4f90c41e1b113c89644f25ecd81e47a32c5e47ec806d2a8de9067b074d2d0); /* statement */ 
return (1, 0, 2, executeRsetInsn);
        } else {coverage_0x0dbb89fa(0xcdcf02f8d0863c16cf9a154c64e116e34c42659413f54357e50988f9c1b71d54); /* statement */ 
coverage_0x0dbb89fa(0x920908703249e546e9ad636ed75938ef8a89e20b4d6c3d41ead176d5bb355fa5); /* branch */ 
if (opCode == OP_JUMP) {coverage_0x0dbb89fa(0xf70b472d0372324caf06da62f394249ca55ce57aad368bc2e7c0c61600d4bfeb); /* branch */ 

coverage_0x0dbb89fa(0xdb6aa37b520806af14df4d8ac2ec7e49c7028edc9b19d8783433682ead3c3698); /* line */ 
            coverage_0x0dbb89fa(0x46d12c0befb44f4fba06813d0b63ad5b1251d7f26bdad80854fcc293205d12ef); /* statement */ 
return (1, 0, 4, executeJumpInsn);
        } else {coverage_0x0dbb89fa(0x84446a8562b3f6c057296d14e2d2b7623e778266993e07226ffc78248852ec2a); /* statement */ 
coverage_0x0dbb89fa(0x970b719896211970db9becfc70a4c5f3ed533967bdefdb2550cd97a38793ca9c); /* branch */ 
if (opCode == OP_CJUMP) {coverage_0x0dbb89fa(0xda199d9014581db548dfb5ef468a876402b4c76f22e5bd30a9e4352c283c2ced); /* branch */ 

coverage_0x0dbb89fa(0xd80d68f33a8983ea95a4ffb12911cfd2f85fbfb550b90a695c11ee4e0a774c59); /* line */ 
            coverage_0x0dbb89fa(0x08dd3c375628e2f20d4be06c79e0f431108c10d3d88983654e2cadff6b782083); /* statement */ 
return (2, 0, 4, executeCjumpInsn);
        } else {coverage_0x0dbb89fa(0xec7071257b62ab1d5c1f06ba3c5660a059910faff6f8621ddde3c7c32f696553); /* statement */ 
coverage_0x0dbb89fa(0xe678a2a9c8a5fc57edebfbe5741536dc2e98b6fb2a57bdc0b2b7ae38383a5033); /* branch */ 
if (opCode == OP_STACKEMPTY) {coverage_0x0dbb89fa(0x4dc969149d3a4393df58536255a4c4587864d7d5c1d851b306d171ddf36318f6); /* branch */ 

coverage_0x0dbb89fa(0xbdf089c0a745d8c69569b7eb7e30a2c570c8d70578a9bb40caddedcb9662afb2); /* line */ 
            coverage_0x0dbb89fa(0xce8c1390d1a2a4a63012982079aafef5d7a1f5e64e1c156e3cceb64427f05a74); /* statement */ 
return (0, 0, 2, executeStackemptyInsn);
        } else {coverage_0x0dbb89fa(0xaa87f4f0a48dbbe7798e2eea6b6afd1a0cbdb6fcef85ebcf2a5e0c6ab9be2717); /* statement */ 
coverage_0x0dbb89fa(0xda687534c8eb6dad7eb5616d20ca16609bd9bde55f886ec90868a1b7b40c9b3b); /* branch */ 
if (opCode == OP_PCPUSH) {coverage_0x0dbb89fa(0x1d5242263f7e523dde7fd7a19a10257b6ec00e31ad8ac78053970e54d2334310); /* branch */ 

coverage_0x0dbb89fa(0x2d44882728bae847642c4dedb458fe5f4f2a4b303a18beb26dbfaede9eaa76af); /* line */ 
            coverage_0x0dbb89fa(0xb5635948931af59d47b2b1206a0cb697e19430696b5f0e528c091ff56d8f9898); /* statement */ 
return (0, 0, 1, executePcpushInsn);
        } else {coverage_0x0dbb89fa(0x6b3e48645226673ccb26ad57a0d3a0a95c1e955823c558b1128ee6fa7492239f); /* statement */ 
coverage_0x0dbb89fa(0x7f83279459dd6c9bab68cd881aae7932f2808416c0e3628e583ff216e6d83738); /* branch */ 
if (opCode == OP_AUXPUSH) {coverage_0x0dbb89fa(0xff2232bc25aaf11211c202b91bb28b7c1fef4df17b96dee03ce33d5862bff001); /* branch */ 

coverage_0x0dbb89fa(0x878e53e6ec41bdb47a5c1a7bb1efce6ae128036ddd5ad0e3bc24142f76bbc215); /* line */ 
            coverage_0x0dbb89fa(0xe67cdf9c5746cc048d79fba7abb51768b4aee3349742f2c7395ac438b1b07e66); /* statement */ 
return (1, 0, 1, executeAuxpushInsn);
        } else {coverage_0x0dbb89fa(0x390c8f6ed031c5421c7495f535e9471f8404bf20da5a75772894303ca9990f61); /* statement */ 
coverage_0x0dbb89fa(0xdfd70f2791f9482a27ddc70e426c17dc87e343fce17cbb2956eea89701f10abb); /* branch */ 
if (opCode == OP_AUXPOP) {coverage_0x0dbb89fa(0xc6cd51b3f4fd119220ec1ac2a34d6b6f8115df4f87c8a1bc6a6807aa9b5a5a51); /* branch */ 

coverage_0x0dbb89fa(0xfe657f7e8aa8c177a0d513992918899cf608b1e993113d045e303f62a2d6429d); /* line */ 
            coverage_0x0dbb89fa(0x5edbcb6f0f160adf4f0619b8da4a130489b2521bcca28438d1c03df318e44705); /* statement */ 
return (0, 1, 1, executeAuxpopInsn);
        } else {coverage_0x0dbb89fa(0x1f929c98a4eb9b90362b9331e76e4b7ac13e30c8476016bc607d7d0b4f79aba6); /* statement */ 
coverage_0x0dbb89fa(0x7605da585f54e936825f78bd4af03b9337dd567a1bbad4fc66cc98a36696abbb); /* branch */ 
if (opCode == OP_AUXSTACKEMPTY) {coverage_0x0dbb89fa(0x77d6a6f7438d1bec9d4f16d112ff8ec1806cd20aa1f868ec421586f5fd7c4365); /* branch */ 

coverage_0x0dbb89fa(0xb2767f05fc9139868c81b75dc7f74418dc2178967735d98f5f9bbd99a3153e44); /* line */ 
            coverage_0x0dbb89fa(0x825433226eb66ec6bdb135bd386a06611dd96c88e7f60cf4dfafe5b73409ed68); /* statement */ 
return (0, 0, 2, executeAuxstackemptyInsn);
        } else {coverage_0x0dbb89fa(0x6bd8e80428ef26c986f47c94d1ec2c2a6af3dee9d990bc1ce7716d8132b178d4); /* statement */ 
coverage_0x0dbb89fa(0xcd84570db7b83a33eab070cd69076f369b3dc28d9cf686c67fe1d7ce91ad2301); /* branch */ 
if (opCode == OP_NOP) {coverage_0x0dbb89fa(0x5f1604eda6c65e08a02e691488c50f4fe6ae6162bc876927a9628bfaf5c6f541); /* branch */ 

coverage_0x0dbb89fa(0x647a338fa5357a8fcd79c991454a090e4eab9acb108dccfc9edb4b30a0684994); /* line */ 
            coverage_0x0dbb89fa(0x6514f768dc02140edc21e0f5b38d56fa93d1ff8f8b6ad3bfb3577a4661ae9056); /* statement */ 
return (0, 0, 1, executeNopInsn);
        } else {coverage_0x0dbb89fa(0x0d7c3a0e35d19f5f15878282a9f230fa9774744038d2de2615a768440d206ef8); /* statement */ 
coverage_0x0dbb89fa(0xa56a140d406e33b8473ef5c853f08e0d159f04f6e826339ff88b7274dd9fa620); /* branch */ 
if (opCode == OP_ERRPUSH) {coverage_0x0dbb89fa(0x3ef46eea2a238d7b037daad72b69494c9adf0b092486a9a23a2116f97d297ca0); /* branch */ 

coverage_0x0dbb89fa(0x65317d8823eb400799ba1d50d66a47ec1878db94cc08b62b135ad90c31b7b159); /* line */ 
            coverage_0x0dbb89fa(0xaa28a0baf6516dcb966ea1d3e9bec0f17b4b7b4ef61f7db743db6177efdf3f1c); /* statement */ 
return (0, 0, 1, executeErrpushInsn);
        } else {coverage_0x0dbb89fa(0x79fbd778a63dd79022cd4e0dad9d588916b9be2fd63fede62da8a54f2cbad8ea); /* statement */ 
coverage_0x0dbb89fa(0x68bc0f757d27bf683b68a6504c0b17246a6f0672bf0a61ce9e34464482896944); /* branch */ 
if (opCode == OP_ERRSET) {coverage_0x0dbb89fa(0xd87f20a07aab1b7b4f5a50e144d45851a03bfa9b1ceb3ae503371bda7035de9e); /* branch */ 

coverage_0x0dbb89fa(0xde8e1d5e11be3a2f5b96b2f90f6d41cf89e72ed64d2daf3e398a54a3ed7a9269); /* line */ 
            coverage_0x0dbb89fa(0x8dfa6947372d76ba25a4e0e45b2260a51790ba5dcc447229a32627cd9cd8c3d5); /* statement */ 
return (1, 0, 1, executeErrsetInsn);
        } else {coverage_0x0dbb89fa(0xf12c73df5f314c29fa92767174662ae84cad3bdea7240621c9e2ca6530f9c9b2); /* statement */ 
coverage_0x0dbb89fa(0x26c1f65599e1fa80238e0f9ba9e827ec1f7d56a783bb77be328baafa1545cc65); /* branch */ 
if (opCode == OP_DUP0) {coverage_0x0dbb89fa(0x4860b6f7ad75c57235dca13d263f1066bf70e527b7d6dd972425fefdddee7085); /* branch */ 

coverage_0x0dbb89fa(0x03962efeb015e88c0fb4c5865a8b2d7bbf8029bbbcec1e5c9a76a93b57e70c84); /* line */ 
            coverage_0x0dbb89fa(0x6caa0a2baab75a0d52de05d024a798d6c100d8a2197b2bdf8e55bcece833bd05); /* statement */ 
return (1, 0, 1, executeDup0Insn);
        } else {coverage_0x0dbb89fa(0x3067370a895ce1ee639470bd768a3233d1a6ef2898ee7f3d72ad6603be019951); /* statement */ 
coverage_0x0dbb89fa(0xa0e90f0aac214de29ce72c74b6a0c7a94acf9668b73d4d10a1d8e90336fde702); /* branch */ 
if (opCode == OP_DUP1) {coverage_0x0dbb89fa(0x607d2d6911e5a52bd698e8adcdb1954f23ccb4d755f7e28b41e905fc1662242a); /* branch */ 

coverage_0x0dbb89fa(0x6236032d40d11c69f16d31f7ff9bca4b0bd9d19df4e77052cdbc03e5eb78c3cb); /* line */ 
            coverage_0x0dbb89fa(0x3bbc4deb1392e1bd785f74fc9694171df839a5bfdf9ab227d51462e001e5f0c9); /* statement */ 
return (2, 0, 1, executeDup1Insn);
        } else {coverage_0x0dbb89fa(0x04282b21170e9b0cb39d0314bfabec27ee4c9d0b19606c228ba0c21c466a096e); /* statement */ 
coverage_0x0dbb89fa(0xa08510ad91b32e43834ca39975eed2d53fb627778afc0de4f20b907fc0709a7b); /* branch */ 
if (opCode == OP_DUP2) {coverage_0x0dbb89fa(0x68545e6cbfaca29b2450ced1bec7ef4433ece774b2cd35d5c42e4ca7b1c6849a); /* branch */ 

coverage_0x0dbb89fa(0x890fb4c3d6e8bb359ce95f59b15435bc8e0aff53543babd330afcb10a496c31e); /* line */ 
            coverage_0x0dbb89fa(0x3f86f755a1c73e4d4bb895294af0372d28e858dcb97029fbc70542f8c2590fe3); /* statement */ 
return (3, 0, 1, executeDup2Insn);
        } else {coverage_0x0dbb89fa(0x050fd75833ff944f91f5ec3992cd4c94bc486b6a5ae4f463cd2c208d8f8acfb6); /* statement */ 
coverage_0x0dbb89fa(0xfb64d75d270f8395d1ada8812f98abe814e9d8eab9dcbfa5d3e1f271b17b3160); /* branch */ 
if (opCode == OP_SWAP1) {coverage_0x0dbb89fa(0x4fd404bb72ac69d54674faa821ed1ebe5a13c275405c3fbc6afb0aaa9bf4c485); /* branch */ 

coverage_0x0dbb89fa(0x26107ce99b11c5f1c07021aa7fbca2c5cab127df8f798b9e642ad603d43419bd); /* line */ 
            coverage_0x0dbb89fa(0x6606c3493c675daa3b83cdb0b241be7e64dfe9ddf2dc87e38f0dd8b36d1245a3); /* statement */ 
return (2, 0, 1, executeSwap1Insn);
        } else {coverage_0x0dbb89fa(0x7251ce09e184b9379741fdda317e2177e85d0cf42b45a8c83fc90ac1ef2a432d); /* statement */ 
coverage_0x0dbb89fa(0x1366db5214751874d0983a45491716a9c549855f3af8a779c947135371dcc167); /* branch */ 
if (opCode == OP_SWAP2) {coverage_0x0dbb89fa(0x358d67023a86fb5eafebab11dd37eee38d1c16d11f0458f4e3008f22d4effb2e); /* branch */ 

coverage_0x0dbb89fa(0xd0a589eb7991f917336fec01e58a4255bfc1458c0b4d18f135dc86c90f19eaae); /* line */ 
            coverage_0x0dbb89fa(0x08a1923d2e6a05f2882208b0ef5ccfcacb26b248896cdee7c0d67a6c5c07508f); /* statement */ 
return (3, 0, 1, executeSwap2Insn);
        } else {coverage_0x0dbb89fa(0xfc5ed80b65314cf9fb3cd7c4778f145eecddc3faede2a5b63cf31b6eaf2f9fec); /* statement */ 
coverage_0x0dbb89fa(0xf89a32d1d8f1666c462f0663015408c7d2460d7eb8c3c6745d8937a41c04663c); /* branch */ 
if (opCode == OP_TGET) {coverage_0x0dbb89fa(0x3e546e2f16eef21292adaeb0d062e825e2259adff74b76f3291fc55a892b7519); /* branch */ 

coverage_0x0dbb89fa(0x7f18c67fffd1cd5d5ccfdf6523a6d6c751ced7141cdea94ad99040c398315c83); /* line */ 
            coverage_0x0dbb89fa(0xbe37c4fda8044bce44e84a019dfaaa7edd676715f45f7d1e3e58481b69cdd1bf); /* statement */ 
return (2, 0, 2, executeTgetInsn);
        } else {coverage_0x0dbb89fa(0xfa4b03fdff4d014831cd8b3b156d344f3859a19313737d12a81dbbca658f2b7d); /* statement */ 
coverage_0x0dbb89fa(0xca6a091de4cc8552cf50220ea6c3b976ac9f7552a426f3f4bd10b74923a148de); /* branch */ 
if (opCode == OP_TSET) {coverage_0x0dbb89fa(0x4b010683c3eebc6d6d4d343bf85977526907423d6e4dd45f1c38870ec7fefa2d); /* branch */ 

coverage_0x0dbb89fa(0x8755014657444388f314fa1acbb95f006cc0ce8b4eb14463acea57b2b2512e59); /* line */ 
            coverage_0x0dbb89fa(0xe83aca918b64244dcb9c5c5c34f80c5a560a831a16ad0970f94eefdb7efe4cc4); /* statement */ 
return (3, 0, 40, executeTsetInsn);
        } else {coverage_0x0dbb89fa(0x577abf950497d27136b90f32ae460538547a5f487bd8ab03984acfc7e19f0786); /* statement */ 
coverage_0x0dbb89fa(0x88b9856a9c4724571ab988f1a2bee263fd8c24d580ce45c2a23d74a7481620b5); /* branch */ 
if (opCode == OP_TLEN) {coverage_0x0dbb89fa(0x29714d53e738c612c7191d899710989b02921a0674d03041162b480764c57eac); /* branch */ 

coverage_0x0dbb89fa(0xae704faeab622e3b0602e8c4ea0fbecd0982e3d780673357530edd70a2a8b189); /* line */ 
            coverage_0x0dbb89fa(0xfd0a89fdb32102a4b2104e5fed368e68cb6a3f8ce6abcb52c59c3d76ac0eaf31); /* statement */ 
return (1, 0, 2, executeTlenInsn);
        } else {coverage_0x0dbb89fa(0x2b656716d80864b5e9e6f0b6533c430e17bcd3043a3b83834166948f487690b7); /* statement */ 
coverage_0x0dbb89fa(0x682370ba0106388dcf55693812ed5e9439587465df25fbd92f3547500fc8a7d8); /* branch */ 
if (opCode == OP_XGET) {coverage_0x0dbb89fa(0x3775ef785122e01263eccfc690946467e9f7bcb527f74dc2809ef3537bc98079); /* branch */ 

coverage_0x0dbb89fa(0x9dd116104686491db8ddd5820a2f007804676633235af7da5fc69e39b557a49d); /* line */ 
            coverage_0x0dbb89fa(0x280fef50f93614557d0e419868a539f3709d2335debc6a0fccd50ed44888d6a2); /* statement */ 
return (1, 1, 3, executeXgetInsn);
        } else {coverage_0x0dbb89fa(0x076b338f79f6cf9a469aadbb2d7fab80b7ee53a81177d429388abdb7780b52d2); /* statement */ 
coverage_0x0dbb89fa(0xdba48443d48ccb3b9f656cdab65ad43e8db2b93715024881058611d7f7d3b072); /* branch */ 
if (opCode == OP_XSET) {coverage_0x0dbb89fa(0x3521a4ba106b5ea8d6ffa3575c68caf771c5371e66a081f6e123053e52ee0e9a); /* branch */ 

coverage_0x0dbb89fa(0xb58ed6d06e7e4a0ed3f8444ee2c2f8ee19f040e6fca5a43da36230cd91dc0234); /* line */ 
            coverage_0x0dbb89fa(0x9426a2f5a7e67cef5d847a2db1543cace12bbf98c42d072ec97cf205e2e4fd2a); /* statement */ 
return (2, 1, 41, executeXsetInsn);
        } else {coverage_0x0dbb89fa(0x88c0523e5afc9b411a85ffe449f4d1a79af7fc36165ab721dfb8704864b8c360); /* statement */ 
coverage_0x0dbb89fa(0xade6f13a94307f12fd119050e20e6ce84859292c2a329d5021896dbe557a4701); /* branch */ 
if (opCode == OP_BREAKPOINT) {coverage_0x0dbb89fa(0x214deded52b9e079acd776d729fbf35a7b1b761011247ed2034b78ed63550046); /* branch */ 

coverage_0x0dbb89fa(0x31b00761f9c2199913b8fb223431e0656cf7abf89be344169f8e5964065e5d22); /* line */ 
            coverage_0x0dbb89fa(0x32113252fd96f6e14716062253abc50bbb53d1d87fac640dd3faba31eb271778); /* statement */ 
return (0, 0, 100, executeNopInsn);
        } else {coverage_0x0dbb89fa(0x76405057c6eb531774dec20bd04fcff90fccd011ec39d5edfdf4308044c50e0c); /* statement */ 
coverage_0x0dbb89fa(0x71c989e24b77e187952a30e6084fb4d910d129ea8377306489522a2f05d81432); /* branch */ 
if (opCode == OP_LOG) {coverage_0x0dbb89fa(0xe43cb2f007841269cea07035dbd226149e7de5a42bdd91b05746e7ce89831149); /* branch */ 

coverage_0x0dbb89fa(0x10583c94c26a216bf529aac72cd8bf166871f52e45b214cb3961bb9a5f441b44); /* line */ 
            coverage_0x0dbb89fa(0x71665894d448be76a14b9e2e8ff4abf49881f2b6277415b59fd651ea10c873b8); /* statement */ 
return (1, 0, 100, executeLogInsn);
        } else {coverage_0x0dbb89fa(0x82d9d8b1e8926c55754efc6edb97852f04dc113ab1c1ab2715a25e11e5db91be); /* statement */ 
coverage_0x0dbb89fa(0x9164e7ffb407164dabe9c6f75fb3e320695a5338aeaa5d3b297bbe3ae72724e7); /* branch */ 
if (opCode == OP_SEND) {coverage_0x0dbb89fa(0x78bf91698f597967abf79a2c04b999a3e40a5a8475623589bff45bea3468759e); /* branch */ 

coverage_0x0dbb89fa(0x4898afe28739b3ecfab5e09149ad515cf4f071b0d7d521fb32dfc0a181227f02); /* line */ 
            coverage_0x0dbb89fa(0xc3c1cd1e119458aa004e8ab9a3b55e712d5cafc34c6be9a3e229f21a51a74b93); /* statement */ 
return (1, 0, 100, executeSendInsn);
        } else {coverage_0x0dbb89fa(0xb01c32c5a20a4b6becd8b1141c2c27a09bed334060dacc06d5bc91bc21fe589a); /* statement */ 
coverage_0x0dbb89fa(0x9d7e6b3cc73811ca04a60c30a585471bf1729eaf39b9dd0053e573d55038f0d6); /* branch */ 
if (opCode == OP_INBOX_PEEK) {coverage_0x0dbb89fa(0x4026282a13147f8eec992ef06e6025b191ee014fe6ec2248998ad5a8d65875b7); /* branch */ 

coverage_0x0dbb89fa(0x08595405cfbb58266f1a8dfba8f9160d8397e46140818b5a4cf20cd8abaad2c7); /* line */ 
            coverage_0x0dbb89fa(0x47880d21a98cd221d10159d27f76854bfb27bfecbdc560dc8c6612771883e8d2); /* statement */ 
return (1, 0, 40, executeInboxPeekInsn);
        } else {coverage_0x0dbb89fa(0x39e5715d281c7b0288b93ca4b792f9eaf4368198c455a9b06c43f7959cd316f4); /* statement */ 
coverage_0x0dbb89fa(0xe6cc09411bae4ec2a61e6e064fac8ffd77885d687ad6ea811fb85a0a9e2dd1b3); /* branch */ 
if (opCode == OP_INBOX) {coverage_0x0dbb89fa(0x7bcfdbd32cc71e3064d164da93936c71b345c46c05349ff58c37dc41306f7c6a); /* branch */ 

coverage_0x0dbb89fa(0x49fe6cd96cf55213223efe3ff4ac30f271f92ef61e5e87b07298e924c524bf35); /* line */ 
            coverage_0x0dbb89fa(0x0df08fcbbcdad68b36f80be680e8cd7d3c49800f639486cdce23743c16042276); /* statement */ 
return (0, 0, 40, executeInboxInsn);
        } else {coverage_0x0dbb89fa(0xb8d113f81fbab316c00b7c97fa2fffca3a29c61cc09d63b1d5983a29f34d26ad); /* statement */ 
coverage_0x0dbb89fa(0x9da5e0c52a7c5dd3f300f1b4f7100ecfc26d0768e479c262cd7a3db61d839ddd); /* branch */ 
if (opCode == OP_ERROR) {coverage_0x0dbb89fa(0xd78aa6aca7ad7cc1b860b16c82fb2726b020b896a291b43b446dedf2f9cbde35); /* branch */ 

coverage_0x0dbb89fa(0x1f5da02773ec558de0e865aaba625d63b3e09f8099767892c666a9f0aed634d9); /* line */ 
            coverage_0x0dbb89fa(0x71c5e8a653e04a63e845888bc02bde94331f0931afc0ed1dc5d15d3329717186); /* statement */ 
return (0, 0, 5, executeErrorInsn);
        } else {coverage_0x0dbb89fa(0xf6b3283a8fe719d44e0fe0a33261d913beade559160aeabf11124fe07371ea89); /* statement */ 
coverage_0x0dbb89fa(0xbac936ec6c41abd258048d45a52d2e98aa9f1d08b92aa8fd3986bc7bae9c8048); /* branch */ 
if (opCode == OP_STOP) {coverage_0x0dbb89fa(0x5e44e7af6658559b061dc9bde38d32b236a17d3f5ce4b3eaa4974cdf46dde7ed); /* branch */ 

coverage_0x0dbb89fa(0xbfcb932e6339bcc1f9e0d1d19e06a7670a1740ddd63b0ecd064664f4e7dd2b01); /* line */ 
            coverage_0x0dbb89fa(0xe649199a49464833ecd630153637b180fa75bb04037b228e715ca0db6e80c3ff); /* statement */ 
return (0, 0, 10, executeStopInsn);
        } else {coverage_0x0dbb89fa(0x2553eca24e0624dad7cf93b70885f1f6e56f85b3822834e16a5b9ef5020af17a); /* statement */ 
coverage_0x0dbb89fa(0xb3d32aee6bc0f94e59655916da8072af007b5043d33d74e0541cae346c1adb0d); /* branch */ 
if (opCode == OP_SETGAS) {coverage_0x0dbb89fa(0x0db6f92c3af02b9ee92838c48110a278791665a1633ed69edc60438c8a66693d); /* branch */ 

coverage_0x0dbb89fa(0x14e48de3d9630a58264bac0410aa06a98c24e8d2cb48bf73ff52d4a76487a8d6); /* line */ 
            coverage_0x0dbb89fa(0x64cffc6279f296c655fda3c9dad0924ff9e4675484256ffe1ea96bc30661c028); /* statement */ 
return (1, 0, 0, executeSetGasInsn);
        } else {coverage_0x0dbb89fa(0xe532317e7b20555438076ce7d82a5893367599b45bac869d2c2fea408f47b569); /* statement */ 
coverage_0x0dbb89fa(0xd3f19acc35fc965468218832bcd4921f1bb39bb2a1699b9150d8bb70c36356c5); /* branch */ 
if (opCode == OP_PUSHGAS) {coverage_0x0dbb89fa(0x65acce1f9613dca0660a962da01cb9c865c8faa07b38ae95d07c8fbbb185a2cc); /* branch */ 

coverage_0x0dbb89fa(0xd0798c6c17366edf22b2764745a08846b6a16d3441be8a5f08946d3c78e76172); /* line */ 
            coverage_0x0dbb89fa(0xcf2ccddb6c61321c6743dfe336dafe457d840f57844580e616ca56625078fefb); /* statement */ 
return (0, 0, 1, executePushGasInsn);
        } else {coverage_0x0dbb89fa(0xaf64820282868b39e73942403592fea5d0211eae0c1711a214c731e2edf50ad7); /* statement */ 
coverage_0x0dbb89fa(0x9f8bd4347beab650c339afcab667963de30d7bc2567ef8af81ae924737b33157); /* branch */ 
if (opCode == OP_ERR_CODE_POINT) {coverage_0x0dbb89fa(0x1c59d0d2d777753ba9de6f6c14c30488a6bb47baa1260bc99b6eb58c28ffd59e); /* branch */ 

coverage_0x0dbb89fa(0x34dc1d41cb10a759d458509ba552cf3272b585d557e042a061fba3886361d83d); /* line */ 
            coverage_0x0dbb89fa(0xeda884c91da65b0f772443eb9ff8352089eb4b04eb380b840ff18bd5bbcd011f); /* statement */ 
return (0, 0, 25, executeErrCodePointInsn);
        } else {coverage_0x0dbb89fa(0xb61910bb75bc19a25ef67d5dd8cf846c31cc171c5e41289bf12228a034ff81a7); /* statement */ 
coverage_0x0dbb89fa(0xe8fd14ff7a45eea598bf6b0dfb9e8cca8c387e1170d3614e67a8b7c760bbfe79); /* branch */ 
if (opCode == OP_PUSH_INSN) {coverage_0x0dbb89fa(0x3d8372a5867e4b76e7e174bd0c93cfb617459d3d0cbfdbf1bd7a94564510c035); /* branch */ 

coverage_0x0dbb89fa(0xe7a04032b0dd4867ac7c11250a3c8dbb56c99a3e7ab747f8fa0fa0dda4a85a3d); /* line */ 
            coverage_0x0dbb89fa(0xce17fb3809fd8b270ad567b6b11338ce490977c3b62410dc8fbb5f160bd5f8c9); /* statement */ 
return (2, 0, 25, executePushInsnInsn);
        } else {coverage_0x0dbb89fa(0xcda3d72c8b3dac28c6aadf9ace2e89ebfc320b45c2b229d7c0bfc076c679f868); /* statement */ 
coverage_0x0dbb89fa(0x65c45977a269b47e1920dfa195b51a823361826653f2f3ae6346c49d25a86d4a); /* branch */ 
if (opCode == OP_PUSH_INSN_IMM) {coverage_0x0dbb89fa(0x451e6b6380de20603911df1fe29672b109ba95cb152a8659bc70a3fa7a44b172); /* branch */ 

coverage_0x0dbb89fa(0xa1fd62f085f106f390f462fe66aa2148760e9ca9909d9c655283bc419cd334b0); /* line */ 
            coverage_0x0dbb89fa(0x7d54ffb55f3df7c5e6f091dfb409e7eb97a40284650d458768fc157ee54dbaf7); /* statement */ 
return (3, 0, 25, executePushInsnImmInsn);
        } else {coverage_0x0dbb89fa(0x80456d4b400c4ac789d353bfdca905e5e668d99352e9e18f88df57cfc4c230b1); /* statement */ 
coverage_0x0dbb89fa(0x0466cbf007595805cd137f481b8500a9f8982ba1715dca9ca324036f66afc016); /* branch */ 
if (opCode == OP_SIDELOAD) {coverage_0x0dbb89fa(0x37a816d089d291fed4be400ba69919c177bd6698c704c1b1acecda325851028a); /* branch */ 

coverage_0x0dbb89fa(0x8b38ef07999b757d0c02406cbe2379d3a56de398d23dbd8911dca2d98cfdcddc); /* line */ 
            coverage_0x0dbb89fa(0x08d1958d838e0b476731a1b0e5e5170f7cc93e433140a05fc154374231c7dc46); /* statement */ 
return (0, 0, 10, executeSideloadInsn);
        } else {coverage_0x0dbb89fa(0xd2983df506453e57820ce590782f05d65f52268b9d83de2a478ec094b2842758); /* statement */ 
coverage_0x0dbb89fa(0x99fac86ea408a10f4fc32f5ab3bc7cbb3f6812707bb78be7c006c967a7bae187); /* branch */ 
if (opCode == OP_ECRECOVER) {coverage_0x0dbb89fa(0xe04dfe405847f3ab9b0bd13647fd11e4f673816998f10ef2083c464dda86fcf9); /* branch */ 

coverage_0x0dbb89fa(0xa106efd0273d412230552f92edc2ac736478def5da43ae995b605f05dcbcdb1e); /* line */ 
            coverage_0x0dbb89fa(0x0660395b7689161f0df980db8c54872539dae6eebdfc06d3ea1cc5ee87ea2a10); /* statement */ 
return (4, 0, 20000, executeECRecoverInsn);
        } else {coverage_0x0dbb89fa(0x52e4bdef2d78cd8d5cfc3a1860081ac2f3f8623b3f3a7118cd038e587dccd2a1); /* statement */ 
coverage_0x0dbb89fa(0x9ce18b5378ead69574c4447ce106ab77310aae74b5310692688ce806321da700); /* branch */ 
if (opCode == OP_ECADD) {coverage_0x0dbb89fa(0x34828c0d61b4b011da800c44c8440964840f67c06e0aa4133df96e2a54305140); /* branch */ 

coverage_0x0dbb89fa(0x7d03a213d406847cedb12997f446c243662c2f74484259d4dff2ed3e44a42339); /* line */ 
            coverage_0x0dbb89fa(0x7b374755a12058c0f7320e4f6629d0707b592fb77bf192c66f81fe40e72f3f57); /* statement */ 
return (4, 0, 3500, executeECAddInsn);
        } else {coverage_0x0dbb89fa(0xc6c2caa46d42cbe66ba1d02e9372f2e01ea0a1be2d98eed578fc7fe3d25f6eb0); /* statement */ 
coverage_0x0dbb89fa(0xf591279137103fdbffdf4cd2a9aa0c2cf8b9cd5eb9fc638ee81fc9067532746e); /* branch */ 
if (opCode == OP_ECMUL) {coverage_0x0dbb89fa(0xf642e92d7d31e1b72540d46a9d76af1797cf9c8569b3a853d9dc7821d6c3137a); /* branch */ 

coverage_0x0dbb89fa(0x0cf8904ae06dc32e05bade2d0869baf8cdff26c1efabf788cb2acd3fc7115667); /* line */ 
            coverage_0x0dbb89fa(0x263316986e3bb0db428be037188c313264ff085d8d6e7d2ac16d6ffc670b5922); /* statement */ 
return (3, 0, 82000, executeECMulInsn);
        } else {coverage_0x0dbb89fa(0x7684813c951e4e23cf6425892aa5373c0208fc957bfdc98223f5f48f16609c1c); /* statement */ 
coverage_0x0dbb89fa(0x608250042af19043d690d8f0e5b560a5a3c6211807099df50b0bc0a83b8d07aa); /* branch */ 
if (opCode == OP_ECPAIRING) {coverage_0x0dbb89fa(0xc621df914cac87f62f333e29ac1a75b406157994d2e2af45b8bdc4bf7fba6385); /* branch */ 

coverage_0x0dbb89fa(0xdd0d119f69f078679b5ca02eae36102f5c8e1be858d45d29783a4d933220425e); /* line */ 
            coverage_0x0dbb89fa(0x1413c16f0b3e63e500cf8e26f5667c1f97e8e80535cb1e08d1c1607e099cd2ae); /* statement */ 
return (1, 0, 1000, executeECPairingInsn);
        } else {coverage_0x0dbb89fa(0x56f8a36428cc5934bddabdcdca269d025512ec2276919c75de67e26713f2f135); /* branch */ 

coverage_0x0dbb89fa(0x05e939631c8a94a9349ceba5d678888fec7b032a979002708eb8fa6c300bc884); /* line */ 
            coverage_0x0dbb89fa(0x90f9adc8e62deb8c7da404dba5b7c37dd39b9242682b3aedc8ee761ef5e093d5); /* statement */ 
return (0, 0, 0, executeErrorInsn);
        }}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
    }
}
