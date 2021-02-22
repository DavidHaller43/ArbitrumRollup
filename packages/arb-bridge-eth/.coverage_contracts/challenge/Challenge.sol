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

import "../rollup/IStaking.sol";
import "../libraries/RollupTime.sol";
import "../libraries/Cloneable.sol";

contract Challenge is Cloneable {
function coverage_0x94099878(bytes32 c__0x94099878) public pure {}

    enum State { NoChallenge, AsserterTurn, ChallengerTurn }

    event InitiatedChallenge(uint256 deadlineTicks);

    event AsserterTimedOut();
    event ChallengerTimedOut();

    // Can online initialize once
    string private constant CHAL_INIT_STATE = "CHAL_INIT_STATE";
    // Can only continue challenge in response to bisection

    string private constant CON_STATE = "CON_STATE";
    // deadline expired
    string private constant CON_DEADLINE = "CON_DEADLINE";
    // Only original challenger can continue challenge
    string private constant CON_SENDER = "CON_SENDER";

    // Can only bisect assertion in response to a challenge
    string private constant BIS_STATE = "BIS_STATE";
    // deadline expired
    string private constant BIS_DEADLINE = "BIS_DEADLINE";
    // Only original asserter can continue bisect
    string private constant BIS_SENDER = "BIS_SENDER";

    address internal rollupAddress;
    address payable internal asserter;
    address payable internal challenger;

    uint256 internal deadlineTicks;

    // The current deadline at which the challenge timeouts and a winner is
    // declared. This deadline resets at each step in the challenge
    uint256 private challengePeriodTicks;

    State private state;

    modifier asserterAction {coverage_0x94099878(0x79ab23f2143a6a8ca8d6c4d5642fd401dd90cc7e50c95d8a8798e285345989a3); /* function */ 

coverage_0x94099878(0x86b884d9c7a129d4a0cd0ebb827780835898f7cbb82258b4f27e88bd9cf0e2ee); /* line */ 
        coverage_0x94099878(0x1aababbcac14d9e17f16bd52db7d8838cf9945bb770c342f3c003fbb1faccd70); /* assertPre */ 
coverage_0x94099878(0xfa956a146223ab88fe2c1008eb12b96dcb90d41d406db9426c581a2025a452ce); /* statement */ 
require(State.AsserterTurn == state, BIS_STATE);coverage_0x94099878(0x29429996041215e928cff3dd224e1e179fb109732d1412aefb61706873c84ae5); /* assertPost */ 

coverage_0x94099878(0x8111fd943191138004756054da5619e05344bb44662b96180f537dd05e5d21ea); /* line */ 
        coverage_0x94099878(0xc1ce7800cd3c08e6cde790f78b3089d9083a6591182cdc9302e9abff7738475a); /* assertPre */ 
coverage_0x94099878(0x5b5bf1fe303ff9f6a3afe7b9e764532e2630deb0ba5f25478da73bb343ea110f); /* statement */ 
require(RollupTime.blocksToTicks(block.number) <= deadlineTicks, BIS_DEADLINE);coverage_0x94099878(0x68420c746762a57899286e094024a7e8128d83e2a7a8f04109a6f5a92bdc5390); /* assertPost */ 

coverage_0x94099878(0x4f1f4ef02e4dddc82a9a3cfd04b5bd5ead9ce93b761a2367e3bb03ce4c641947); /* line */ 
        coverage_0x94099878(0xe22158e27ea200ecb9704dfa1e01374c51ef39093b66b2bac7dfa9b530893be5); /* assertPre */ 
coverage_0x94099878(0x97e10826099f4aa8dcfdead6fec404b7ebbd5270a0ca07b18b4a94f516c438c0); /* statement */ 
require(msg.sender == asserter, BIS_SENDER);coverage_0x94099878(0xa94fa5da93ae2c94c061a508267d2c7f5e8bea54ff23e7fdd8a92466d1fafab1); /* assertPost */ 

coverage_0x94099878(0x768c19ef1e56e4319ddb5409f0ad667f67bc02125a920a77a3601932cc9e13fc); /* line */ 
        _;
    }

    modifier challengerAction {coverage_0x94099878(0x70447a903ec2dbdbd0b290bf9e27d8339738bf1555ccf055719d91f224b5277b); /* function */ 

coverage_0x94099878(0x1f36bf56f046d87f1d6265b19ddd7d248455015ece707ee1a291f4fbd1af9402); /* line */ 
        coverage_0x94099878(0xe4dbfcec5e208648b627c86d1b7036f875fb0aa504034854709c3c3256725c16); /* assertPre */ 
coverage_0x94099878(0x8df4609066fe21be05234a1db9621a91210b3689263c690d759435b95f7e803e); /* statement */ 
require(State.ChallengerTurn == state, CON_STATE);coverage_0x94099878(0x7cac51119cbe8e8c7a8044b18303b69df638521f92ddd68d5698bc80f4c482ef); /* assertPost */ 

coverage_0x94099878(0xa522a437283ffee2ba8865a2e72d8ffae95eb26ef5cd36d4be0cc76d893f6119); /* line */ 
        coverage_0x94099878(0x91996bb8db225284ef59f2b4fb5e93772a2e013d12ba9619beddfe74a1d3e68c); /* assertPre */ 
coverage_0x94099878(0xf20b827f7be0176a323d0a2daff643cbc57b2959bfce3fae0c67a23dbd372302); /* statement */ 
require(RollupTime.blocksToTicks(block.number) <= deadlineTicks, CON_DEADLINE);coverage_0x94099878(0x141ad90e74af1a208c87fbfa90407cbb04a7b0cf9c05997f231e85bc49b50c51); /* assertPost */ 

coverage_0x94099878(0x4ebb698965ab6c501dbfe71713cb73510163209560cf501c4235b69392b8871d); /* line */ 
        coverage_0x94099878(0xd2abfa20ac28928010a18dd2ce0ae597183bd7cb35e984ffa11bf3715c545e47); /* assertPre */ 
coverage_0x94099878(0x6452ee466626eee6466e8f145c42b383d48b86bb01e07abf587d35a07fd447c8); /* statement */ 
require(msg.sender == challenger, CON_SENDER);coverage_0x94099878(0x0b639263ba75a48f248cea320129d9609d6eeaf7d99e6c943f695882b2f23f5d); /* assertPost */ 

coverage_0x94099878(0x203ca3a05d8cc98c5d41b12d37e03839360515ec47acc0fd20e9f53b9d5a8b39); /* line */ 
        _;
    }

    function timeoutChallenge() public {coverage_0x94099878(0xe2f4bbf2cac39b28aef6a02cc1e72a2ddf5a3c5f4809131c34bfc5a1eaaa1565); /* function */ 

coverage_0x94099878(0x593d0e49af4719c7fedc2e859d4b4bb96fffa8ca8aba8dfd41e417adb1a2c1ed); /* line */ 
        coverage_0x94099878(0x31c262c4bd1f268e6abdabd0b1eea144b86b5354d8473c50651efef0214115d9); /* assertPre */ 
coverage_0x94099878(0x136008ba2391122bb1b1cc6690fefd6283afaabde1996ed85baf1f753455c330); /* statement */ 
require(RollupTime.blocksToTicks(block.number) > deadlineTicks, "Deadline hasn't expired");coverage_0x94099878(0x3a27f10a1f6cc851ad71ea7c7b74fa84f812918f0117aa690c1483b052d14948); /* assertPost */ 


coverage_0x94099878(0x731cafa7ceadcc94eb9ee8591b23600ced93eb7092ad8f80336dada9a6faf401); /* line */ 
        coverage_0x94099878(0xeb0c4054648375d1762b41dd3c815f1e45c4e65ac1a5a6a70f30281090d74e28); /* statement */ 
if (state == State.AsserterTurn) {coverage_0x94099878(0xeafab1b02a28958719e354b8e037213475ac1c170790257e0b783d1c30f93128); /* branch */ 

coverage_0x94099878(0xb79926d9bd93e1a583bfc056c94690b555926eee6c4c03dbfe294b257760dfc1); /* line */ 
            coverage_0x94099878(0xabc28c3d42525f0b26332a919567d3511ece64ae0da8202af443221a6cb16d33); /* statement */ 
emit AsserterTimedOut();
coverage_0x94099878(0x86c92c0794adf626630f66c280e06cca33de9444b7c89f5cfa8f485724887dee); /* line */ 
            coverage_0x94099878(0x90a0ab64737c238fb023eb3c1050e27571f8471e0edbab4c8005b0173e8ff968); /* statement */ 
_challengerWin();
        } else {coverage_0x94099878(0xd199b608950cb36e3f748f8693b936a699efdd4c5d3beb90be97e0529acbb8cc); /* branch */ 

coverage_0x94099878(0x453eca53da93f219905514e40e37000f1df97b192da6e7199cc2eb667589fac8); /* line */ 
            coverage_0x94099878(0x1fecca3952e5ccfc5d21c1ad7f1a070145b5aa4a79f2efd58e9f372ec9a46e29); /* statement */ 
emit ChallengerTimedOut();
coverage_0x94099878(0x4b331b74cc42a37ceb4e6ba773ea8311d5eaa60d1f56b7ef7336ffded78be048); /* line */ 
            coverage_0x94099878(0xbe44dbf458d93e5739ef5f80092d5a49c860244b86314c808b25d105762cf2a8); /* statement */ 
_asserterWin();
        }
    }

    function initializeChallenge(
        address _rollupAddress,
        address payable _asserter,
        address payable _challenger,
        uint256 _challengePeriodTicks
    ) internal {coverage_0x94099878(0x5efa226100427600aa4f3e389af00433b68dc7b20ada0f401c50ca571858c528); /* function */ 

coverage_0x94099878(0x7f2e0ca6fa607462642e3781e16a3b8e5364935845656b98da38cb55187ad135); /* line */ 
        coverage_0x94099878(0x3a9d34cc96a7688ba8021a9002d41a44dd7be62358b10bd04fb83175e191faaf); /* assertPre */ 
coverage_0x94099878(0x7917fa5f90fabf64f18a6f6a314e4e48230659392b26d23bbd51bc24894bcad0); /* statement */ 
require(state == State.NoChallenge, CHAL_INIT_STATE);coverage_0x94099878(0x9925b5348d7d85c0aa09d987d9a39674ffca11cf5f4b8d68646b69ff62cc84f5); /* assertPost */ 


coverage_0x94099878(0x414691c33945fea9e3a12df927aad04e539ab0a382f24f48d21cce9dca88a3c8); /* line */ 
        coverage_0x94099878(0x1ec7391cb00cd00eb74c78d84b95a81a85556fc23072fe17b0911b3dc57fde8f); /* statement */ 
rollupAddress = _rollupAddress;
coverage_0x94099878(0x7248caf6fb2a0d295e050095f69cc4a882229c833b2ccead7e9e3f4251f40e8c); /* line */ 
        coverage_0x94099878(0x82a36e78da53f065eff7d15f8e47666e55c61ccf00332acf9abbea022de7ac73); /* statement */ 
asserter = _asserter;
coverage_0x94099878(0xcb40f6fd124a6290af4f23f8f4f799a9700b716bb64b64070eaa1f9e151931ac); /* line */ 
        coverage_0x94099878(0xadfe1a46d7190b5cd88947989f98bfdcdb72dc8fec43f7a33d8fada64f46590f); /* statement */ 
challenger = _challenger;
coverage_0x94099878(0xba1192146fce7502f885155989b69eba91f1f4d46e3aeb3bed370310979abda3); /* line */ 
        coverage_0x94099878(0x9dd57a8e78566ef15b8fd684d84511dd28c86eb8d440885026e495024a887d49); /* statement */ 
challengePeriodTicks = _challengePeriodTicks;
coverage_0x94099878(0x06f9a8fabf9744ab17c5efe84a7da81adbfe70d6dc69646b9dd7ff5c95c2ee2d); /* line */ 
        coverage_0x94099878(0x299d7c4aa30b3c4226481ec927330bd02ae53ffbbecfbc9183c09c81c8e06c00); /* statement */ 
state = State.AsserterTurn;
coverage_0x94099878(0x34913b2696ccb0bd44f399ff3d50aa78d7e659d1bb363a196b9c1d2cf675f517); /* line */ 
        coverage_0x94099878(0xfa73060dcf702e850ba2bb018e59f90d7237879cbc4470d0a84e078ee21f77d1); /* statement */ 
updateDeadline();

coverage_0x94099878(0xee54f02568a9dfb815508e557360737e335ac2219e598e18a946bb24983e1b14); /* line */ 
        coverage_0x94099878(0xfba96379c066c71a3d17d66c10ba88d48bf8c98a6613dceea1944e4d4e19b0bd); /* statement */ 
emit InitiatedChallenge(deadlineTicks);
    }

    function updateDeadline() internal {coverage_0x94099878(0xc6a81e0cb898dc3738d65eb072876281a8bff08f2657cbf7963d19a67580e9b5); /* function */ 

coverage_0x94099878(0x09f5cdd275ea43537d81277b79adf37b1d6f24b43a309f0a4658e9675e32dde8); /* line */ 
        coverage_0x94099878(0xeadae6d2ea828c8a2306a1cc4dd966a244bc0e31ff49072cd839770ce5509055); /* statement */ 
deadlineTicks = RollupTime.blocksToTicks(block.number) + challengePeriodTicks;
    }

    function asserterResponded() internal {coverage_0x94099878(0xd057e321aa46a06b8196d50c40e152d69c6b2570d224e98b8aa5bdd2ef4d3080); /* function */ 

coverage_0x94099878(0x11a8f4fc2ae706c6ac3dd09618ea8eba6c373ed3c252d166d988599014896a8d); /* line */ 
        coverage_0x94099878(0x42e19cf10865da05fdada1bedc1962a99b89131f20aaa5c724030eabd18fc3db); /* statement */ 
state = State.ChallengerTurn;
coverage_0x94099878(0xb4b2af746b989f1b5943cc9c53c41bd7223450d2a5d03ed30f5a5a35a0387f57); /* line */ 
        coverage_0x94099878(0xf4b1085604302a6f3e4608e84b28be11985af427436700be22cf43c65aaef096); /* statement */ 
updateDeadline();
    }

    function challengerResponded() internal {coverage_0x94099878(0x187db1d01c864283cd168cad9a9825aaa024e2ec3c51b0927c2a810d73d7fd36); /* function */ 

coverage_0x94099878(0x6b304771d59994189e09325f38e256dece88fc5aa562f6827c9843ea3a8ad8dd); /* line */ 
        coverage_0x94099878(0x2b1c037fb9b9c632376a69ea265b864c31d3383f08f4ca2493b084a5ab456c41); /* statement */ 
state = State.AsserterTurn;
coverage_0x94099878(0xf9f5cd6bc60339ddf4b5bb18af260e50d7046ca6b1fa953c1e6cbfea167bb62b); /* line */ 
        coverage_0x94099878(0x31226d9a49f6210dfe2b1b7e8161f651a173c5f2adbfaba9a43364f06b2b5e12); /* statement */ 
updateDeadline();
    }

    function _asserterWin() internal {coverage_0x94099878(0x0f5a9dcbcc9e6fb0506cc734c55b54e4934c8699f756e5be19830f10ab8b3cc9); /* function */ 

coverage_0x94099878(0xd0f45fbccf4a1dcc5cbab16e036942efcb4a30639bcefc06be7d4d26100cf63c); /* line */ 
        coverage_0x94099878(0x2756e23e33166154fa3015fcaa520407888514147b14d5540e3bef6c52b628bc); /* statement */ 
IStaking(rollupAddress).resolveChallenge(asserter, challenger);
coverage_0x94099878(0x20a4bd2e6bc84a107e9f18287c1db946faebc9d3a55000f129335567b42c68c5); /* line */ 
        coverage_0x94099878(0xe301329b0abb04410a781f2edbd89376db5940addeb6fc45fe90f90550995862); /* statement */ 
safeSelfDestruct(msg.sender);
    }

    function _challengerWin() internal {coverage_0x94099878(0x2b27c45758b7e60bface8716bf7ea57b5bf85898da5446049f9243055de36642); /* function */ 

coverage_0x94099878(0xc30042442809afb35a0d2045878b73a90879ce553d1f6b39fb860b19d1bca75f); /* line */ 
        coverage_0x94099878(0x99f0e488015f82d048819ac709bf520030975fbbb6fc0f76b7168a550202f83f); /* statement */ 
IStaking(rollupAddress).resolveChallenge(challenger, asserter);
coverage_0x94099878(0xc5ba11d10afefb79310557ff40159226648133430ada1e72a4b898253cafc0fb); /* line */ 
        coverage_0x94099878(0x0ef5cd676a159bec399dd8c6ef7ecb887d54a5b492d3819d74f766f8a82dc662); /* statement */ 
safeSelfDestruct(msg.sender);
    }
}
