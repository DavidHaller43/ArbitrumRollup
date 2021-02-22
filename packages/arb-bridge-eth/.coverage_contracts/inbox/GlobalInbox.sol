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

import "./GlobalEthWallet.sol";
import "./GlobalFTWallet.sol";
import "./GlobalNFTWallet.sol";
import "./IGlobalInbox.sol";
import "./Messages.sol";
import "./PaymentRecords.sol";

contract GlobalInbox is
    IGlobalInbox,
    GlobalEthWallet,
    GlobalFTWallet,
    GlobalNFTWallet,
    PaymentRecords // solhint-disable-next-line bracket-align
{
function coverage_0xf49d70be(bytes32 c__0xf49d70be) public pure {}

    uint8 internal constant ETH_TRANSFER = 0;
    uint8 internal constant ERC20_TRANSFER = 1;
    uint8 internal constant ERC721_TRANSFER = 2;
    uint8 internal constant L2_MSG = 3;
    uint8 internal constant INITIALIZATION_MSG = 4;
    uint8 internal constant L2_CONTRACT_PAIR = 5;

    struct Inbox {
        bytes32 value;
        uint256 count;
    }

    mapping(address => Inbox) private inboxes;

    function getInbox(address account) external view returns (bytes32, uint256) {coverage_0xf49d70be(0xd4e558f9542fd18a25175d2d32652119fd1f23e76fb2edcf2beb3365587f566f); /* function */ 

coverage_0xf49d70be(0xdfc6163a089751615c6d4d9d313313a94c2482696b34c628a0dc05f6a85f8285); /* line */ 
        coverage_0xf49d70be(0x64cb103e0233945fcb74a6a59651ec7dab4791dfe793f000e0cf68d4250566ff); /* statement */ 
Inbox storage inbox = inboxes[account];
coverage_0xf49d70be(0xb48d6bdc898960a142f95a294031419838fb6756bfd5410a056bcd27feadb8ab); /* line */ 
        coverage_0xf49d70be(0xdfe8b7a290af58e5fe7e7a33cc00dc9f80e3995e069bd8a5bad2e4363faf7213); /* statement */ 
return (inbox.value, inbox.count);
    }

    /**
     * @notice Process a set of marshalled messages confirmed by a rollup chain
     * @dev messageCounts and nodeHashes are used to uniquely identify messages in conjunction with PaymentRecords
     * @param messages Contiguously marshaled messages from a set of assertions
     * @param initialMaxSendCount Previous total message count sent by this sender
     * @param finalMaxSendCount Total message count sent by this sender after these messages
     */
    function sendMessages(
        bytes calldata messages,
        uint256 initialMaxSendCount,
        uint256 finalMaxSendCount
    ) external {coverage_0xf49d70be(0x99df5e60e59824005d3872fb987e86acf6e9b0bb3eba5b7ebf279b8e2aed7637); /* function */ 

coverage_0xf49d70be(0x25a1fde8b048e1b1524a1b97ed0e16c1ffb7fcb31f4b1a5fa6dce8ad0782033b); /* line */ 
        coverage_0xf49d70be(0xbd21cc82ef83b02ba02a7446504303e1e4e90594f4eaf9f0911503348e5c0588); /* statement */ 
bool valid;
coverage_0xf49d70be(0xd94243fe248f10124d21015fa5869d1ab3e1369765c2dfa5b65f14c50c012641); /* line */ 
        coverage_0xf49d70be(0x3786c2c9052820346508f543cee2560d4b161db6b5615ee70c4da47e297473f6); /* statement */ 
uint256 offset = 0;
coverage_0xf49d70be(0x2dfc03b92a80479dedf35cca58cc7ac537f28271bab68dc4b17566096573cd24); /* line */ 
        coverage_0xf49d70be(0xd46d8c2417c0ee67c2569f9936e497849ffc6a95349cee1502260533603d1be3); /* statement */ 
Messages.OutgoingMessage memory message;

coverage_0xf49d70be(0x852fd9e6a37c152d72e32a4de839cf147ab8bc5be199b89eba73188a15711cac); /* line */ 
        coverage_0xf49d70be(0x3d31fe11cf1bec0d4ea388b52e0b44210023f208223428a91ad8aecb05f5c035); /* statement */ 
for (uint256 i = initialMaxSendCount; i < finalMaxSendCount; i++) {
coverage_0xf49d70be(0xdc32475518ac3c075fee26aebe92a59bbfd65cc36a5ca69aacd353f7e537883c); /* line */ 
            coverage_0xf49d70be(0x37e07d4bc609bc90deca66e03566478a43ee48f631c6e0615601fe5d0288dc8f); /* statement */ 
(valid, offset, message) = Messages.unmarshalOutgoingMessage(messages, offset);
coverage_0xf49d70be(0x61b2a6c0a5f8af6bf7f3e2d808baa4b6835324733aa2f9c5276328e54a9aaaa6); /* line */ 
            coverage_0xf49d70be(0xb4506ad50a93fe4dcf32812d4a03b371ccb2d10947b9d9d25f14cd461549a1a0); /* statement */ 
if (!valid) {coverage_0xf49d70be(0xa7901693eb97383628f08d587b2e295c4b64dbc3279bf0c2be8518a592a0e078); /* branch */ 

coverage_0xf49d70be(0x24936b2b98ce577e6857328f9573df045fbd45ca3efa13202833ef2ac9bab29a); /* line */ 
                coverage_0xf49d70be(0x2c3e415b05619ae9bbcb1edaef83b2ca8c7ad898eca7b190d48d044939b65a45); /* statement */ 
return;
            }else { coverage_0xf49d70be(0xc3028c77ffb801ad3d9d9697632fada231193cb0bcdd0991087c6b73bd807532); /* branch */ 
}
coverage_0xf49d70be(0xaf04c8c8a0522ba1ed06fcaa955acf1f3b0406f645aedd59cef4ed5f7cb11e03); /* line */ 
            coverage_0xf49d70be(0x5fe4a7fe0e5f618c7f8194db23a76a41a8f68f851c174d7f947ca1bc7a889b19); /* statement */ 
sendDeserializedMsg(i, message);
        }
    }

    /**
     * @notice Send a generic L2 message to a given Arbitrum Rollup chain
     * @dev This method is an optimization to avoid having to emit the entirety of the messageData in a log. Instead validators are expected to be able to parse the data from the transaction's input
     * @param chain Address of the rollup chain that the ETH is deposited into
     * @param messageData Data of the message being sent
     */
    function sendL2MessageFromOrigin(address chain, bytes calldata messageData) external {coverage_0xf49d70be(0x066cf22817452fed6b6ef4b86ac031e0e0ac56f870358d9e0316f9278909a5d4); /* function */ 

        // solhint-disable-next-line avoid-tx-origin
coverage_0xf49d70be(0x6c78e8ef9011149b3eca0895901f4f92727e2ba2f840e67039c170a79f2511e3); /* line */ 
        coverage_0xf49d70be(0xc13a81efd3990852901a65ee96ccaa9aec8b8bc0a3ca9e44a13c86ca82345006); /* assertPre */ 
coverage_0xf49d70be(0x006bb23049cd5df574b8bd73bb9a262faafe4937509af1cb8f07b37e5515d16b); /* statement */ 
require(msg.sender == tx.origin, "origin only");coverage_0xf49d70be(0x81ac8eb760f32a30da9d3700c77c4f486347e24e76fbe0608c4e44ffbac3f206); /* assertPost */ 

coverage_0xf49d70be(0x7be62c90e0952acd95d4fc64a3f7a8df3c1d93c69f968833dc99990479a5c9ca); /* line */ 
        coverage_0xf49d70be(0x8fe2a5f8bb381dd67dfaecb2b2c2ca6086e4dea354024f302d2b6217582904c5); /* statement */ 
uint256 inboxSeqNum = _deliverMessageImpl(
            chain,
            L2_MSG,
            msg.sender,
            keccak256(messageData)
        );
coverage_0xf49d70be(0x7acc11c6b37892e6ef0482af4a09aa32b27ba6524d40e43c16b7da9675ccc81c); /* line */ 
        coverage_0xf49d70be(0xd3ce6be1de132290a204c049aeec1bbe8186bdb9e042566479108e930967bd07); /* statement */ 
emit MessageDeliveredFromOrigin(chain, L2_MSG, msg.sender, inboxSeqNum);
    }

    /**
     * @notice Send a generic L2 message to a given Arbitrum Rollup chain
     * @dev This method can be used to send any type of message that doesn't require L1 validation
     * @param chain Address of the rollup chain that the ETH is deposited into
     * @param messageData Data of the message being sent
     */
    function sendL2Message(address chain, bytes calldata messageData) external {coverage_0xf49d70be(0xacbed9e6ac15a9012d266eef0c7dddf7bf604e45b833b54d657b32968db19ecf); /* function */ 

coverage_0xf49d70be(0x272345f9efafd0a3016e5cca258efdbf3e852223ddbcbc7eea85ca290e31ba4e); /* line */ 
        coverage_0xf49d70be(0xea6f260f55d63cd6db4b3b90454ab8996889950bc74bc94cc97051865bb7920b); /* statement */ 
_deliverMessage(chain, L2_MSG, msg.sender, messageData);
    }

    function deployL2ContractPair(
        address chain,
        uint256 maxGas,
        uint256 gasPriceBid,
        uint256 payment,
        bytes calldata contractData
    ) external {coverage_0xf49d70be(0x8e5d4a5d5a3cd39a717fecca0969893769d04ad254e55851a7fd48923824756a); /* function */ 

coverage_0xf49d70be(0xc609a4c516ca3fc9d0a6e78531d397bb852cbd98d1fa5514fa3e4e2a5a29ec51); /* line */ 
        coverage_0xf49d70be(0x7fe6a590fd535c658d0c48773f019313312c80ed58d4f957f2f20191bb3f49a4); /* assertPre */ 
coverage_0xf49d70be(0x67e3c2e95b2c23ace740a04897c114c38b020efe7652f7c01a75afed1c839897); /* statement */ 
require(isContract(msg.sender), "must be called by contract");coverage_0xf49d70be(0x10aaa82f38a9cfc1b0c48e00e425c413b33a94b860edd3dd346b9872201600e3); /* assertPost */ 

coverage_0xf49d70be(0x9e98295c6c39bbcf9e8b3f1825cce480647ef7c3d0476e761156305b0c476c2d); /* line */ 
        coverage_0xf49d70be(0xa06427bacbd0f0eb3b6e20c9dcd8d405419bbf994f707243bdc868ec99d90a3f); /* statement */ 
requestPairing(msg.sender, chain);
coverage_0xf49d70be(0x7a8acaaff45da3e95885c8a52432b11413837f7662b05ecdd75bf8dfb396b117); /* line */ 
        coverage_0xf49d70be(0x92131dd6c984b8482027903846c7c5c74f786bf686d89fc9e7f307fb88a3ecfb); /* statement */ 
_deliverMessage(
            chain,
            L2_CONTRACT_PAIR,
            msg.sender,
            abi.encodePacked(maxGas, gasPriceBid, payment, contractData)
        );
coverage_0xf49d70be(0x13bdd775c7e2f3d0cd206275415f47330137de079f61763a5893e01297bf25c0); /* line */ 
        coverage_0xf49d70be(0xf4f6a6ffb2023a5aa9557a9d238fc1668df5f567bf2486bb3b090729bad4c184); /* statement */ 
emit BuddyContractPair(msg.sender, chain);
    }

    /**
     * @notice Send a generic L2 message to a given Arbitrum Rollup chain
     * @dev This method can be used to send any type of message that doesn't require L1 validation
     * @param messageData Data of the message being sent
     */
    function sendInitializationMessage(bytes calldata messageData) external {coverage_0xf49d70be(0x63373fc3bef5812bb3a923c52c4394786faba3272ba7f319c55e6772f999c58c); /* function */ 

coverage_0xf49d70be(0x0c61b54fc462296c0b049903d180129225ab2e82875c06e5332b2697f1889a39); /* line */ 
        coverage_0xf49d70be(0x480b49d6eb3184c4524338c4870f5070cb0a27bb41a57186b378006a622c9f51); /* statement */ 
_deliverMessage(msg.sender, INITIALIZATION_MSG, msg.sender, messageData);
    }

    /**
     * @notice Deposits ETH into a given Arbitrum Rollup chain
     * @dev This method is payable and will deposit all value it is called with
     * @param chain Address of the rollup chain that the ETH is deposited into
     * @param to Address on the rollup chain that will receive the ETH
     */
    function depositEthMessage(address chain, address to) external payable {coverage_0xf49d70be(0xc2904f59066f7afabb656539f2d46c181601ad070dcb54bd2b2daff373e0e63a); /* function */ 

coverage_0xf49d70be(0x3cf32de4f51c846f209fe879f57a0c802cc1da61d3dfbf5bcc35cc9ea9acbcc6); /* line */ 
        coverage_0xf49d70be(0x8ee18af332cc95ffaa8420dd2a53697ff20d7d6f76ad3932d79e0d25d28c3197); /* statement */ 
depositEth(chain);
coverage_0xf49d70be(0xe821a15bea95d22a1c90357bd06c4a10dce719b89699443fbb0eaf8709937be4); /* line */ 
        coverage_0xf49d70be(0x005f1185c25cde2defc50d3b6fba7f3e767407d12697b89412bc9f8fdb71bc3b); /* statement */ 
_deliverMessage(
            chain,
            ETH_TRANSFER,
            msg.sender,
            abi.encodePacked(uint256(uint160(bytes20(to))), msg.value)
        );
    }

    /**
     * @notice Deposits an ERC20 token into a given Arbitrum Rollup chain
     * @dev This method requires approving this contract for transfers
     * @param chain Address of the rollup chain that the token is deposited into
     * @param erc20 L1 address of the token being deposited
     * @param to Address on the rollup chain that will receive the tokens
     * @param value Quantity of tokens being deposited
     */
    function depositERC20Message(
        address chain,
        address erc20,
        address to,
        uint256 value
    ) external {coverage_0xf49d70be(0x6b4512f30b1e611c4962dee8d68fb3bba0f1c19659f8e28bb5698504ed48431c); /* function */ 

coverage_0xf49d70be(0xf303ecef124a53776dddc89947bd280e7809c79ab90908d9688d951982bb47b0); /* line */ 
        coverage_0xf49d70be(0xb638e8e0eae0fffb766c0bf93db71937012b6a3eed4c89b1dd5de021b9939f61); /* statement */ 
depositERC20(erc20, chain, value);
coverage_0xf49d70be(0x34740a2c1aee37f6915533b93f79ef53bafb499051726f5fabec7bd02c36e635); /* line */ 
        coverage_0xf49d70be(0x606a12d5f997c17d18609e84d2f1f1b70cc2991c0391837f9f4ea721e6eb5c57); /* statement */ 
_deliverMessage(
            chain,
            ERC20_TRANSFER,
            msg.sender,
            abi.encodePacked(uint256(uint160(bytes20(erc20))), uint256(uint160(bytes20(to))), value)
        );
    }

    /**
     * @notice Deposits an ERC721 token into a given Arbitrum Rollup chain
     * @dev This method requires approving this contract for transfers
     * @param chain Address of the rollup chain that the token is deposited into
     * @param erc721 L1 address of the token being deposited
     * @param to Address on the rollup chain that will receive the token
     * @param id ID of the token being deposited
     */
    function depositERC721Message(
        address chain,
        address erc721,
        address to,
        uint256 id
    ) external {coverage_0xf49d70be(0x1cd960f0d5f497e6eec1d77f84a45b415ba1c2e456714979a198c30f8842ccf2); /* function */ 

coverage_0xf49d70be(0xfc9b590a65aba4d41a59fd43bdf9f19ac83e8a1d3bbfc42065350ad12d513d4f); /* line */ 
        coverage_0xf49d70be(0x21272a8616acd827ba832ccb9d2bd7dcbd18dc71177c80b38040645ac60db27a); /* statement */ 
depositERC721(erc721, chain, id);
coverage_0xf49d70be(0x5aed29fee3e01c2495e25a1ca79857b94823b65aa97cfb02755334939ab24090); /* line */ 
        coverage_0xf49d70be(0x299937f32fa580eef422ca5d12713762764f31a9f89993e95468e97af2197b97); /* statement */ 
_deliverMessage(
            chain,
            ERC721_TRANSFER,
            msg.sender,
            abi.encodePacked(uint256(uint160(bytes20(erc721))), uint256(uint160(bytes20(to))), id)
        );
    }

    function _deliverMessage(
        address _chain,
        uint8 _kind,
        address _sender,
        bytes memory _messageData
    ) private {coverage_0xf49d70be(0x3752829fe0c2e6636948a81174910fe7efeb64f56e95e9c19c547a0ca00db83f); /* function */ 

coverage_0xf49d70be(0xd0c03c572188c8a7f1fed4b2e827301b40c8d97a169ca8c80c09b173fc9593ff); /* line */ 
        coverage_0xf49d70be(0xee82d415b28a6e6fd37664d92eee7c30b8d45abd56637ee4e4532d46b9bec5c4); /* statement */ 
uint256 inboxSeqNum = _deliverMessageImpl(_chain, _kind, _sender, keccak256(_messageData));
coverage_0xf49d70be(0x3364bcd5c3a99e06024434d586a370f7be6bd916cb664417ab57fc8199a767e0); /* line */ 
        coverage_0xf49d70be(0x1a4dc42a34e07f17c4ab49b655f410fb38b045d18fc91a4b4273a92a1c70e4c5); /* statement */ 
emit MessageDelivered(_chain, _kind, _sender, inboxSeqNum, _messageData);
    }

    function _deliverMessageImpl(
        address _chain,
        uint8 _kind,
        address _sender,
        bytes32 _messageDataHash
    ) private returns (uint256) {coverage_0xf49d70be(0xd35e1e6e47607a2a9215ed3b31d2e9bbd15347cfe6c0865f0c2acdf95686a5ea); /* function */ 

coverage_0xf49d70be(0x14dd54c7ea0736beecc9d7f48c05391e5507d086a3e41115ad34650a83bfe9e8); /* line */ 
        coverage_0xf49d70be(0x1c1bbae5616414124e4ac639935fce3ed4762f157ddbbda2f37b72bfdff1b7d4); /* statement */ 
Inbox storage inbox = inboxes[_chain];
coverage_0xf49d70be(0xd17f073ccd91536a9b06c61cbf2ac29d2ccaff24466d6ee1a08c7d5f260afe73); /* line */ 
        coverage_0xf49d70be(0xc31ce2788b6067fbf08c998e136b72811d56afc1166868a0cdabe7b4b4461f38); /* statement */ 
uint256 updatedCount = inbox.count + 1;
coverage_0xf49d70be(0x1592d727ca49c502fb9f97802db2872b1b92c043136320e5c9863e2a54671fc0); /* line */ 
        coverage_0xf49d70be(0x6e1ed20ceab08938b10b7bf5e88c2344c8545dbb735bc27ec1290a44303e198e); /* statement */ 
bytes32 messageHash = Messages.messageHash(
            _kind,
            _sender,
            block.number,
            block.timestamp, // solhint-disable-line not-rely-on-time
            updatedCount,
            _messageDataHash
        );
coverage_0xf49d70be(0x2d91b45b8963799344fe5c895ac720ad41d4c8338d236ae7d2023d1da60330a9); /* line */ 
        coverage_0xf49d70be(0xa1c3b01743d96410f4e619a650069caf3bb69611dd0e316dcceb26a0cc9a6f38); /* statement */ 
inbox.value = Messages.addMessageToInbox(inbox.value, messageHash);
coverage_0xf49d70be(0xbeb5389abebfd1679ae2109c4cd754c897a26344ec628e96e694e00ba8fdf3bd); /* line */ 
        coverage_0xf49d70be(0x30262e9bc883e58d94f8ac391d7f04fa9cd2b96bc005904def913e84caa04542); /* statement */ 
inbox.count = updatedCount;
coverage_0xf49d70be(0x62598c6178ba1cc9adf65ea4914ea7997b937a005da43dc86be3e6665341ddf7); /* line */ 
        coverage_0xf49d70be(0x3def1a35a5be652cb3350a3b7cab7a08ba3f00ce90d8ebef475c5d04edfe2bf1); /* statement */ 
return updatedCount;
    }

    function sendDeserializedMsg(uint256 messageIndex, Messages.OutgoingMessage memory message)
        private
    {coverage_0xf49d70be(0x81a8360467ef76503c164cb4f70d7cf952579d441a940cce962a80a2e86c6846); /* function */ 

coverage_0xf49d70be(0x247d3e031a6b0979c36a42011baff73bbe4772a81b7d383668cc2912caebdb40); /* line */ 
        coverage_0xf49d70be(0xe4d82ff658df7d51e1af37b308f79f81a43f9f530028ab48665291ad7a1f75bb); /* statement */ 
if (message.kind == ETH_TRANSFER) {coverage_0xf49d70be(0x1cfe7a027f26df399a65e817959c1ba8b1542b6b302328caa16d0c8467624b5d); /* branch */ 

coverage_0xf49d70be(0x6089895af8bcec63ad4ed6f4f89519b1d91bbff078c010e5e9519f84153b7e0b); /* line */ 
            coverage_0xf49d70be(0x6b351ead6a5efe11d8dcbf7200fb683f41e999691b848d5165137f486f400f96); /* statement */ 
(bool valid, Messages.EthMessage memory eth) = Messages.parseEthMessage(message.data);
coverage_0xf49d70be(0xf6a0e0bc90257adf40cbb120635767d7615ab1ceea2c9636a4042f65019a4805); /* line */ 
            coverage_0xf49d70be(0xfc312773c4678c0b083f33f65300681adb5fab69e85fdd4b90a3812e73f70adc); /* statement */ 
if (!valid) {coverage_0xf49d70be(0x0cb0078a982b0a5f658c1bd0f8444a2b410bb66273eaee0229eeb2a2ec507029); /* branch */ 

coverage_0xf49d70be(0xb3de2cf77f5da52dd96c52f340e28bd47cb7ca20709f7eea0ca7212bf5f51aa0); /* line */ 
                coverage_0xf49d70be(0x60a78b4d124e2543428d8583c62595d7f1e4ee933e8426d4f1b4e331815a040c); /* statement */ 
return;
            }else { coverage_0xf49d70be(0xb5fca21c105f07d745e7a121d2f034929089e2678c6479edfd2ff33f300c74d4); /* branch */ 
}

coverage_0xf49d70be(0x2237c5feac7b9b116ab99cebbcad752215624bfb7be10b2b026db92c5f91d504); /* line */ 
            coverage_0xf49d70be(0x3d202678f2d2771f099d5274d25a88da5a2eadad5ceff61d1041d25aaea3773a); /* statement */ 
address paymentOwner = getPaymentOwner(eth.dest, messageIndex);
coverage_0xf49d70be(0x4c10df7fae1247c6b39c2e1e433bf93bdacf3765cc0bab9e971873d148ccb7a3); /* line */ 
            coverage_0xf49d70be(0x6f8257e77bf3e0af5ca75138b27afa61af4ec60f4896db2a672f3658b15b1a46); /* statement */ 
deletePayment(eth.dest, messageIndex);
coverage_0xf49d70be(0xa2ce6395be3165e890841b3f5d0dfb0e2f24f81e7b638fa8312b18497592151d); /* line */ 
            coverage_0xf49d70be(0x6a3166e82bd5a6aec90d2cf9c3e79a92b96cbb8df3d66a5f423854277e578018); /* statement */ 
transferEth(msg.sender, paymentOwner, eth.value);
        } else {coverage_0xf49d70be(0x167654a61341552becb71169b52a2434993def5bfd0d7c447e747dc446ffa1d6); /* statement */ 
coverage_0xf49d70be(0x5400a956141113885dd774aa78af4d28cc55d9139ad7fb6eb72cb32f316da41d); /* branch */ 
if (message.kind == ERC20_TRANSFER) {coverage_0xf49d70be(0x1d8dba658b69062b703b59096f96bb08a0e3990af81ef188acbff25a2761d9e8); /* branch */ 

coverage_0xf49d70be(0x8b9386085ef2a95d3a1290faa7e17f891275be597c92a754bf351cfa8de7800d); /* line */ 
            coverage_0xf49d70be(0x7676a7f46e0a67b082b36ccd7e7bdc3631cba78b8769c0fbaf9d426843393c4c); /* statement */ 
(bool valid, Messages.ERC20Message memory erc20) = Messages.parseERC20Message(
                message.data
            );
coverage_0xf49d70be(0x1ba75c1638205adba38d8bc4a42b511b312e8079e0e3c4ecf6f4096c0d2aa01f); /* line */ 
            coverage_0xf49d70be(0xc00e0be588c83760f29cce02bfcc8ee868c8c49b0e473b7a2722a880745d6f69); /* statement */ 
if (!valid) {coverage_0xf49d70be(0xe05a5ed03b6d089dc268a011feb1c04854bd6520b170d52b31bc2f4829ef9559); /* branch */ 

coverage_0xf49d70be(0xe7f8f07ff5a5ef70b6d937b907ab28b8adc79a08b5d8ef78dcea1ddef62875ef); /* line */ 
                coverage_0xf49d70be(0x5ee34cf8fff5f734263aac38d65c00a2e060bc041f8efb217b3642e9e4e00d22); /* statement */ 
return;
            }else { coverage_0xf49d70be(0xb9b1e29d87b1d359969901e005853b991efefb9e7b09485663b8aa17dcb5c202); /* branch */ 
}

coverage_0xf49d70be(0x126016c31dfaa1084dc3f74699ecff7f5f3a18297477cdaac5f5884741c7a29e); /* line */ 
            coverage_0xf49d70be(0x8ae4b748c9b2078bfcc127745818501d45c5bbf13eb3d78ba5590f09fbeb8076); /* statement */ 
address paymentOwner = getPaymentOwner(erc20.dest, messageIndex);
coverage_0xf49d70be(0x4eec775fb906849233f2be0ed92a811a08d67e4ee3d7455144176abfd7883659); /* line */ 
            coverage_0xf49d70be(0x9d26a558746f12fe323fabf7a371a80695dd07bba0bfe89bb0d34f697074267e); /* statement */ 
transferERC20(msg.sender, paymentOwner, erc20.token, erc20.value);
coverage_0xf49d70be(0xeb491bbd80af85e32b79af931ef7926f8e5bd5c0b18ff063fb42f79a8fa8babf); /* line */ 
            coverage_0xf49d70be(0x873c0b209a94741bda04a82014353f90db25be7b28af93c25a4a5110b2aa791e); /* statement */ 
deletePayment(erc20.dest, messageIndex);
        } else {coverage_0xf49d70be(0xa72026c63cc8f5328fdafba3dbf223d887b182dbd89c445a09fc6e7062ce1022); /* statement */ 
coverage_0xf49d70be(0xed84c5fad12d73390f7024ca18b4373bbc901620c4235d0fb58c23af8348d8ca); /* branch */ 
if (message.kind == ERC721_TRANSFER) {coverage_0xf49d70be(0x065ea126b34b70d73962e5ab765f28f473144c574196e1b7d62c94b01bb0e990); /* branch */ 

coverage_0xf49d70be(0xdf1808530e9c3bc319231d1ffa71cbd0f3f0bb02796469371a23446f6be35823); /* line */ 
            coverage_0xf49d70be(0x7b4b60087330b83e8e4653b6afb1b6980997e8ec9f5f8d00602cc405430b8c88); /* statement */ 
(bool valid, Messages.ERC721Message memory erc721) = Messages.parseERC721Message(
                message.data
            );
coverage_0xf49d70be(0xb9020e1ec848119daf612d4895f12c658129d9d564a468729025d28e427bd5e9); /* line */ 
            coverage_0xf49d70be(0x473ea766c528b97850394134f907b88d328a67b72c3bdc1f110a4f5352f79932); /* statement */ 
if (!valid) {coverage_0xf49d70be(0x06b0458a1bbff168162f0ecf1a5770858f939a4c85c76dccfe3353722a5694cc); /* branch */ 

coverage_0xf49d70be(0x5e6f195faa26cd98bee5164d3743cf5ea1621cfb4ebcc0df5802fdd17a8a29f3); /* line */ 
                coverage_0xf49d70be(0x422d443a79078042095b4265a0af0b6ccdba8f20c6df109a14603e75bcf29fbc); /* statement */ 
return;
            }else { coverage_0xf49d70be(0xfeb048aaffec5fef1d731cbb88f2cf98915281043aaa13821e44ac182f31255c); /* branch */ 
}

coverage_0xf49d70be(0x5e29e13835eac6f1cb3b98d17a116dd86a9aded48c97379c6231e680252ba21e); /* line */ 
            coverage_0xf49d70be(0x27cc3c236eb24bdbe538b7848eafef77b77b5c483f743c13c1a9ac8b16ec7009); /* statement */ 
address paymentOwner = getPaymentOwner(erc721.dest, messageIndex);
coverage_0xf49d70be(0xf6852a1eff5fd215658083908a11c10021f9af59304444abb96e71eaca2824e9); /* line */ 
            coverage_0xf49d70be(0xa9ee911ce5aac6438e2b3a8d7c502b0d04650a4bb0517e3123382b5849fe2745); /* statement */ 
transferNFT(msg.sender, paymentOwner, erc721.token, erc721.id);
coverage_0xf49d70be(0x7c7133afd060d4e93c309c4c2b19fb7a9c31d8bbd509d1fa249d2ab1b666c732); /* line */ 
            coverage_0xf49d70be(0xcb81539ebde44bb8f22e4657ef49e504adbde414589261d00bfc9abda6ca0404); /* statement */ 
deletePayment(erc721.dest, messageIndex);
        } else {coverage_0xf49d70be(0xa4478248835c895a4924a01c1ab8f721030bdf79ae12f899a864d36853ae37e9); /* statement */ 
coverage_0xf49d70be(0x7dc60ec50c99f70798cbd37e0cc8b6b9a789cea34dbec28439e8748178405df9); /* branch */ 
if (message.kind == L2_CONTRACT_PAIR) {coverage_0xf49d70be(0xf873f2a341fb2632b25f50a007ed5a07e7efb53ffbebdbe99c483152192a02e4); /* branch */ 

coverage_0xf49d70be(0xf197cab4a03fcca745767a9d99124d20222ea4c64dd454f5b2fab5eeafd93a0f); /* line */ 
            coverage_0xf49d70be(0xecd470af84b04eb0b159417906f3d0a7d01db07365ecaf83b5df8e53e5008080); /* statement */ 
updatePairing(message.sender, msg.sender, message.data[0] != 0);
coverage_0xf49d70be(0x1529c6b6a6da382ce2c8fbab61d0b6daddfd7e76ff200a9ef9ad613c53bffb4a); /* line */ 
            coverage_0xf49d70be(0x37a060443ad5e65c858a0aaf1c17fea1b92a51d1ebc95b35ea8c3d292f4a5a03); /* statement */ 
emit BuddyContractDeployed(message.sender, message.data);
        }else { coverage_0xf49d70be(0xccfbff3364b7222a80bfde48acb7e5eb8f90d6b3da4c615ec26e4a8ca31ab275); /* branch */ 
}}}}
    }

    // Implementation taken from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v3.1.0/contracts/utils/Address.sol)
    function isContract(address account) private view returns (bool) {coverage_0xf49d70be(0x281f171d11aab52a531d0c7dfa91eb5f82fda8337817ce73b4a6afc841457b24); /* function */ 

        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
coverage_0xf49d70be(0xa2abad6edaf8b25d8645caf8bd7af723bd815ed86dd369a539f29e80f7159cb1); /* line */ 
        coverage_0xf49d70be(0x6739ae2ca5411324895f6faf7b94ec55c1c14de44cf4c332c06a2151b279ddae); /* statement */ 
bytes32 codehash;

coverage_0xf49d70be(0xcec1ae853c8da40af168aeaed37a9dc913dbdee019de01d85b544896c1b72cf1); /* line */ 
        coverage_0xf49d70be(0x3602923d3e58afb2a5dc01ecfa39af88129669a1a6bbb690626d9cedbbd8f54a); /* statement */ 
bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
coverage_0xf49d70be(0xdecee58b331b7ecc7f28013154b4c69e40fbed99c119748978678f572d496607); /* line */ 
        assembly {
            codehash := extcodehash(account)
        }
coverage_0xf49d70be(0xab28c570bb18bc2cb2558b667205dbb6f3be5be1e8927c715a1a2ea95980846a); /* line */ 
        coverage_0xf49d70be(0x756dacc8e8291cadb51e455a169c61c7746cf53ef431bc10038c990ad5c46162); /* statement */ 
return (codehash != accountHash && codehash != 0x0);
    }
}
