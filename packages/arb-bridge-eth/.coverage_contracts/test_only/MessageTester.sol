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

import "../inbox/Messages.sol";

contract MessageTester {
    using Hashing for Value.Data;

    function messageHash(
        uint8 messageType,
        address sender,
        uint256 blockNumber,
        uint256 timestamp,
        uint256 inboxSeqNum,
        bytes32 messageDataHash
    ) public pure returns (bytes32) {
        return
            Messages.messageHash(
                messageType,
                sender,
                blockNumber,
                timestamp,
                inboxSeqNum,
                messageDataHash
            );
    }

    function messageValueHash(
        uint8 messageType,
        uint256 blockNumber,
        uint256 timestamp,
        address sender,
        uint256 inboxSeqNum,
        bytes memory messageData
    ) public pure returns (bytes32) {
        return
            Messages
                .messageValue(messageType, blockNumber, timestamp, sender, inboxSeqNum, messageData)
                .hash();
    }

    function addMessageToInbox(bytes32 inbox, bytes32 message) public pure returns (bytes32) {
        return Messages.addMessageToInbox(inbox, message);
    }

    function unmarshalOutgoingMessage(bytes memory data, uint256 startOffset)
        public
        pure
        returns (
            bool, // valid
            uint256, // offset
            uint8, // kind
            address, // sender
            bytes memory // data
        )
    {
        (bool valid, uint256 offset, Messages.OutgoingMessage memory message) = Messages
            .unmarshalOutgoingMessage(data, startOffset);
        return (valid, offset, message.kind, message.sender, message.data);
    }

    function parseEthMessage(bytes memory data)
        public
        pure
        returns (
            bool valid,
            address dest,
            uint256 value
        )
    {
        (bool isValid, Messages.EthMessage memory message) = Messages.parseEthMessage(data);
        return (isValid, message.dest, message.value);
    }

    function parseERC20Message(bytes memory data)
        public
        pure
        returns (
            bool valid,
            address token,
            address dest,
            uint256 value
        )
    {
        (bool isValid, Messages.ERC20Message memory message) = Messages.parseERC20Message(data);
        return (isValid, message.token, message.dest, message.value);
    }

    function parseERC721Message(bytes memory data)
        public
        pure
        returns (
            bool valid,
            address token,
            address dest,
            uint256 id
        )
    {
        (bool isValid, Messages.ERC721Message memory message) = Messages.parseERC721Message(data);
        return (isValid, message.token, message.dest, message.id);
    }
}
