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

package ethbridgetest

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"log"
	"os"
	"testing"

	"github.com/offchainlabs/arbitrum/packages/arb-validator-core/ethbridgetestcontracts"
	"github.com/offchainlabs/arbitrum/packages/arb-validator-core/test"
)

var valueTester *ethbridgetestcontracts.ValueTester
var messageTester *ethbridgetestcontracts.MessageTester

func TestMain(m *testing.M) {
	client, pks := test.SimulatedBackend()
	auth := bind.NewKeyedTransactor(pks[0])

	_, _, deployedValueTester, err := ethbridgetestcontracts.DeployValueTester(
		auth,
		client,
	)
	if err != nil {
		log.Fatal(err)
	}

	_, _, deployedMessageTester, err := ethbridgetestcontracts.DeployMessageTester(
		auth,
		client,
	)
	if err != nil {
		log.Fatal(err)
	}

	client.Commit()

	valueTester = deployedValueTester
	messageTester = deployedMessageTester

	code := m.Run()
	os.Exit(code)
}
