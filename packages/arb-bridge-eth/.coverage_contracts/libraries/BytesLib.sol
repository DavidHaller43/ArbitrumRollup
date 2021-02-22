// SPDX-License-Identifier: MIT

/*
 * @title Solidity Bytes Arrays Utils
 * @author Gonçalo Sá <goncalo.sa@consensys.net>
 *
 * @dev Bytes tightly packed arrays utility library for ethereum contracts written in Solidity.
 *      The library lets you concatenate, slice and type cast bytes arrays both in memory and storage.
 */

pragma solidity ^0.5.11;

/* solhint-disable no-inline-assembly */
library BytesLib {
function coverage_0xe48d970b(bytes32 c__0xe48d970b) public pure {}

    function toAddress(bytes memory _bytes, uint256 _start) internal pure returns (address) {coverage_0xe48d970b(0xe6cd9adf2f466f7fb562f98847c7658775c47cf76e7546dc285217144a7656c9); /* function */ 

coverage_0xe48d970b(0x69667aa9d49bf6ac40b25e0e61ebb2a87cf9ccb5f56b1f4c4d786b306df70ec6); /* line */ 
        coverage_0xe48d970b(0x0f83044db2af23efed8aba54a3cb1c403588778e217411b77a4916ae82d285d5); /* assertPre */ 
coverage_0xe48d970b(0x3b7300cbcf317a4af6a27e6d8a36dee61c9f1f88acb411a52bf80bc74e4bf71d); /* statement */ 
require(_bytes.length >= (_start + 20), "Read out of bounds");coverage_0xe48d970b(0xa5b27ee9748e3f35745927649363e4c859f3090ceb788258f266488b94f822c8); /* assertPost */ 

coverage_0xe48d970b(0x27f39c481124566ad08ad1fada64987c71178849cf2d606c477c2390f60e7438); /* line */ 
        coverage_0xe48d970b(0x3f0eb1bf182bea964786a017009d9d0af76431c1aa4e8d22e359a05f9850c8f0); /* statement */ 
address tempAddress;

coverage_0xe48d970b(0xa9329e12119c9b4aa53512fdc43d1effe7309ef1ae93d3394e5ff1eebedfcae6); /* line */ 
        assembly {
            tempAddress := div(mload(add(add(_bytes, 0x20), _start)), 0x1000000000000000000000000)
        }

coverage_0xe48d970b(0xc4b257a19f0947be2464aaa538d2a9e40a4e800bdd3a2d7455137fce8082a3ce); /* line */ 
        coverage_0xe48d970b(0x6d42a2a5f7dde765efa599037fb7d6cd013601c56b6796a0e34da6c1d2f2f4a2); /* statement */ 
return tempAddress;
    }

    function toUint8(bytes memory _bytes, uint256 _start) internal pure returns (uint8) {coverage_0xe48d970b(0xa5a5997d70c59e7aa04d93e217ac2edf2de56b12dad977b648be89dbda761cd1); /* function */ 

coverage_0xe48d970b(0xd52457f2c5f1fb633f699e15b8f7ebd194ecd4adf095c06ced69d63bee2aa9af); /* line */ 
        coverage_0xe48d970b(0x774a029019ca4864309165714e0d45ae69f35f06c77322e4b55e18409fcc4105); /* assertPre */ 
coverage_0xe48d970b(0xab8fc681c338d2e977eaebad5ed45ef990c9b046e226917197ce43c463e73653); /* statement */ 
require(_bytes.length >= (_start + 1), "Read out of bounds");coverage_0xe48d970b(0x161aaed1f24f8759bd3231e4e02232eb5771e6255bce24f7cbdd0fdc9083d2cd); /* assertPost */ 

coverage_0xe48d970b(0xddd72280a066dbb4fae14433908b15278f3ec56aa29437a76606a56424a1a33c); /* line */ 
        coverage_0xe48d970b(0x57df1c5f08401e07a86e0ca8e13c22dc283429483a519ea4d05e982d03a160e9); /* statement */ 
uint8 tempUint;

coverage_0xe48d970b(0xf34f582836e3339eb0c2475175eb24dd2450ab8943c6a4bd47fcb8b18cf03086); /* line */ 
        assembly {
            tempUint := mload(add(add(_bytes, 0x1), _start))
        }

coverage_0xe48d970b(0x2aa256e42c055a1180220842f77681341ca19f7c5583d6a385c35f2ac380fa35); /* line */ 
        coverage_0xe48d970b(0xa41885341ed6d985f2cf13085ef2e627024fb5ed46eeb6b744bf8f439084f130); /* statement */ 
return tempUint;
    }

    function toUint(bytes memory _bytes, uint256 _start) internal pure returns (uint256) {coverage_0xe48d970b(0x490a9bdd133bec70aeffc62856144c7b222d0da597953b804ba47aec4289dfb0); /* function */ 

coverage_0xe48d970b(0x3c5a33595bde34fddf8502b8a4092d36fee8808c1aeeeb152d8b36acf4123a37); /* line */ 
        coverage_0xe48d970b(0xfac570fa18d365db584d8bb7d0c4a3c82535bf18330aa486f22e1a61d212f136); /* assertPre */ 
coverage_0xe48d970b(0x69f5866ff9c9a1c6cb7d586c98b4564acb2e137cb29630a24777a296ac836376); /* statement */ 
require(_bytes.length >= (_start + 32), "Read out of bounds");coverage_0xe48d970b(0xb1d941dab94a5ba09e02f8130ebb6148cea86ff06bbda821234be4bbce8de936); /* assertPost */ 

coverage_0xe48d970b(0x962b24f7c7ca4a5a33eddd365f233d08fa10e3ef0f6fae1b58297141cd4f47d5); /* line */ 
        coverage_0xe48d970b(0x2b7f27347fb4dd01b7f83f7bf889048560dc7126ea7d10d87d0c4a8c9f5cc915); /* statement */ 
uint256 tempUint;

coverage_0xe48d970b(0xc5ed98b4fdb593c01ed5490d37822ca37915e6890788cf388e5d69b2cb3e0825); /* line */ 
        assembly {
            tempUint := mload(add(add(_bytes, 0x20), _start))
        }

coverage_0xe48d970b(0x2b51aa46a7ddcd035b549090a6861bd6456e3410f7b7b184f812e0cc11f477cc); /* line */ 
        coverage_0xe48d970b(0xc1dbf442bdfa1dc08723d94554a63ff00f2ffa872a5fd359f678d6a1cc1a216d); /* statement */ 
return tempUint;
    }

    function toBytes32(bytes memory _bytes, uint256 _start) internal pure returns (bytes32) {coverage_0xe48d970b(0x2a500ec35a1ea52a0d60b95f632de5b1d308f927b5b51a70832b0e69c5f52cd0); /* function */ 

coverage_0xe48d970b(0x1cef7ddb833b44e2ef3366ce21631a7ae98084420dc6143a16091bb1f3d3dc53); /* line */ 
        coverage_0xe48d970b(0x68f7b3ee8cc31a44ae8d84f7699c3c98ee134ac1ce25109c0295b8fb50a1dab2); /* assertPre */ 
coverage_0xe48d970b(0xa138676a56dc046512b4747359b3b5ea962ed585a118b89517524aede487e955); /* statement */ 
require(_bytes.length >= (_start + 32), "Read out of bounds");coverage_0xe48d970b(0xe095e87129d02dc6fe87dc553f21125d337df52711dc625b6ecfa242996afca7); /* assertPost */ 

coverage_0xe48d970b(0x91bf80d31af0e3b5f307dd8f5142784bd3d899ec198f9e48736f61004ac1e9e2); /* line */ 
        coverage_0xe48d970b(0x2412e3d4f9fae3bd279a09175c7415893667e21b43a5b7d5748447f8884a65b4); /* statement */ 
bytes32 tempBytes32;

coverage_0xe48d970b(0x1cb746f3254429decc187ee0b1c621dbfc5078e22e2cd2cc8919e703928e851c); /* line */ 
        assembly {
            tempBytes32 := mload(add(add(_bytes, 0x20), _start))
        }

coverage_0xe48d970b(0x0fabb8efcd46ae6722c3afc207ab5761fb17ea3357e9250370c94d3fe6578906); /* line */ 
        coverage_0xe48d970b(0x5aa154f5c6bb3858df42a2a2e592035d800057068a39df5878098f8cbb3f3e6f); /* statement */ 
return tempBytes32;
    }
}
/* solhint-enable no-inline-assembly */
