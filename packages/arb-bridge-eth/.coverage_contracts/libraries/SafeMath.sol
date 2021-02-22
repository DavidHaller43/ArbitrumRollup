// SPDX-License-Identifier: MIT

pragma solidity ^0.5.11;

// SafeMath comes from @openzeppelin under the MIT License

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
function coverage_0x73f85bb9(bytes32 c__0x73f85bb9) public pure {}

    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {coverage_0x73f85bb9(0x4f31e41db37b2a978b1a7777e4b2257c35356a87d654fdf9e489ae285c4c97cc); /* function */ 

coverage_0x73f85bb9(0xc42907c0733e31af3d6be1ac2eb1c43397232fa4ed1caf603fb50b90daed2e34); /* line */ 
        coverage_0x73f85bb9(0xcd0110f65be07595f05b68841be166a848861904233dab1864a616680744a238); /* statement */ 
uint256 c = a + b;
coverage_0x73f85bb9(0xe99cc2a2a51fca742337cbb0314300d2a01160b0b773c9385201d3f0f83dff96); /* line */ 
        coverage_0x73f85bb9(0xa6a7178b42f27e2cdb2610faee141d12865aa9175d8c768d8ebb3b03f7791527); /* assertPre */ 
coverage_0x73f85bb9(0x248bd6158c381b3c426e488e3a4d84783b157db46f4800557a278711cd4b2355); /* statement */ 
require(c >= a, "addition overflow");coverage_0x73f85bb9(0x6728fd219ced6b6645fd13e042028861f041d8d51cd99d45561c0e89a46d1721); /* assertPost */ 


coverage_0x73f85bb9(0x785c3590083f19653a67f01f3c1a6f93280627311152d373a34d77bb600d1e4d); /* line */ 
        coverage_0x73f85bb9(0x6ed678c18918cd22d4ee577c097c425a89b985522ff75ccbef741c8b0942506e); /* statement */ 
return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {coverage_0x73f85bb9(0x6a7daa8290a16b749f42e23f9a611726022c2d4b73d5a4921469184ed505f18c); /* function */ 

coverage_0x73f85bb9(0xaa435288a8153887241e03c9adeaddc5b4d6170cacb736716c8291056f3d57f3); /* line */ 
        coverage_0x73f85bb9(0x302217fa2a3a2ffd81389701b6d5b456e451783d8f256c83591df0603efe4342); /* statement */ 
return sub(a, b, "subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {coverage_0x73f85bb9(0x38e36e69c12289ff174f7041558d82fe19be10a9382e8453bb8b2cbb691eb6cf); /* function */ 

coverage_0x73f85bb9(0x614f0527090f9c45389491c92a7ca27cc2aaeafedf9abfda88d4ddc43b9fff33); /* line */ 
        coverage_0x73f85bb9(0x350f5bc80e5f56f8cb3be10d146bf02473a989a65b2b8932d0f7079f0feb28a4); /* assertPre */ 
coverage_0x73f85bb9(0x7c1561c535ec83348a10db3808c0f54bc81ddc68ee92a549e5c91fdb46a55546); /* statement */ 
require(b <= a, errorMessage);coverage_0x73f85bb9(0x75ef703b7ec350290e982d50954a6f98140c3a42e42896e0837ee91263de1e63); /* assertPost */ 

coverage_0x73f85bb9(0xd4d6a298a9766c52b69387c0b6aae610e929f70a2fa57635cd243da7138981d8); /* line */ 
        coverage_0x73f85bb9(0x1703c8c59d27b5d486afd17a3c4440bf5f4b01915c17c11ab23385284707f262); /* statement */ 
uint256 c = a - b;

coverage_0x73f85bb9(0x553a538c999d6fdc6bb0e224f99d24239682b5da2fbeabe5eb692b3140c16e16); /* line */ 
        coverage_0x73f85bb9(0x97d5f32c8dc69c3dbbbcb2dfe249ca2cb265b7e2b33f8976d226bd0b04286b3c); /* statement */ 
return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {coverage_0x73f85bb9(0x588c27a777c1dff7988545259e3de925c23657932927bdc50461e7cbd20163d7); /* function */ 

        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
coverage_0x73f85bb9(0x5acfaa71bd6f3a5e8f6e28716e5da1f1a47f6ee25da87cb07540fda2214d1de9); /* line */ 
        coverage_0x73f85bb9(0x9751260dde4a32a13eb77b8d06b2c88e6f00a9ebb83ed943aa76e2467c94dd9a); /* statement */ 
if (a == 0) {coverage_0x73f85bb9(0x120fbfb048f1e74eed3ae5857f5908cff5cef65c576320a02830f14250500259); /* branch */ 

coverage_0x73f85bb9(0xf1e92306f117ab109d70a72b71e99f832cc4206201a398b118b582d55d906563); /* line */ 
            coverage_0x73f85bb9(0x94df05739aac289503a92a0ebbc8110a336058e6b2bc700323cffc936dceb2d6); /* statement */ 
return 0;
        }else { coverage_0x73f85bb9(0x48ce0d1f5210d2799963080b00bb3641abf31d4dfef075f4895f1091b503ce86); /* branch */ 
}

coverage_0x73f85bb9(0x095edc3a8ec9c46c13e9165674e0e3d9389b3cce52d588c3d50afae99b400add); /* line */ 
        coverage_0x73f85bb9(0xa1ad3ce584b1241f870872ed13d751e1add6eb5dc155d0c066368f2859beb204); /* statement */ 
uint256 c = a * b;
coverage_0x73f85bb9(0x0f4e8d7e51a7fa71b319c1bbcc20d1114bf22b5645ab20750e16229cf97fd82b); /* line */ 
        coverage_0x73f85bb9(0x40a66efb971da3040519d66faa1963c19282c30739c23b730b636cdb64db448f); /* assertPre */ 
coverage_0x73f85bb9(0xa48becb4b9e00252d5cf59273d7c3512855c79872007ffbb2dfe78ea58b3591e); /* statement */ 
require(c / a == b, "multiplication overflow");coverage_0x73f85bb9(0x6b362761b664c28ce8e7699b4529da8859ccad2ac3fe444048b7d47e4bd38f80); /* assertPost */ 


coverage_0x73f85bb9(0xc03e097ce8cf7e1a1fd2caa960c1b6c2a038840b81d3a14fb4b2185a844387bb); /* line */ 
        coverage_0x73f85bb9(0xef1241ae1f10e98a093d036b99af379afc0e7d4e724c60b06135e76e331f502e); /* statement */ 
return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {coverage_0x73f85bb9(0x2fc34f738c35cefc27de693ece4a0424af807307a14328cd093ddfa042c92fab); /* function */ 

coverage_0x73f85bb9(0x876de2877d2b548a3af913fbc56b01bcb5bdbed972d3cdb4c4a56e0f49038b60); /* line */ 
        coverage_0x73f85bb9(0x37b4394b512d6838e25beef395e076f2e81e14cc943f5e0bf9db042d723bf339); /* statement */ 
return div(a, b, "division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {coverage_0x73f85bb9(0x3ae074ac07e3e36430d0fc65f58324a0b09e3f44e6dc89a2c1d963325700cede); /* function */ 

        // Solidity only automatically asserts when dividing by 0
coverage_0x73f85bb9(0xebe4747ad9b4fd86a17eeb4ad01f005b34d176818c2e4dc02b0e46705261adba); /* line */ 
        coverage_0x73f85bb9(0x24474c726bbf75d675270731cf20abd3ffe7b1fffc46c848d4dec503ea2e668d); /* assertPre */ 
coverage_0x73f85bb9(0x3c3ebdac6782b00cf8d7e7123d9b476baa3bc54e200e54c3a5747795784d187a); /* statement */ 
require(b > 0, errorMessage);coverage_0x73f85bb9(0xfb55aa8c65c430d0b1b998c364cc12c95738a6a10ddce58d1857fc4b43795c6e); /* assertPost */ 

coverage_0x73f85bb9(0x857b4e1996716fd214591cdf8341a9c224bf6854594d570fcac14afdf5ed3edf); /* line */ 
        coverage_0x73f85bb9(0x1a8b83dcded6d9227979642037779851e86ff96a8b72781588af97a13ab17483); /* statement */ 
uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

coverage_0x73f85bb9(0xcc90496e76f0be433ab60a0518d43f457182f8be73791b6e340fdb69163dce51); /* line */ 
        coverage_0x73f85bb9(0xbf0fde4fff419e1a10d1106e794d4ed5942f90a506634832ff6daeff20e75e72); /* statement */ 
return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {coverage_0x73f85bb9(0x11b197e9727905f5bd7d85166e2819eb079de757224a189fb552aba7c017de93); /* function */ 

coverage_0x73f85bb9(0xb645c27d15fb0e35910a8dece6f9e19b830bf27145c92507fcce6ded4060e827); /* line */ 
        coverage_0x73f85bb9(0xea4ad06a0230b8e498f3e95ce27253d11be33297364e2ad84e91e3dd918ceee3); /* statement */ 
return mod(a, b, "modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {coverage_0x73f85bb9(0xd3c1528cbbcc32185ca0e6a6e51effe59ffbf5320ee2dcab0e762ac1a2218391); /* function */ 

coverage_0x73f85bb9(0x146ebe1a9724239898fc17e6a2b1a597f43c1ad91ee773c1125e9648833f5c28); /* line */ 
        coverage_0x73f85bb9(0xfebc8ff60b488a1a2a7e37f5b8ac0226ff4539766724e178ae01debcee5ae127); /* assertPre */ 
coverage_0x73f85bb9(0x1b643283b32425ddef7a1da180e080d0bea2ca9bbe12d2125550eb4317094e2a); /* statement */ 
require(b != 0, errorMessage);coverage_0x73f85bb9(0xedd590707209e806b7b0f0e99e3f30b6bd2cb2774e9688a3415d4847785b8057); /* assertPost */ 

coverage_0x73f85bb9(0xe442df66bf21174653415c4de3a16a204f548cdab27a31403efe3f55883cdc93); /* line */ 
        coverage_0x73f85bb9(0x372509123dcd7fd6886bfad2c775fac1d2b306660894a34612ab730d288f7681); /* statement */ 
return a % b;
    }
}
