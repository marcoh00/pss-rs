// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {PssSecp256k1} from "../src/PssSecp256k1.sol";

contract PssSecp256k1Test is Test {
    PssSecp256k1 public counter;

    function setUp() public {
        counter = new PssSecp256k1();
    }

    function test_Increment() public {
        assertEq(uint8(1), 1);
    }

    function testFuzz_SetNumber(uint256 x) public {
        assertEq(x, x);
    }
}
