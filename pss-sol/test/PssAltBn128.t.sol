// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import "../src/PssAltBn128.sol";

contract PssAltBn128Test is Test {
    PssAltBn128 public pss;

    function setUp() public {
        uint256 pk_m_x = 0x2419abedc7b63f91ee54f6a4f2541c45161df9502b1e963e1939490a2a5a3e84;
        uint256 pk_m_y = 0x091bac1d80add32c64a38c53d00e0e25a6ddb8c5b8f7ab141dac7b12e019aec5;
        uint256 pk_icc_x = 0x0e4c624a73693c74b52cb9f21c14ec6c4938ba9cb533c7d041332f381073aae1;
        uint256 pk_icc_y = 0x2d7db99fee244a5f5d30883b6186e54586c381805dbcdd79eafbab072fd3765a;
        uint256 pk_sector_x = 0x1f0c7c2177eb64558ff501d650046fdfca773947e786a526d862f1947a01de33;
        uint256 pk_sector_y = 0x1c5c86e03ebe022cb8fdb91dd1b1aa4153559fbca9d6ccb061a93190717c27d9;
        pss = new PssAltBn128(ECC.Point(pk_m_x, pk_m_y), ECC.Point(pk_icc_x, pk_icc_y), ECC.Point(pk_sector_x, pk_sector_y));
    }

    function test_validate_signature_sector_0() public {
        bytes memory message = new bytes(14);
        message[0] = 0x88;
        message[1] = 0x94;
        message[2] = 0xb8;
        message[3] = 0xfa;
        message[4] = 0x98;
        message[5] = 0xe0;
        message[6] = 0x49;
        message[7] = 0x7e;
        message[8] = 0x4c;
        message[9] = 0xa8;
        message[10] = 0x0e;
        message[11] = 0x8e;
        message[12] = 0x9c;
        message[13] = 0xf1;
        uint256 c = 0x07b68c42116d8b1000113a49b80d1bceaed6e5eca42864a7da477cca7c2d13e6;
        uint256 s1 = 0x16f8907125dc5340d032846a54b4c2803541ade5d9639f1cfbebfaeb783d5e4a;
        uint256 s2 = 0x02bc3b94e44d5ac7a36cb6269395802240ca5f99d63f055eb959a5fe54c799b6;
        assertTrue(pss.validate_signature(message, c, s1, s2));
    }
    function test_validate_signature_sector_0_p1() public {
        bytes memory message = new bytes(19);
        message[0] = 0x10;
        message[1] = 0x8f;
        message[2] = 0x79;
        message[3] = 0x89;
        message[4] = 0xd0;
        message[5] = 0x76;
        message[6] = 0x33;
        message[7] = 0x1f;
        message[8] = 0xbc;
        message[9] = 0xc0;
        message[10] = 0x8b;
        message[11] = 0xae;
        message[12] = 0xe7;
        message[13] = 0xd3;
        message[14] = 0xcb;
        message[15] = 0x76;
        message[16] = 0x58;
        message[17] = 0x75;
        message[18] = 0xee;
        uint256 c = 0x0c6910c92d500ec3e1e291dcd87aa7c15aa8c871cfd00b1beada20c8823edbbd;
        uint256 s1 = 0x0d5405c4ea8bb375ac9c3a3cdf395bec436fcee9f71c325ed8e22a6cc08b9d06;
        uint256 s2 = 0x12e7f4469ebb49b53639c94139590fc609e99725e5d006d58f62679d8e982978;
        ECC.Point memory i_sector_icc_1 = ECC.Point(0x18aa51bdbcbe392c9464a8fc9260ec9dc817efdafd0aab812747e733eaaa3d59, 0x1acd08ed14298178954d5bafc979824db731685139eebd21dbe17f49ba8fabb1);
        assertTrue(pss.validate_signature_p1(message, c, s1, s2, i_sector_icc_1));
    }
    function test_validate_signature_sector_0_p2() public {
        bytes memory message = new bytes(15);
        message[0] = 0x47;
        message[1] = 0x20;
        message[2] = 0xc1;
        message[3] = 0x43;
        message[4] = 0xf3;
        message[5] = 0xa9;
        message[6] = 0x59;
        message[7] = 0x10;
        message[8] = 0xc3;
        message[9] = 0x75;
        message[10] = 0xd3;
        message[11] = 0x97;
        message[12] = 0x04;
        message[13] = 0x12;
        message[14] = 0x29;
        uint256 c = 0x1392b664858c1d633812bd6d84a50ebf4a31c5319289bb868e8e4d1cb1027210;
        uint256 s1 = 0x1bc8172dde0919eeb3a9b5b14f1d49cfe8190713033d1be87bb4e45bfeab6123;
        uint256 s2 = 0x0be6375e8a2215565e3ab349804f0dbde434fec6214dee58d8f396a359ee6a21;
        ECC.Point memory i_sector_icc_2 = ECC.Point(0x2bf6b686dcea3c5bd27e06452a9a1798a4cf58d398e4843650e880f0685b10d8, 0x0ace8f228027fa3d7b11b4dc559d738459e3e614c124049a06f1baea4f9bc476);
        assertTrue(pss.validate_signature_p2(message, c, s1, s2, i_sector_icc_2));
    }
    function test_validate_signature_sector_0_p1_p2() public {
        bytes memory message = new bytes(12);
        message[0] = 0x86;
        message[1] = 0x26;
        message[2] = 0xde;
        message[3] = 0x58;
        message[4] = 0xe5;
        message[5] = 0x5e;
        message[6] = 0x94;
        message[7] = 0x5e;
        message[8] = 0x75;
        message[9] = 0x88;
        message[10] = 0xb9;
        message[11] = 0x0e;
        uint256 c = 0x072b834ee85a05be40bec3b1a3b82f58cd4abc27b7b93843e4b0f8a5a391af65;
        uint256 s1 = 0x0b53cbe80d0f6eff2248334ccd6b0aabbcb7dd6074c803b8e52900d6e42a3f24;
        uint256 s2 = 0x219c0c79d05567b65af04ebb62ecc7aabf21f39e1e52a092d5dd87262580b3af;
        ECC.Point memory i_sector_icc_1 = ECC.Point(0x18aa51bdbcbe392c9464a8fc9260ec9dc817efdafd0aab812747e733eaaa3d59, 0x1acd08ed14298178954d5bafc979824db731685139eebd21dbe17f49ba8fabb1);
        ECC.Point memory i_sector_icc_2 = ECC.Point(0x2bf6b686dcea3c5bd27e06452a9a1798a4cf58d398e4843650e880f0685b10d8, 0x0ace8f228027fa3d7b11b4dc559d738459e3e614c124049a06f1baea4f9bc476);
        assertTrue(pss.validate_signature_p1_p2(message, c, s1, s2, i_sector_icc_1, i_sector_icc_2));
    }
}
