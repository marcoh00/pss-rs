// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import "../src/PssSecp256k1.sol";

contract CONTRACTNAME is Test {
    PssSecp256k1 public pss;

    function setUp() public {
        uint256 pk_m_x = 0x11784311499b67a32e8676a3133ce596f0071996e979afd539592ecf8ae4fd74;
        uint256 pk_m_y = 0x0d70e1bf3e4f9aa628caeea0f1fa1acc571aba960861471bcdc11fd60157b2b3;
        uint256 pk_icc_x = 0x6aae3f679e0efe123c7f61a8fb8170b5848aed9c117b047394d895467344ea02;
        uint256 pk_icc_y = 0xeb2296f6e82bfb8341383b65630a349c9abd78f81291bf1d410e488a93764d0e;
        uint256 pk_sector_x = 0xec0414f9cda5d7a4c603cd1a6dbad9b9f0af9f7866a6e6d59958418fb6fa89f3;
        uint256 pk_sector_y = 0x72726aa8d61befe2a47a0e1e1f3e07f8979add66640a5a729acd16ee9235536d;
        pss = new PssSecp256k1(ECC.Point(pk_m_x, pk_m_y), ECC.Point(pk_icc_x, pk_icc_y), ECC.Point(pk_sector_x, pk_sector_y));
    }

    function test_validate_signature_sector_0() public {
        bytes memory message = new bytes(22);
        message[0] = 0x6a;
        message[1] = 0x70;
        message[2] = 0x95;
        message[3] = 0x55;
        message[4] = 0x2e;
        message[5] = 0x66;
        message[6] = 0xd4;
        message[7] = 0x5b;
        message[8] = 0x10;
        message[9] = 0x2d;
        message[10] = 0x66;
        message[11] = 0x31;
        message[12] = 0x9c;
        message[13] = 0xce;
        message[14] = 0x03;
        message[15] = 0x10;
        message[16] = 0x14;
        message[17] = 0x47;
        message[18] = 0x34;
        message[19] = 0xbf;
        message[20] = 0xd7;
        message[21] = 0xbd;
        uint256 c = 0x68013fd0aa528169478c9efe3fcc61b73c7eb7c2c1b3dc4464d8fe83b5f19a1b;
        uint256 s1 = 0xd0a6f858c3d23cf73bbbe4d5f454916e0f629b2a25463daea91ead35a04caf2f;
        uint256 s2 = 0xa0b4577c84a96665d415f1682d6ac46c9d6dd6182f855e6166352536ec6b0b16;
        assertTrue(pss.validate_signature(message, c, s1, s2));
    }
    function test_validate_signature_sector_0_p1() public {
        bytes memory message = new bytes(32);
        message[0] = 0x50;
        message[1] = 0x96;
        message[2] = 0x6e;
        message[3] = 0x90;
        message[4] = 0xda;
        message[5] = 0xec;
        message[6] = 0x6f;
        message[7] = 0x3a;
        message[8] = 0x35;
        message[9] = 0x79;
        message[10] = 0x29;
        message[11] = 0xbd;
        message[12] = 0xca;
        message[13] = 0x88;
        message[14] = 0x59;
        message[15] = 0x07;
        message[16] = 0xa1;
        message[17] = 0x5b;
        message[18] = 0xf1;
        message[19] = 0x2a;
        message[20] = 0x6f;
        message[21] = 0xc1;
        message[22] = 0x6c;
        message[23] = 0xba;
        message[24] = 0x79;
        message[25] = 0x24;
        message[26] = 0xac;
        message[27] = 0x2e;
        message[28] = 0xa4;
        message[29] = 0xe8;
        message[30] = 0x0a;
        message[31] = 0x8a;
        uint256 c = 0xb15e97c2c772e9a82d7a79f2c8c9af5fdaf7f762124b7031102e2abc2bb3a2b4;
        uint256 s1 = 0x08789b17ac77429ef786432feaeffba56eb9e34117688736a50886d04cb7ba70;
        uint256 s2 = 0x977e6eb78ef477f632d52de8ebeca046e8b2fc6e405257e65216b370bed21815;
        ECC.Point memory i_sector_icc_1 = ECC.Point(0x54d86b3483163a39d265372e97021fdf39fe6633c268e59e1b97a69f56b8719f, 0xbfc1581e97e0fa880be62e71bf7cddd980f9c369e7cebdbf7c6abad4940b6259);
        assertTrue(pss.validate_signature_p1(message, c, s1, s2, i_sector_icc_1));
    }
    function test_validate_signature_sector_0_p2() public {
        bytes memory message = new bytes(28);
        message[0] = 0x1a;
        message[1] = 0x74;
        message[2] = 0x19;
        message[3] = 0x47;
        message[4] = 0x60;
        message[5] = 0xda;
        message[6] = 0x64;
        message[7] = 0xe2;
        message[8] = 0xec;
        message[9] = 0xba;
        message[10] = 0xdc;
        message[11] = 0x05;
        message[12] = 0x7c;
        message[13] = 0xd8;
        message[14] = 0xa4;
        message[15] = 0x56;
        message[16] = 0xeb;
        message[17] = 0xc5;
        message[18] = 0xa8;
        message[19] = 0x0f;
        message[20] = 0x6d;
        message[21] = 0xdd;
        message[22] = 0x17;
        message[23] = 0xbd;
        message[24] = 0x4b;
        message[25] = 0xcb;
        message[26] = 0x95;
        message[27] = 0x28;
        uint256 c = 0x6f742cfe187f2c5285c3e7d14ed010971682a89aad7cfb68ebac435e934960c7;
        uint256 s1 = 0xf5faf7ba815a6aac31a31ab1a2e99f55a492bc223e19f56cd3d98e4b3cfc214d;
        uint256 s2 = 0x5770a3434884501627605298358b46fd5861c2a9b064e7ee04579bc4b0e4850f;
        ECC.Point memory i_sector_icc_2 = ECC.Point(0xc1792bef8e672a2cdf7ca3a79440fe7fa2f41fcf0b8d5c7dd681cb1db56b039e, 0x57e5a6d8585e28e48016c3edf3def0aff9a7b06460f7766f64ad5b284a1c0c3b);
        assertTrue(pss.validate_signature_p2(message, c, s1, s2, i_sector_icc_2));
    }
    function test_validate_signature_sector_0_p1_p2() public {
        bytes memory message = new bytes(29);
        message[0] = 0x6e;
        message[1] = 0xfd;
        message[2] = 0x57;
        message[3] = 0x56;
        message[4] = 0xe9;
        message[5] = 0xe8;
        message[6] = 0x04;
        message[7] = 0xc1;
        message[8] = 0x74;
        message[9] = 0x9c;
        message[10] = 0x5d;
        message[11] = 0xb0;
        message[12] = 0x3b;
        message[13] = 0x10;
        message[14] = 0xe8;
        message[15] = 0x18;
        message[16] = 0xdc;
        message[17] = 0x3f;
        message[18] = 0x5c;
        message[19] = 0xab;
        message[20] = 0x33;
        message[21] = 0xfe;
        message[22] = 0xb1;
        message[23] = 0x9c;
        message[24] = 0xfa;
        message[25] = 0x13;
        message[26] = 0x02;
        message[27] = 0x50;
        message[28] = 0xcf;
        uint256 c = 0x06dc08c93da5171dbbd1e5e6ab6457615ca00a0e4b24a896ed69e00236119f3c;
        uint256 s1 = 0xe96114e6917e523c3f943635eea7301f2d1e2c38b77e1f39a0ac7f72c238353f;
        uint256 s2 = 0x286ac08e7f304d375ff9a4e44393ac609153e9bb7686b22687919e9923beeeba;
        ECC.Point memory i_sector_icc_1 = ECC.Point(0x54d86b3483163a39d265372e97021fdf39fe6633c268e59e1b97a69f56b8719f, 0xbfc1581e97e0fa880be62e71bf7cddd980f9c369e7cebdbf7c6abad4940b6259);
        ECC.Point memory i_sector_icc_2 = ECC.Point(0xc1792bef8e672a2cdf7ca3a79440fe7fa2f41fcf0b8d5c7dd681cb1db56b039e, 0x57e5a6d8585e28e48016c3edf3def0aff9a7b06460f7766f64ad5b284a1c0c3b);
        assertTrue(pss.validate_signature_p1_p2(message, c, s1, s2, i_sector_icc_1, i_sector_icc_2));
    }
}