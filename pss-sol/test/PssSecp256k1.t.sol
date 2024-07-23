// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {PssSecp256k1} from "../src/PssSecp256k1.sol";

contract PssSecp256k1Test is Test {
    PssSecp256k1 public pss;

    function setUp() public {
        uint256 pk_m_x = 0x2193f8dbd6e8e849e9592261ceba8906078a89b7cf596c7453a83cc79d12d098;
        uint256 pk_m_y = 0xe04e1a08a2fa08d40f6466676217180a24faacd6eb0aafc8ffba2bcb8550adf8;
        uint256 pk_icc_x = 0xcee1f1f90bdf3122857bc1c42f14317ff7a7d863ec31a9e42b81b692533fa5f2;
        uint256 pk_icc_y = 0xc5024b8e8978341b238f91e0810b9c214fcd7a2c45da9842216cdb10d0e46fcc;
        uint256 pk_sector_x = 0x37cba49a7c2cdef48453180bf068a04a7e13c440c560fe0d9474b529f223e793;
        uint256 pk_sector_y = 0xecfb6929733fdda34b393ed99b211daf8e05d612890101b3f85bc8fb6d0f1fa1;
        PssSecp256k1.GroupManagerPublicKey memory gpk = PssSecp256k1.GroupManagerPublicKey(pk_m_x, pk_m_y, pk_icc_x, pk_icc_y);
        pss = new PssSecp256k1(gpk, pk_sector_x, pk_sector_y);
    }

    function testValidateSignature() public {
        bytes memory message = new bytes(3);
        message[0] = 0x00;
        message[1] = 0x01;
        message[2] = 0x02;
        uint256 c = 0xe0452759835e9ef183d1423f36593946eb7a8365714770c9c39750a9a933707b;
        uint256 s1 = 0xd0e079ed7180875af4a33e45b9eabd13ac4495cefd1fa0fe7b0f85d324314402;
        uint256 s2 = 0x0643d2fca273bcd24c5522d8c1b10749646f56375f3920007b207eea9baef4cb;
        assertTrue(pss.validate_signature(message, c, s1, s2));
    }

    function testValidateSignatureP1() public {
        bytes memory message = new bytes(3);
        message[0] = 0x00;
        message[1] = 0x01;
        message[2] = 0x02;
        uint256 c = 0xc0f1ba093f20b56e064d366a87ddfbc4c976f71c1a48a1afbe0470015136877e;
        uint256 s1 = 0xce43577c286fb84c97e8472742ce6b03915bcc47474a98295aea5ddc867fcf4f;
        uint256 s2 = 0xaaa64e1f263d6781c2de2ba433ec4c21f2df55c9ee3e2dfb57c61a39dadc5155;
        uint256 i_sector_icc_1_x = 0xeed346335d29f9fcb4be53dc728b6639cbd35f7011d10a40ef137dffbfa87db9;
        uint8 i_sector_icc_1_parity = 0x02;
        assertTrue(pss.validate_signature_p1(message, c, s1, s2, i_sector_icc_1_parity, i_sector_icc_1_x));
    }

    function testValidateSignatureP2() public {
        bytes memory message = new bytes(3);
        message[0] = 0x00;
        message[1] = 0x01;
        message[2] = 0x02;
        uint256 c = 0x1c3df8b974b15948ef8ee7743cf3095108f8550be48cf838494cd6883dc20f68;
        uint256 s1 = 0x846cb54fe43468847fd9a0bfb1211c77fbc7dba44638827c1849048172477ead;
        uint256 s2 = 0x6c7ef5837341eed427d9f29fde513ae638fbf23fb7275bd61f8f8e7cbe05b65d;
        uint256 i_sector_icc_2_x = 0x9ee5722a3a79805acf80595dcf1377cba906a9336ca062509bc7cdc8e80e9e28;
        uint8 i_sector_icc_2_parity = 0x03;
        assertTrue(pss.validate_signature_p2(message, c, s1, s2, i_sector_icc_2_parity, i_sector_icc_2_x));
    }

    function testValidateSignatureP1P2() public {
        bytes memory message = new bytes(3);
        message[0] = 0x00;
        message[1] = 0x01;
        message[2] = 0x02;
        uint256 c = 0xa9192e26950d8f950fad697cd36e63b889cd26eb0d8b230d923da3834ac326bb;
        uint256 s1 = 0xf8f46ed1cc26ec06c3972cffb789dc8f5c5ddee43feda8b37d84043241e362ee;
        uint256 s2 = 0xbac0a45e47e8a26a85f19feda272c09669d30e72f5aa20c0cb03c61b4490a404;
        uint256 i_sector_icc_1_x = 0xeed346335d29f9fcb4be53dc728b6639cbd35f7011d10a40ef137dffbfa87db9;
        uint8 i_sector_icc_1_parity = 0x02;
        uint256 i_sector_icc_2_x = 0x9ee5722a3a79805acf80595dcf1377cba906a9336ca062509bc7cdc8e80e9e28;
        uint8 i_sector_icc_2_parity = 0x03;
        assertTrue(pss.validate_signature_p1_p2(message, c, s1, s2, i_sector_icc_1_parity, i_sector_icc_1_x, i_sector_icc_2_parity, i_sector_icc_2_x));
    }
}
