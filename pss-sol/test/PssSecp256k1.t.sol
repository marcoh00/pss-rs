// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {PssSecp256k1} from "../src/PssSecp256k1.sol";

contract PssSecp256k1Test is Test {
    PssSecp256k1 public pss;

    function setUp() public {
        uint256 pk_m_x = 0xb80bc3a30299f7e9648c141d93fb9d61ad6257bafe1e5d93e4afa8f30e19e00e;
        uint256 pk_m_y = 0xd701072c1f7fa56463144869b6806a1b3dd950c9bd8e526c6addd99ab8550b56;
        uint256 pk_icc_x = 0x534c697122448f267968063d02d01c0cf44188d96cd99514607dbad6f4955950;
        uint256 pk_icc_y = 0x11c9f356fbe8281cb833f232e215a7c86a7cc5f3ac101045af0848e98681b7b8;
        uint256 pk_sector_x = 0x8b3deeeee07d19880f864772fc54a711200c7486ef40a3357e5737c837b2cad1;
        uint256 pk_sector_y = 0x7a0873e05aec944006bee4c1012079888c363a6aace0e651922ffae6f116ff08;
        PssSecp256k1.GroupManagerPublicKey memory gpk = PssSecp256k1.GroupManagerPublicKey(pk_m_x, pk_m_y, pk_icc_x, pk_icc_y);
        pss = new PssSecp256k1(gpk, pk_sector_x, pk_sector_y);
    }

    function testTellOutput() public {
        bytes memory message = new bytes(3);
        message[0] = 0x00;
        message[1] = 0x01;
        message[2] = 0x02;
        uint256 c = 0xdddedbb73809fa73132ce0d946bfde589ccc048ae3b860ab314840938da912a8;
        uint256 s1 = 0x8c00d39c38370e8ad9206d32dd0df320a280340e7f050a358eafef399a2973c7;
        uint256 s2 = 0xe5054106e049795cc3126220d93d773ed17c23ca9a2409fb6b4f27a622f94bd2;
        uint256 i_sector_icc_1_x = 0x70afa9712473338366d0037e10d1d1e9dd56a43772414ed731c290693ef53a44;
        uint8 i_sector_icc_1_parity = 0x03;
        uint256 i_sector_icc_2_x = 0x9354da7c85f63be2d109301713848975334b4dbf03eeab4b9d2218bd97b3f9c2;
        uint8 i_sector_icc_2_parity = 0x02;
        bytes memory hashinput = pss.recover_hash_input_p1_p2(message, c, s1, s2, i_sector_icc_1_parity, i_sector_icc_1_x, i_sector_icc_2_parity, i_sector_icc_2_x);
        bytes32 h = keccak256(hashinput);
        console.log("message");
        console.logBytes(message);
        console.log("hashinput");
        console.logBytes(hashinput);
        console.log("h");
        console.logBytes32(h);
        console.log("h as uint");
        console.log(uint256(h));
        console.log("c", c);
        console.log("c as bytes");
        console.logBytes32(bytes32(c));
    }
}
