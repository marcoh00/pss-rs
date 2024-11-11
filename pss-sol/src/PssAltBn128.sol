// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8;

import "./Altbn128.sol";
import "./IPssVerifier.sol";

import {console} from "forge-std/console.sol";


contract PssAltBn128 is IPssVerifier {
    bytes15 public constant DSI = "ECC-ALTBN128-G1";
    
    struct GroupManagerPublicKey {
        Pairing.G1Point pk_m;
        Pairing.G1Point pk_icc;
    }

    GroupManagerPublicKey public gpk;
    Pairing.G1Point public pk_sector;

    constructor(ECC.Point memory pk_m, ECC.Point memory pk_icc, ECC.Point memory _pk_sector) {
        gpk = GroupManagerPublicKey(Pairing.G1Point(pk_m.X, pk_m.Y), Pairing.G1Point(pk_icc.X, pk_icc.Y));
        pk_sector = Pairing.G1Point(_pk_sector.X, _pk_sector.Y);
    }

    function get_gpk() public view returns (uint256, uint256, uint256, uint256) {
        return (gpk.pk_m.X, gpk.pk_m.Y, gpk.pk_icc.X, gpk.pk_icc.Y);
    }

    function get_sector() public view returns (uint256, uint256) {
        return (pk_sector.X, pk_sector.Y);
    }

    function calc_q1(uint256 c, uint256 s1, uint256 s2) private view returns (Pairing.G1Point memory) {
        Pairing.G1Point memory q1s1 = Pairing.scalar_mul(gpk.pk_icc, c);

        console.log("c");
        console.logBytes(abi.encodePacked(c));

        console.log("pkicc X");
        console.logBytes(abi.encodePacked(gpk.pk_icc.X));

        console.log("pkicc Y");
        console.logBytes(abi.encodePacked(gpk.pk_icc.Y));

        console.log("q1s1 X");
        console.logBytes(abi.encodePacked(q1s1.X));

        console.log("q1s1 Y");
        console.logBytes(abi.encodePacked(q1s1.Y));

        Pairing.G1Point memory q1s2 = Pairing.scalar_mul(Pairing.base(), s1);

        console.log("q1s2 X");
        console.logBytes(abi.encodePacked(q1s2.X));

        console.log("s1");
        console.logBytes(abi.encodePacked(s1));

        Pairing.G1Point memory q1s3 = Pairing.scalar_mul(gpk.pk_m, s2);

        console.log("q1s3 X");
        console.logBytes(abi.encodePacked(q1s3.X));

        console.log("s2");
        console.logBytes(abi.encodePacked(s2));

        Pairing.G1Point memory q1s4 = Pairing.plus(q1s1, q1s2);
        console.log("q1s4 X");
        console.logBytes(abi.encodePacked(q1s4.X));

        Pairing.G1Point memory q1 = Pairing.plus(q1s3, q1s4);

        console.log("q1 X");
        console.logBytes(abi.encodePacked(q1.X));
        return q1;
    }

    function calc_a(Pairing.G1Point memory public_key, uint256 c, uint256 s) private view returns (Pairing.G1Point memory) {
        Pairing.G1Point memory c_x_pk = Pairing.scalar_mul(public_key, c);
        Pairing.G1Point memory s_x_sector = Pairing.scalar_mul(pk_sector, s);
        return Pairing.plus(c_x_pk, s_x_sector);
    }

    function validate_signature(bytes calldata message, uint256 c, uint256 s1, uint256 s2) public view override returns (bool) {
        console.log("validateSignature c");
        console.logBytes(abi.encodePacked(c));

        bytes memory hash_input = recover_hash_input(message, c, s1, s2);
        console.log("Hash Input:");
        console.logBytes(hash_input);

        bytes memory hashed = abi.encodePacked(keccak256(hash_input));
        console.log("Hashed:");
        console.logBytes(hashed);
        hashed[0] &= 0x1F;

        console.log("Hashed and shortened:");
        console.logBytes(hashed);

        uint256 asnum = uint256(bytes32(hashed));
        console.log("As number:");
        console.logUint(asnum);

        uint256 withmod = asnum % Pairing.PRIME_Q;
        console.log("ModN:");
        console.logUint(withmod);

        console.log("== c?");
        console.logUint(c);
        console.logBytes(abi.encodePacked(c));
        return withmod == c;
    }

    function recover_hash_input(bytes calldata message, uint256 c, uint256 s1, uint256 s2) public view returns (bytes memory) {
        Pairing.G1Point memory q1 = calc_q1(c, s1, s2);
        // Q || PK_Sector || ID_DSI || m
        return abi.encodePacked(
                uint8(4),
                q1.X,
                q1.Y,
                uint8(4),
                pk_sector.X,
                pk_sector.Y,
                DSI,
                message
        );
    }

    function validate_signature_p1(bytes calldata message, uint256 c, uint256 s1, uint256 s2, ECC.Point memory i_sector_icc_1) public view override returns (bool) {
        bytes memory hashed = abi.encodePacked(keccak256(recover_hash_input_p1(message, c, s1, s2, Pairing.G1Point(i_sector_icc_1.X, i_sector_icc_1.Y))));
        hashed[0] &= 0x1F;
        return uint256(bytes32(hashed)) % Pairing.PRIME_Q == c;
    }

    function recover_hash_input_p1(bytes calldata message, uint256 c, uint256 s1, uint256 s2, Pairing.G1Point memory i_sector_icc_1) public view returns (bytes memory) {
        Pairing.G1Point memory q1 = calc_q1(c, s1, s2);
        Pairing.G1Point memory a1 = calc_a(i_sector_icc_1, c, s1);
        // Q || I_sector_icc_1 || A1 || PK_Sector || ID_DSI || m
        return abi.encodePacked(
                uint8(4),
                q1.X,
                q1.Y,
                uint8(4),
                i_sector_icc_1.X,
                i_sector_icc_1.Y,
                uint8(4),
                a1.X,
                a1.Y,
                uint8(4),
                pk_sector.X,
                pk_sector.Y,
                DSI,
                message
        );
    }

    function validate_signature_p1_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, ECC.Point memory i_sector_icc_1, ECC.Point memory i_sector_icc_2) public view override returns (bool) {
        bytes memory hashed = abi.encodePacked(keccak256(recover_hash_input_p1_p2(message, c, s1, s2, Pairing.G1Point(i_sector_icc_1.X, i_sector_icc_1.Y), Pairing.G1Point(i_sector_icc_2.X, i_sector_icc_2.Y))));
        hashed[0] &= 0x1F;
        return uint256(bytes32(hashed)) % Pairing.PRIME_Q == c;
    }

    function recover_hash_input_p1_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, Pairing.G1Point memory i_sector_icc_1, Pairing.G1Point memory i_sector_icc_2) public view returns (bytes memory) {
        Pairing.G1Point memory q1 = calc_q1(c, s1, s2);
        Pairing.G1Point memory a1 = calc_a(i_sector_icc_1, c, s1);
        Pairing.G1Point memory a2 = calc_a(i_sector_icc_2, c, s2);
        // Q || I_sector_icc_1 || A1 || I_sector_icc_2 || A2 || PK_Sector || ID_DSI || m
        return abi.encodePacked(
                uint8(4),
                q1.X,
                q1.Y,
                uint8(4),
                i_sector_icc_1.X,
                i_sector_icc_1.Y,
                uint8(4),
                a1.X,
                a1.Y,
                uint8(4),
                i_sector_icc_2.X,
                i_sector_icc_2.Y,
                uint8(4),
                a2.X,
                a2.Y,
                uint8(4),
                pk_sector.X,
                pk_sector.Y,
                DSI,
                message
        );
    }

    function validate_signature_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, ECC.Point memory i_sector_icc_2) public view override returns (bool) {
        bytes memory hashed = abi.encodePacked(keccak256(recover_hash_input_p2(message, c, s1, s2, Pairing.G1Point(i_sector_icc_2.X, i_sector_icc_2.Y))));
        hashed[0] &= 0x1F;
        return uint256(bytes32(hashed)) % Pairing.PRIME_Q == c;
    }

    function recover_hash_input_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, Pairing.G1Point memory i_sector_icc_2) public view returns (bytes memory) {
        Pairing.G1Point memory q1 = calc_q1(c, s1, s2);
        Pairing.G1Point memory a2 = calc_a(i_sector_icc_2, c, s2);
        // Q || I_sector_icc_2 || A2 || PK_Sector || ID_DSI || m
        return abi.encodePacked(
                uint8(4),
                q1.X,
                q1.Y,
                uint8(4),
                i_sector_icc_2.X,
                i_sector_icc_2.Y,
                uint8(4),
                a2.X,
                a2.Y,
                uint8(4),
                pk_sector.X,
                pk_sector.Y,
                DSI,
                message
        );
    }

    function new_g1point(uint256 x, uint256 y) public pure returns (Pairing.G1Point memory) {
        return Pairing.G1Point(x, y);
    }

    function new_gpk(Pairing.G1Point memory pk_m, Pairing.G1Point memory pk_icc) public pure returns (GroupManagerPublicKey memory) {
        return GroupManagerPublicKey(
            pk_m, pk_icc
        );
    }
}
