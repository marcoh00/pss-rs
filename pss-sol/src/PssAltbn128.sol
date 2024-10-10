// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8;

import "./Altbn128.sol";
import "./IPssVerifier.sol";

contract PssAltbn128 is IPssVerifier {
    bytes13 public constant DSI = "ECC-ALTBN128-G1";
    
    struct GroupManagerPublicKey {
        Pairing.G1Point pk_m;
        Pairing.G1Point pk_icc;
    }

    GroupManagerPublicKey public gpk;
    Pairing.G1Point public pk_sector;

    constructor(GroupManagerPublicKey memory _gpk, Pairing.G1Point _pk_sector) {
        gpk = _gpk;
        pk_sector = _pk_sector;
    }

    function get_gpk() public view returns (uint256, uint256, uint256, uint256) {
        return (gpk.pk_m.X, gpk.pk_m.Y, gpk.pk_icc.X, gpk.pk_icc.Y);
    }

    function get_sector() public view returns (uint256, uint256) {
        return (pk_sector.X, pk_sector.Y);
    }

    function calc_q1(uint256 c, uint256 s1, uint256 s2) private view returns (Pairing.G1Point memory) {
        Pairing.G1Point q1s1 = Pairing.scalar_mul(gpk.pk_icc, c);
        Pairing.G1Point q1s2 = Pairing.scalar_mul(Pairing.G1_BASE, s1);
        Pairing.G1Point q1s3 = Pairing.scalar_mul(gpk.pk_m, s2);
        Pairing.G1Point q1s4 = Pairing.plus(q1s1, q1s2);
        return Pairing.plus(q1s3, q1s4);
    }

    function calc_a(Pairing.G1Point public_key, uint256 c, uint256 s) private view returns (Pairing.G1Point memory) {
        Pairing.G1Point c_x_pk = Pairing.scalar_mul(public_key, c);
        Pairing.G1Point s_x_sector = Pairing.scalar_mul(pk_sector, s);
        return Pairing.plus(c_x_pk, s_x_sector);
    }

    function validate_signature(bytes calldata message, uint256 c, uint256 s1, uint256 s2) public view override returns (bool) {
        return uint256(keccak256(recover_hash_input(message, c, s1, s2))) % Pairing.PRIME_Q == c;
    }

    function recover_hash_input(bytes calldata message, uint256 c, uint256 s1, uint256 s2) public view returns (bytes memory) {
        Pairing.G1Point q1 = calc_q1(c, s1, s2);
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

    function validate_signature_p1(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_1_parity, uint256 i_sector_icc_1_x) public view override returns (bool) {
        return uint256(keccak256(recover_hash_input_p1(message, c, s1, s2, i_sector_icc_1_parity, i_sector_icc_1_x))) % Pairing.PRIME_Q == c;
    }

    function recover_hash_input_p1(bytes calldata message, uint256 c, uint256 s1, uint256 s2, Pairing.G1Point i_sector_icc_1) public view returns (bytes memory) {
        Pairing.G1Point q1 = calc_q1(c, s1, s2);
        Pairing.G1Point a1 = calc_a(i_sector_icc_1, c, s1);
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

    function validate_signature_p1_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_1_parity, uint256 i_sector_icc_1_x, uint8 i_sector_icc_2_parity, uint256 i_sector_icc_2_x) public view override returns (bool) {
        return uint256(keccak256(recover_hash_input_p1_p2(message, c, s1, s2, i_sector_icc_1_parity, i_sector_icc_1_x, i_sector_icc_2_parity, i_sector_icc_2_x))) % PP == c;
    }

    function recover_hash_input_p1_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, Pairing.G1Point i_sector_icc_1, Pairing.G1Point i_sector_icc_2) public view returns (bytes memory) {
        Pairing.G1Point q1 = calc_q1(c, s1, s2);
        Pairing.G1Point a1 = calc_a(i_sector_icc_1, c, s1);
        Pairing.G1Point a2 = calc_a(i_sector_icc_2, c, s2);
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

    function validate_signature_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_2_parity, uint256 i_sector_icc_2_x) public view override returns (bool) {
        return uint256(keccak256(recover_hash_input_p2(message, c, s1, s2, i_sector_icc_2_parity, i_sector_icc_2_x))) % Pairing.PRIME_Q == c;
    }

    function recover_hash_input_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, Pairing.G1Point i_sector_icc_2) public view returns (bytes memory) {
        Pairing.G1Point q1 = calc_q1(c, s1, s2);
        Pairing.G1Point a2 = calc_a(i_sector_icc_2, c, s2);
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

    function new_gpk(Pairing.G1Point pk_m, Pairing.G1Point pk_icc) public pure returns (GroupManagerPublicKey memory) {
        return GroupManagerPublicKey(
            pk_m, pk_icc
        );
    }
}
