// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8;

import "elliptic-curve-solidity/contracts/EllipticCurve.sol";
import "./IPssVerifier.sol";

contract PssSecp256k1 is IPssVerifier {
    uint256 public constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    
    bytes13 public constant DSI = "ECC-SECP256K1";
    
    struct GroupManagerPublicKey {
        uint256 pk_m_x;
        uint256 pk_m_y;
        uint256 pk_icc_x;
        uint256 pk_icc_y;
    }

    GroupManagerPublicKey public gpk;
    uint256 public pk_sector_x;
    uint256 public pk_sector_y;

    constructor(GroupManagerPublicKey memory _gpk, uint256 _pk_sector_x, uint256 _pk_sector_y) {
        gpk = _gpk;
        pk_sector_x = _pk_sector_x;
        pk_sector_y = _pk_sector_y;
    }

    function get_gpk() public view returns (uint256, uint256, uint256, uint256) {
        return (gpk.pk_m_x, gpk.pk_m_y, gpk.pk_icc_x, gpk.pk_icc_y);
    }

    function get_sector() public view returns (uint256, uint256) {
        return (pk_sector_x, pk_sector_y);
    }

    function calc_q1(uint256 c, uint256 s1, uint256 s2) private view returns (uint256, uint256) {
        (uint256 q1s1_x, uint256 q1s1_y) = EllipticCurve.ecMul(c, gpk.pk_icc_x, gpk.pk_icc_y, AA, PP);
        (uint256 q1s2_x, uint256 q1s2_y) = EllipticCurve.ecMul(s1, GX, GY, AA, PP);
        (uint256 q1s3_x, uint256 q1s3_y) = EllipticCurve.ecMul(s2, gpk.pk_m_x, gpk.pk_m_y, AA, PP);
        (uint256 q1s4_x, uint256 q1s4_y) = EllipticCurve.ecAdd(q1s1_x, q1s1_y, q1s2_x, q1s2_y, AA, PP);
        return EllipticCurve.ecAdd(q1s3_x, q1s3_y, q1s4_x, q1s4_y, AA, PP);

    }

    function calc_a(uint256 public_key_x, uint256 public_key_y, uint256 c, uint256 s) private view returns (uint256, uint256) {
        (uint256 c_x_pk_x, uint256 c_x_pk_y) = EllipticCurve.ecMul(c, public_key_x, public_key_y, AA, PP);
        (uint256 s_x_sector_x, uint256 s_x_sector_y) = EllipticCurve.ecMul(s, pk_sector_x, pk_sector_y, AA, PP);
        return EllipticCurve.ecAdd(c_x_pk_x, c_x_pk_y, s_x_sector_x, s_x_sector_y, AA, PP);

    }

    function validate_signature(bytes calldata message, uint256 c, uint256 s1, uint256 s2) public view override returns (bool) {
        return uint256(keccak256(recover_hash_input(message, c, s1, s2))) % PP == c;
    }

    function recover_hash_input(bytes calldata message, uint256 c, uint256 s1, uint256 s2) public view returns (bytes memory) {
        (uint256 q1_x, uint256 q1_y) = calc_q1(c, s1, s2);
        // Q || PK_Sector || ID_DSI || m
        return abi.encodePacked(
                uint8(4),
                q1_x,
                q1_y,
                uint8(4),
                pk_sector_x,
                pk_sector_y,
                DSI,
                message
        );
    }

    function validate_signature_p1(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_1_parity, uint256 i_sector_icc_1_x) public view override returns (bool) {
        return uint256(keccak256(recover_hash_input_p1(message, c, s1, s2, i_sector_icc_1_parity, i_sector_icc_1_x))) % PP == c;
    }

    function recover_hash_input_p1(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_1_parity, uint256 i_sector_icc_1_x) public view returns (bytes memory) {
        (uint256 q1_x, uint256 q1_y) = calc_q1(c, s1, s2);
        uint256 i_sector_icc_1_y = EllipticCurve.deriveY(i_sector_icc_1_parity, i_sector_icc_1_x, AA, BB, PP);
        (uint256 a1_x, uint256 a1_y) = calc_a(i_sector_icc_1_x, i_sector_icc_1_y, c, s1);
        // Q || I_sector_icc_1 || A1 || PK_Sector || ID_DSI || m
        return abi.encodePacked(
                uint8(4),
                q1_x,
                q1_y,
                uint8(4),
                i_sector_icc_1_x,
                i_sector_icc_1_y,
                uint8(4),
                a1_x,
                a1_y,
                uint8(4),
                pk_sector_x,
                pk_sector_y,
                DSI,
                message
        );
    }

    function validate_signature_p1_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_1_parity, uint256 i_sector_icc_1_x, uint8 i_sector_icc_2_parity, uint256 i_sector_icc_2_x) public view override returns (bool) {
        return uint256(keccak256(recover_hash_input_p1_p2(message, c, s1, s2, i_sector_icc_1_parity, i_sector_icc_1_x, i_sector_icc_2_parity, i_sector_icc_2_x))) % PP == c;
    }

    function recover_hash_input_p1_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_1_parity, uint256 i_sector_icc_1_x, uint8 i_sector_icc_2_parity, uint256 i_sector_icc_2_x) public view returns (bytes memory) {
        (uint256 q1_x, uint256 q1_y) = calc_q1(c, s1, s2);
        uint256 i_sector_icc_1_y = EllipticCurve.deriveY(i_sector_icc_1_parity, i_sector_icc_1_x, AA, BB, PP);
        (uint256 a1_x, uint256 a1_y) = calc_a(i_sector_icc_1_x, i_sector_icc_1_y, c, s1);
        uint256 i_sector_icc_2_y = EllipticCurve.deriveY(i_sector_icc_2_parity, i_sector_icc_2_x, AA, BB, PP);
        (uint256 a2_x, uint256 a2_y) = calc_a(i_sector_icc_2_x, i_sector_icc_2_y, c, s2);
        // Q || I_sector_icc_1 || A1 || I_sector_icc_2 || A2 || PK_Sector || ID_DSI || m
        return abi.encodePacked(
                uint8(4),
                q1_x,
                q1_y,
                uint8(4),
                i_sector_icc_1_x,
                i_sector_icc_1_y,
                uint8(4),
                a1_x,
                a1_y,
                uint8(4),
                i_sector_icc_2_x,
                i_sector_icc_2_y,
                uint8(4),
                a2_x,
                a2_y,
                uint8(4),
                pk_sector_x,
                pk_sector_y,
                DSI,
                message
        );
    }

    function validate_signature_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_2_parity, uint256 i_sector_icc_2_x) public view override returns (bool) {
        return uint256(keccak256(recover_hash_input_p2(message, c, s1, s2, i_sector_icc_2_parity, i_sector_icc_2_x))) % PP == c;
    }

    function recover_hash_input_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_2_parity, uint256 i_sector_icc_2_x) public view returns (bytes memory) {
        (uint256 q1_x, uint256 q1_y) = calc_q1(c, s1, s2);
        uint256 i_sector_icc_2_y = EllipticCurve.deriveY(i_sector_icc_2_parity, i_sector_icc_2_x, AA, BB, PP);
        (uint256 a2_x, uint256 a2_y) = calc_a(i_sector_icc_2_x, i_sector_icc_2_y, c, s2);
        // Q || I_sector_icc_2 || A2 || PK_Sector || ID_DSI || m
        return abi.encodePacked(
                uint8(4),
                q1_x,
                q1_y,
                uint8(4),
                i_sector_icc_2_x,
                i_sector_icc_2_y,
                uint8(4),
                a2_x,
                a2_y,
                uint8(4),
                pk_sector_x,
                pk_sector_y,
                DSI,
                message
        );
    }

    function new_gpk(uint256 pk_m_x, uint256 pk_m_y, uint256 pk_icc_x, uint256 pk_icc_y) public pure returns (GroupManagerPublicKey memory) {
        return GroupManagerPublicKey(
            pk_m_x, pk_m_y, pk_icc_x, pk_icc_y
        );
    }
}
