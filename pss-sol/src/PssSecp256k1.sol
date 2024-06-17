// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "elliptic-curve-solidity/contracts/EllipticCurve.sol";
import "elliptic-curve-solidity/examples/Secp256k1.sol";

contract PssSecp256k1 {
    uint256 public constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    
    bytes13 public constant DSI = "ECC-KECCAK256";
    
    struct GroupManagerPublicKey {
        uint256 pk_m_x;
        uint256 pk_m_y;
        uint256 pk_icc_x;
        uint256 pk_icc_y;
    }

    GroupManagerPublicKey[] public valid_keys;
    uint256 public pk_sector_x;
    uint256 public pk_sector_y;

    function calc_q1(uint256 gpkIdx, uint256 c, uint256 s1, uint256 s2) private view returns (uint256, uint256) {
        GroupManagerPublicKey storage gpk = valid_keys[gpkIdx];
        (uint256 q1s1_x, uint256 q1s1_y) = EllipticCurve.ecMul(c, gpk.pk_icc_x, gpk.pk_icc_y, AA, PP);
        (uint256 q1s2_x, uint256 q1s2_y) = EllipticCurve.ecMul(s1, GX, GY, AA, PP);
        (uint256 q1s3_x, uint256 q1s3_y) = EllipticCurve.ecMul(s2, gpk.pk_m_x, gpk.pk_m_y, AA, PP);
        (uint256 q1s4_x, uint256 q1s4_y) = EllipticCurve.ecAdd(q1s1_x, q1s1_y, q1s2_x, q1s2_y, AA, PP);
        return EllipticCurve.ecAdd(q1s3_x, q1s3_y, q1s4_x, q1s4_y, AA, PP);

    }

    function validate_signature(bytes calldata message, uint256 gpkIdx, uint256 c, uint256 s1, uint256 s2) public view returns (bool) {
        (uint256 q1_x, uint256 q1_y) = calc_q1(gpkIdx, c, s1, s2);
        bytes32 c_recover = keccak256(abi.encodePacked(
                uint8(4),
                q1_x,
                q1_y,
                uint8(4),
                pk_sector_x,
                pk_sector_y,
                DSI,
                message
        ));
        return c_recover == bytes32(c);
    }

    function validate_signature_p1(bytes calldata message, uint256 gpkIdx, uint256 c, uint256 s1, uint256 s2, uint8 pseudonym1_parity, uint256 pseudonym1_x) public view returns (bool) {
        (uint256 q1_x, uint256 q1_y) = calc_q1(gpkIdx, c, s1, s2);
        bytes32 c_recover = keccak256(abi.encodePacked(
                uint8(4),
                q1_x,
                q1_y,
                uint8(4),
                pk_sector_x,
                pk_sector_y,
                DSI,
                message
        ));
        return c_recover == bytes32(c);
    }

    function validate_signature_p1_p2(bytes calldata message, uint256 gpkIdx, uint256 c, uint256 s1, uint256 s2, uint8 pseudonym1_parity, uint256 pseudonym1_x, uint8 pseudonym2_parity, uint256 pseudonym2_x) public view returns (bool) {
        (uint256 q1_x, uint256 q1_y) = calc_q1(gpkIdx, c, s1, s2);
        bytes32 c_recover = keccak256(abi.encodePacked(
                uint8(4),
                q1_x,
                q1_y,
                uint8(4),
                pk_sector_x,
                pk_sector_y,
                DSI,
                message
        ));
        return c_recover == bytes32(c);
    }

    function validate_signature_p2(bytes calldata message, uint256 gpkIdx, uint256 c, uint256 s1, uint256 s2, uint8 pseudonym2_parity, uint256 pseudonym2_x) public view returns (bool) {
        (uint256 q1_x, uint256 q1_y) = calc_q1(gpkIdx, c, s1, s2);
        bytes32 c_recover = keccak256(abi.encodePacked(
                uint8(4),
                q1_x,
                q1_y,
                uint8(4),
                pk_sector_x,
                pk_sector_y,
                DSI,
                message
        ));
        return c_recover == bytes32(c);
    }

    function setNumber(uint256 newNumber) public {
    }

    function increment() public {
    }
}
