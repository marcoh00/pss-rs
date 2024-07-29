// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8;

interface IPssVerifier {
    function validate_signature(bytes calldata, uint256, uint256, uint256) external view returns (bool);
    function validate_signature_p1(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_1_parity, uint256 i_sector_icc_1_x) external view returns (bool);
    function validate_signature_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_2_parity, uint256 i_sector_icc_2_x) external view returns (bool);
    function validate_signature_p1_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, uint8 i_sector_icc_1_parity, uint256 i_sector_icc_1_x, uint8 i_sector_icc_2_parity, uint256 i_sector_icc_2_x) external view returns (bool);
}