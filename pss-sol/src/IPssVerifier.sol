// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8;

library ECC {
    struct Point {
        uint256 X;
        uint256 Y;
    }

    function point(uint256 _x, uint256 _y) public pure returns (Point memory) {
        return Point(_x, _y);
    }
}

interface IPssVerifier {
    function validate_signature(bytes calldata, uint256, uint256, uint256) external view returns (bool);
    function validate_signature_p1(bytes calldata message, uint256 c, uint256 s1, uint256 s2, ECC.Point memory i_sector_icc_1) external view returns (bool);
    function validate_signature_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, ECC.Point memory i_sector_icc_2) external view returns (bool);
    function validate_signature_p1_p2(bytes calldata message, uint256 c, uint256 s1, uint256 s2, ECC.Point memory i_sector_icc_1, ECC.Point memory i_sector_icc_2) external view returns (bool);
    function get_gpk() external view returns (uint256, uint256, uint256, uint256);
    function get_sector() external view returns (uint256, uint256);
}