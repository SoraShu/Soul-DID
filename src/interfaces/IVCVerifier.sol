// SPDX-License-Identifier:  MIT
pragma solidity ^0.8.20;

/// @title IVCVerifier - VC Verifier Interface
interface IVCVerifier {
    /// @notice Verification record structure
    struct VerificationRecord {
        uint256 didTokenId; // DID tokenId
        address issuer; // Issuer
        uint256 verifiedAt; // Verification time
        uint256 expiresAt; // Expiration time (0=never expires)
        bool isValid; // Is valid
    }

    /// @notice VC verified event
    event VCVerified(uint256 indexed didTokenId, address indexed issuer, uint256 verifiedAt, uint256 expiresAt);

    /// @notice Verification record revoked event
    event VerificationRevoked(uint256 indexed didTokenId, address indexed revokedBy);

    /// @notice Verify VC and record the result
    /// @param didTokenId DID tokenId
    /// @param issuer Issuer address
    /// @param expiresAt Expiration timestamp
    /// @param signature Issuer signature
    /// @param vcData VC specific data (varies by VC type)
    function verifyAndRecord(
        uint256 didTokenId,
        address issuer,
        uint256 expiresAt,
        bytes calldata signature,
        bytes calldata vcData
    ) external returns (bool);

    /// @notice Check if DID has a valid verification
    function hasValidVerification(uint256 didTokenId) external view returns (bool);

    /// @notice Get verification record
    function getVerification(uint256 didTokenId) external view returns (VerificationRecord memory);

    /// @notice Get VC type name
    /// forge-lint: disable-next-line(mixed-case-function)
    function getVCType() external pure returns (string memory);

    /// @notice Get VC type description
    /// forge-lint: disable-next-line(mixed-case-function)
    function getVCDescription() external pure returns (string memory);
}
