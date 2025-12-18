// SPDX-License-Identifier:  MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IVCVerifier} from "../interfaces/IVCVerifier.sol";
import {IssuerRegistry} from "../IssuerRegistry.sol";
import {SoulboundDID} from "../SoulboundDID.sol";

/// @title BaseVCVerifier - VC Verifier Base Contract
abstract contract BaseVCVerifier is IVCVerifier, Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    SoulboundDID public immutable DID_CONTRACT;
    IssuerRegistry public immutable ISSUER_REGISTRY;

    // DID tokenId => verification record
    mapping(uint256 => VerificationRecord) internal _verifications;

    // all verified DID tokenIds
    /// forge-lint: disable-next-line(mixed-case-variable)
    uint256[] internal _verifiedDIDs;

    // whether DID is already in the list
    mapping(uint256 => bool) internal _isInVerifiedList;

    constructor(address _didContract, address _issuerRegistry) Ownable(msg.sender) {
        DID_CONTRACT = SoulboundDID(_didContract);
        ISSUER_REGISTRY = IssuerRegistry(_issuerRegistry);
    }

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
    ) external virtual returns (bool) {
        // 1. Verify DID exists and caller is DID owner
        (,,, address didOwner) = DID_CONTRACT.getDIDInfo(didTokenId);
        require(didOwner != address(0), "DID not exist");
        require(didOwner == msg.sender, "Not DID owner");

        // 2. Verify issuer is valid
        require(ISSUER_REGISTRY.isValidIssuer(issuer), "Invalid issuer");

        // 3. Verify expiration time
        if (expiresAt != 0) {
            require(expiresAt > block.timestamp, "VC expired");
        }

        // 4. Construct and verify signature
        bytes32 messageHash = _constructMessageHash(didTokenId, issuer, expiresAt, vcData);
        bytes32 ethSignedMessage = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessage.recover(signature);
        require(signer == issuer, "Invalid signature");

        // 5. Verify VC specific data (implemented by subclass)
        require(_verifyVCData(vcData), "Invalid VC data");

        // 6. Record verification result
        _verifications[didTokenId] = VerificationRecord({
            didTokenId: didTokenId, issuer: issuer, verifiedAt: block.timestamp, expiresAt: expiresAt, isValid: true
        });

        // Add to verified list
        if (!_isInVerifiedList[didTokenId]) {
            _verifiedDIDs.push(didTokenId);
            _isInVerifiedList[didTokenId] = true;
        }

        emit VCVerified(didTokenId, issuer, block.timestamp, expiresAt);
        return true;
    }

    /// @notice Revoke verification record (only issuer or contract owner can operate)
    function revokeVerification(uint256 didTokenId) external {
        VerificationRecord storage record = _verifications[didTokenId];
        require(record.verifiedAt > 0, "No verification");
        require(msg.sender == record.issuer || msg.sender == owner(), "Not authorized");

        record.isValid = false;
        emit VerificationRevoked(didTokenId, msg.sender);
    }

    /// @notice Check if DID has a valid verification
    function hasValidVerification(uint256 didTokenId) external view returns (bool) {
        VerificationRecord storage record = _verifications[didTokenId];

        if (!record.isValid) return false;
        if (record.verifiedAt == 0) return false;
        if (record.expiresAt != 0 && block.timestamp > record.expiresAt) return false;
        if (!ISSUER_REGISTRY.isValidIssuer(record.issuer)) return false;

        return true;
    }

    /// @notice get verification record
    function getVerification(uint256 didTokenId) external view returns (VerificationRecord memory) {
        return _verifications[didTokenId];
    }

    /// @notice Get verified DID count
    /// forge-lint: disable-next-line(mixed-case-function)
    function getVerifiedDIDCount() external view returns (uint256) {
        return _verifiedDIDs.length;
    }

    /// @notice Get verified DID list (paginated)
    /// forge-lint: disable-next-line(mixed-case-function)
    function getVerifiedDIDs(uint256 offset, uint256 limit) external view returns (uint256[] memory) {
        uint256 total = _verifiedDIDs.length;
        if (offset >= total) {
            return new uint256[](0);
        }

        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }

        uint256[] memory result = new uint256[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = _verifiedDIDs[i];
        }

        return result;
    }

    /// @notice Construct signature message hash (can be overridden by subclass)
    function _constructMessageHash(uint256 didTokenId, address issuer, uint256 expiresAt, bytes calldata vcData)
        internal
        view
        virtual
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                address(this), // Verifier contract address
                getVCType(), // VC type
                didTokenId,
                issuer,
                expiresAt,
                vcData
            )
        );
    }

    /// @notice Verify VC specific data (implemented by subclass)
    /// forge-lint: disable-next-line(mixed-case-function)
    function _verifyVCData(bytes calldata vcData) internal view virtual returns (bool);

    /// @notice Get VC type (implemented by subclass)
    /// forge-lint: disable-next-line(mixed-case-function)
    function getVCType() public pure virtual returns (string memory);

    /// @notice Get VC description (implemented by subclass)
    /// forge-lint: disable-next-line(mixed-case-function)
    function getVCDescription() public pure virtual returns (string memory);
}
