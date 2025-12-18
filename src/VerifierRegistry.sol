// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IVCVerifier} from "./interfaces/IVCVerifier.sol";
import {SoulboundDID} from "./SoulboundDID.sol";

/// @title VerifierRegistry - Registry for VC Verifiers
/// @notice Manage all VC verifiers for easy frontend queries
contract VerifierRegistry is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    struct VerifierInfo {
        address verifierAddress;
        string vcType;
        string description;
        bool isActive;
        uint256 registeredAt;
    }

    // vcType => verifier address
    mapping(string => address) public verifiers;

    // verifier address => is registered
    mapping(address => bool) public isRegistered;

    // all VC types
    string[] public vcTypes;

    SoulboundDID public immutable DID_CONTRACT;

    event VerifierRegistered(address indexed verifier, string vcType);
    event VerifierRemoved(string vcType);

    constructor(address _didContract) {
        DID_CONTRACT = SoulboundDID(_didContract);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    /// @notice Register verifier
    function registerVerifier(address verifierAddress) external onlyRole(ADMIN_ROLE) {
        require(!isRegistered[verifierAddress], "Already registered");

        IVCVerifier verifier = IVCVerifier(verifierAddress);
        string memory vcType = verifier.getVCType();

        require(verifiers[vcType] == address(0), "VC type exists");

        verifiers[vcType] = verifierAddress;
        isRegistered[verifierAddress] = true;
        vcTypes.push(vcType);

        emit VerifierRegistered(verifierAddress, vcType);
    }

    /// @notice Remove verifier
    function removeVerifier(string calldata vcType) external onlyRole(ADMIN_ROLE) {
        address verifierAddress = verifiers[vcType];
        require(verifierAddress != address(0), "Not registered");

        verifiers[vcType] = address(0);
        isRegistered[verifierAddress] = false;

        emit VerifierRemoved(vcType);
    }

    /// @notice Get verifier address
    function getVerifier(string calldata vcType) external view returns (address) {
        return verifiers[vcType];
    }

    /// @notice Get all VC types
    /// forge-lint: disable-next-line(mixed-case-function)
    function getAllVCTypes() external view returns (string[] memory) {
        return vcTypes;
    }

    /// @notice Get VC type count
    /// forge-lint: disable-next-line(mixed-case-function)
    function getVCTypeCount() external view returns (uint256) {
        return vcTypes.length;
    }

    /// @notice Get verifier info
    function getVerifierInfo(string calldata vcType) external view returns (VerifierInfo memory) {
        address verifierAddress = verifiers[vcType];
        if (verifierAddress == address(0)) {
            return
                VerifierInfo({
                    verifierAddress: address(0), vcType: "", description: "", isActive: false, registeredAt: 0
                });
        }

        IVCVerifier verifier = IVCVerifier(verifierAddress);
        return VerifierInfo({
            verifierAddress: verifierAddress,
            vcType: verifier.getVCType(),
            description: verifier.getVCDescription(),
            isActive: true,
            registeredAt: 0
        });
    }

    /// @notice Get all verification statuses for a DID
    /// forge-lint: disable-next-line(mixed-case-function)
    function getDIDVerifications(uint256 didTokenId)
        external
        view
        returns (string[] memory types, bool[] memory hasVerification, IVCVerifier.VerificationRecord[] memory records)
    {
        uint256 count = vcTypes.length;
        types = new string[](count);
        hasVerification = new bool[](count);
        records = new IVCVerifier.VerificationRecord[](count);

        for (uint256 i = 0; i < count; i++) {
            types[i] = vcTypes[i];
            address verifierAddress = verifiers[vcTypes[i]];

            if (verifierAddress != address(0)) {
                IVCVerifier verifier = IVCVerifier(verifierAddress);
                hasVerification[i] = verifier.hasValidVerification(didTokenId);
                records[i] = verifier.getVerification(didTokenId);
            }
        }

        return (types, hasVerification, records);
    }

    /// @notice Get all verification statuses for a DID by wallet address
    function getVerificationsByAddress(address walletAddress)
        external
        view
        returns (
            uint256 didTokenId,
            string[] memory types,
            bool[] memory hasVerification,
            IVCVerifier.VerificationRecord[] memory records
        )
    {
        didTokenId = DID_CONTRACT.getDIDByAddress(walletAddress);
        if (didTokenId == 0) {
            return (0, new string[](0), new bool[](0), new IVCVerifier.VerificationRecord[](0));
        }

        (types, hasVerification, records) = this.getDIDVerifications(didTokenId);
        return (didTokenId, types, hasVerification, records);
    }
}
