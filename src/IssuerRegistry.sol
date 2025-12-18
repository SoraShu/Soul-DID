// SPDX-License-Identifier:  MIT
pragma solidity ^0.8.13;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title IssuerRegistry - Registry for Trusted Issuers
contract IssuerRegistry is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    struct Issuer {
        string name;
        string description;
        bool isActive;
        uint256 registeredAt;
    }

    // issuer address => Issuer info
    mapping(address => Issuer) public issuers;
    // all issuer addresses
    address[] public issuerList;

    event IssuerRegistered(address indexed issuer, string name);
    event IssuerStatusChanged(address indexed issuer, bool isActive);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    /// @notice Register a new issuer
    /// @notice Only callable by ADMIN_ROLE
    /// @param issuerAddress The address of the issuer
    /// @param name The name of the issuer
    /// @param description The description of the issuer
    function registerIssuer(address issuerAddress, string calldata name, string calldata description)
        external
        onlyRole(ADMIN_ROLE)
    {
        require(!issuers[issuerAddress].isActive, "Already registered");
        require(bytes(name).length > 0, "Empty name");

        issuers[issuerAddress] =
            Issuer({name: name, description: description, isActive: true, registeredAt: block.timestamp});

        issuerList.push(issuerAddress);
        emit IssuerRegistered(issuerAddress, name);
    }

    /// @notice Set issuer active status
    /// @notice Only callable by ADMIN_ROLE
    /// @param issuerAddress The address of the issuer
    /// @param isActive The active status to set
    function setIssuerStatus(address issuerAddress, bool isActive) external onlyRole(ADMIN_ROLE) {
        require(issuers[issuerAddress].registeredAt > 0, "Not registered");
        issuers[issuerAddress].isActive = isActive;
        emit IssuerStatusChanged(issuerAddress, isActive);
    }

    /// @notice Check if issuer is valid
    function isValidIssuer(address issuerAddress) external view returns (bool) {
        return issuers[issuerAddress].isActive;
    }

    /// @notice Get issuer info
    function getIssuerInfo(address issuerAddress)
        external
        view
        returns (string memory name, string memory description, bool isActive, uint256 registeredAt)
    {
        Issuer storage issuer = issuers[issuerAddress];
        return (issuer.name, issuer.description, issuer.isActive, issuer.registeredAt);
    }

    /// @notice Get total issuer count
    function getIssuerCount() external view returns (uint256) {
        return issuerList.length;
    }

    /// @notice Get issuer address at index
    function getIssuerAt(uint256 index) external view returns (address) {
        require(index < issuerList.length, "Index out of bounds");
        return issuerList[index];
    }
}
