// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseVCVerifier} from "./BaseVCVerifier.sol";

/// @title AgeOver18Verifier - Verifier for Age Over 18 VC
contract AgeOver18Verifier is BaseVCVerifier {
    constructor(address _didContract, address _issuerRegistry) BaseVCVerifier(_didContract, _issuerRegistry) {}

    /// forge-lint: disable-next-line(mixed-case-function)
    function getVCType() public pure override returns (string memory) {
        return "AgeOver18";
    }

    /// forge-lint: disable-next-line(mixed-case-function)
    function getVCDescription() public pure override returns (string memory) {
        return "Verifies that the DID holder is 18 years of age or older";
    }

    /// @notice Verify VC data
    /// @dev vcData format:  empty
    /// forge-lint: disable-next-line(mixed-case-function)
    function _verifyVCData(bytes calldata vcData) internal pure override returns (bool) {
        // vcData can include birth date, which is signed by the issuer off-chain
        // Here we only need to ensure the data format is correct
        if (vcData.length == 0) {
            return true; // Allow empty data, rely on issuer's signature
        } else {
            return false; // Invalid data format
        }
    }
}
