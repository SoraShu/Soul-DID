// SPDX-License-Identifier:  MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {SoulboundDID} from "../src/SoulboundDID.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";
import {VerifierRegistry} from "../src/VerifierRegistry.sol";
import {AgeOver18Verifier} from "../src/verifiers/AgeOver18Verifier.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("===========================================");
        console.log("Deployer:", deployer);
        console.log("Balance:", deployer.balance / 1e18, "ETH");
        console.log("===========================================\n");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy SoulboundDID
        SoulboundDID didContract = new SoulboundDID();
        console.log("SoulboundDID deployed at:", address(didContract));

        // 2. Deploy IssuerRegistry
        IssuerRegistry issuerRegistry = new IssuerRegistry();
        console.log("IssuerRegistry deployed at:", address(issuerRegistry));

        // 3. Deploy VerifierRegistry
        VerifierRegistry verifierRegistry = new VerifierRegistry(address(didContract));
        console.log("VerifierRegistry deployed at:", address(verifierRegistry));

        // 4. Deploy AgeOver18Verifier
        AgeOver18Verifier ageOver18Verifier = new AgeOver18Verifier(address(didContract), address(issuerRegistry));
        console.log("AgeOver18Verifier deployed at:", address(ageOver18Verifier));

        // 5. Register verifier
        verifierRegistry.registerVerifier(address(ageOver18Verifier));
        console.log("AgeOver18Verifier registered to VerifierRegistry");

        // 6. Register deployer as test issuer
        issuerRegistry.registerIssuer(deployer, "Test Issuer", "Default issuer for testing on Anvil");
        console.log("Test issuer registered:", deployer);

        vm.stopBroadcast();

        // Output deployment summary
        console.log("\n===========================================");
        console.log("         DEPLOYMENT SUMMARY");
        console.log("===========================================");
        console.log("SoulboundDID:       ", address(didContract));
        console.log("IssuerRegistry:     ", address(issuerRegistry));
        console.log("VerifierRegistry:   ", address(verifierRegistry));
        console.log("AgeOver18Verifier:  ", address(ageOver18Verifier));
        console.log("===========================================\n");
    }
}
