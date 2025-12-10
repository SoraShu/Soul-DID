// SPDX-License-Identifier:  MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {SoulboundDID} from "../src/SoulboundDID.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";
import {VerifierRegistry} from "../src/VerifierRegistry.sol";
import {IVCVerifier} from "../src/interfaces/IVCVerifier.sol";
import {AgeOver18Verifier} from "../src/verifiers/AgeOver18Verifier.sol";

contract InteractScript is Script {
    // Set these addresses in .env before running
    address DID_CONTRACT = vm.envAddress("DID_CONTRACT");
    address ISSUER_REGISTRY = vm.envAddress("ISSUER_REGISTRY");
    address VERIFIER_REGISTRY = vm.envAddress("VERIFIER_REGISTRY");
    address AGE_VERIFIER = vm.envAddress("AGE_VERIFIER");

    function run() external {
        // deployer's account
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        // use account1 as user
        uint256 userPrivateKey = vm.envUint("USER_PRIVATE_KEY");
        address user = vm.addr(userPrivateKey);

        // use account2 as issuer (registered during deployment)
        uint256 issuerPrivateKey = vm.envUint("ISSUER_PRIVATE_KEY");
        address issuer = vm.addr(issuerPrivateKey);

        SoulboundDID didContract = SoulboundDID(DID_CONTRACT);
        AgeOver18Verifier ageVerifier = AgeOver18Verifier(AGE_VERIFIER);
        VerifierRegistry verifierRegistry = VerifierRegistry(VERIFIER_REGISTRY);

        console.log("===========================================");
        console.log("\nUser address:   ", user);
        console.log("\nIssuer address: ", issuer);
        console.log("===========================================\n");
        
        // step 0: Add issuer to IssuerRegistry
        // if already registered, skip
        vm.startBroadcast(deployerPrivateKey);
        IssuerRegistry issuerRegistry = IssuerRegistry(ISSUER_REGISTRY);
        if (!(issuerRegistry.isValidIssuer(issuer))) {
            issuerRegistry.registerIssuer(issuer, "Demo Issuer", "Issuer for interaction testing");
            console.log("Issuer registered:", issuer);
        } else {
            console.log("Issuer already registered:", issuer);
        }
        vm.stopBroadcast();

        // Step 1: User mints DID
        console.log("\nStep 1: Minting DID for user...");
        vm.startBroadcast(userPrivateKey);
        // if already minted, skip
        uint256 tokenId;
        if (didContract.addressToTokenId(user) != 0) {
            tokenId = didContract.addressToTokenId(user);
            console.log("User already has a DID with tokenId:", didContract.addressToTokenId(user));
        } else {
            bytes memory publicKey = abi.encodePacked(user);
            tokenId = didContract.mintDID(publicKey, "ipfs://test-did-document");
            console.log("DID minted with tokenId:", tokenId);
        }
        vm.stopBroadcast();

        // Step 2: Verify DID info
        console.log("\nStep 2: Verifying DID info...");
        (, uint256 createdAt, string memory didDoc, address owner) =
            didContract.getDIDInfo(tokenId);
        console.log("DID Owner:", owner);
        console.log("Created At:", createdAt);
        console.log("DID Document:", didDoc);

        // Step 3: Challenge-Response verification
        console.log("\nStep 3: Challenge-Response verification...");
        bytes32 challenge = keccak256("prove your identity - nonce 12345");
        bytes32 ethSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", challenge));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(userPrivateKey, ethSignedMessage);
        bytes memory challengeSignature = abi.encodePacked(r1, s1, v1);

        bool challengeValid = didContract.verifyChallenge(tokenId, challenge, challengeSignature);
        console.log("Challenge verification result:", challengeValid);

        // Step 4: Issuer signs VC (off-chain simulation)
        console.log("\nStep 4: Issuer signing VC...");
        uint256 expiresAt = block.timestamp + 365 days;
        bytes memory vcData = "";

        bytes32 vcMessageHash =
            keccak256(abi.encodePacked(address(ageVerifier), "AgeOver18", tokenId, issuer, expiresAt, vcData));
        bytes32 vcEthSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", vcMessageHash));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(issuerPrivateKey, vcEthSignedMessage);
        bytes memory vcSignature = abi.encodePacked(r2, s2, v2);
        console.log("VC signed by issuer");

        // Step 5: User submits VC for verification
        console.log("\nStep 5: User submitting VC for on-chain verification...");
        vm.startBroadcast(userPrivateKey);

        bool verifyResult = ageVerifier.verifyAndRecord(tokenId, issuer, expiresAt, vcSignature, vcData);

        vm.stopBroadcast();
        console.log("VC verification result:", verifyResult);

        // Step 6: Query verification status
        console.log("\nStep 6: Querying verification status...");
        bool hasValidVerification = ageVerifier.hasValidVerification(tokenId);
        console.log("Has valid AgeOver18 verification:", hasValidVerification);

        IVCVerifier.VerificationRecord memory record = ageVerifier.getVerification(tokenId);
        console.log("Verification issuer:", record.issuer);
        console.log("Verified at:", record.verifiedAt);
        console.log("Expires at:", record.expiresAt);

        // Step 7: Query all verifications via VerifierRegistry
        console.log("\nStep 7: Querying all verifications for user...");
        (uint256 queriedTokenId, string[] memory vcTypes, bool[] memory hasVerifications,) =
            verifierRegistry.getVerificationsByAddress(user);

        console.log("User DID tokenId:", queriedTokenId);
        for (uint256 i = 0; i < vcTypes.length; i++) {
            console.log("VC Type:", vcTypes[i], "- Verified:", hasVerifications[i]);
        }

        console.log("\n===========================================");
        console.log("\n         INTERACTION COMPLETE");
        console.log("\n===========================================");
    }
}
