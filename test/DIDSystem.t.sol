// SPDX-License-Identifier:  MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SoulboundDID} from "../src/SoulboundDID.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";
import {VerifierRegistry} from "../src/VerifierRegistry.sol";
import {IVCVerifier} from "../src/interfaces/IVCVerifier.sol";
import {AgeOver18Verifier} from "../src/verifiers/AgeOver18Verifier.sol";
import {IERC5192} from "../src/interfaces/IERC5192.sol";

contract DIDSystemTest is Test {
    SoulboundDID public didContract;
    IssuerRegistry public issuerRegistry;
    VerifierRegistry public verifierRegistry;
    AgeOver18Verifier public ageVerifier;

    address public admin;

    uint256 public userPrivateKey = 0xA11CE;
    address public user;

    uint256 public user2PrivateKey = 0xB0B2;
    address public user2;

    uint256 public issuerPrivateKey = 0xB0B;
    address public issuer;

    event DIDCreated(uint256 indexed tokenId, address indexed owner, bytes publicKey, uint256 timestamp);
    event Locked(uint256 tokenId);
    event VCVerified(uint256 indexed didTokenId, address indexed issuer, uint256 verifiedAt, uint256 expiresAt);
    event VerificationRevoked(uint256 indexed didTokenId, address indexed revokedBy);

    function setUp() public {
        admin = address(this);
        user = vm.addr(userPrivateKey);
        user2 = vm.addr(user2PrivateKey);
        issuer = vm.addr(issuerPrivateKey);

        // Deploy contracts
        didContract = new SoulboundDID();
        issuerRegistry = new IssuerRegistry();
        verifierRegistry = new VerifierRegistry(address(didContract));

        ageVerifier = new AgeOver18Verifier(address(didContract), address(issuerRegistry));

        // Register verifier
        verifierRegistry.registerVerifier(address(ageVerifier));

        // Register issuer
        issuerRegistry.registerIssuer(issuer, "Government Agency", "Official identity issuer");

        // Give test users some ETH
        vm.deal(user, 10 ether);
        vm.deal(user2, 10 ether);
    }

    // ============ SoulboundDID Tests ============

    function test_MintDID() public {
        vm.startPrank(user);

        bytes memory publicKey = abi.encodePacked(user);

        uint256 tokenId = didContract.mintDID(publicKey, "ipfs://did-document-uri");

        assertEq(tokenId, 1);
        assertEq(didContract.ownerOf(tokenId), user);
        assertEq(didContract.getDIDByAddress(user), tokenId);
        assertEq(didContract.balanceOf(user), 1);

        (bytes memory storedPubKey, uint256 createdAt, string memory didDoc, address owner) =
            didContract.getDIDInfo(tokenId);

        assertEq(storedPubKey, publicKey);
        assertGt(createdAt, 0);
        assertEq(didDoc, "ipfs://did-document-uri");
        assertEq(owner, user);

        vm.stopPrank();
    }

    function test_MintDID_EmitsEvents() public {
        vm.startPrank(user);

        bytes memory publicKey = abi.encodePacked(user);

        vm.expectEmit(true, true, false, false);
        emit DIDCreated(1, user, publicKey, block.timestamp);

        vm.expectEmit(false, false, false, true);
        emit Locked(1);

        didContract.mintDID(publicKey, "");

        vm.stopPrank();
    }

    function test_MintDID_MultipleUsers() public {
        vm.prank(user);
        uint256 tokenId1 = didContract.mintDID(abi.encodePacked(user), "");

        vm.prank(user2);
        uint256 tokenId2 = didContract.mintDID(abi.encodePacked(user2), "");

        assertEq(tokenId1, 1);
        assertEq(tokenId2, 2);
        assertEq(didContract.getDIDByAddress(user), 1);
        assertEq(didContract.getDIDByAddress(user2), 2);
    }

    function test_RevertWhen_MintDID_EmptyPublicKey() public {
        vm.prank(user);
        vm.expectRevert("Public key cannot be empty");
        didContract.mintDID("", "");
    }

    function test_RevertWhen_MintDID_AlreadyHasDID() public {
        vm.startPrank(user);
        didContract.mintDID(abi.encodePacked(user), "");

        vm.expectRevert("Address already has a DID");
        didContract.mintDID(abi.encodePacked(user, "new"), "");
        vm.stopPrank();
    }

    function test_RevertWhen_MintDID_PublicKeyAlreadyRegistered() public {
        bytes memory sharedPublicKey = abi.encodePacked("shared-public-key");

        vm.prank(user);
        didContract.mintDID(sharedPublicKey, "");

        vm.prank(user2);
        vm.expectRevert("Public key already registered");
        didContract.mintDID(sharedPublicKey, "");
    }

    function test_RevertWhen_TransferSoulboundNFT() public {
        vm.startPrank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        vm.expectRevert("Soulbound:  Transfer not allowed");
        didContract.transferFrom(user, user2, tokenId);

        vm.expectRevert("Soulbound:  Transfer not allowed");
        didContract.safeTransferFrom(user, user2, tokenId);

        vm.stopPrank();
    }

    function test_VerifyChallenge() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        bytes32 challenge = keccak256("prove your identity - random nonce 12345");

        bytes32 ethSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", challenge));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, ethSignedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool isValid = didContract.verifyChallenge(tokenId, challenge, signature);
        assertTrue(isValid);
    }

    function test_VerifyChallenge_InvalidSignature() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        bytes32 challenge = keccak256("prove your identity");

        // Sign with wrong private key
        bytes32 ethSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", challenge));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user2PrivateKey, ethSignedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool isValid = didContract.verifyChallenge(tokenId, challenge, signature);
        assertFalse(isValid);
    }

    function test_VerifyChallenge_RevertWhen_DIDNotExist() public {
        bytes32 challenge = keccak256("test");
        bytes memory signature = "";

        vm.expectRevert("DID not exist");
        didContract.verifyChallenge(999, challenge, signature);
    }

    function test_GetDIDByPublicKey() public {
        bytes memory publicKey = abi.encodePacked("unique-public-key-123");

        vm.prank(user);
        uint256 tokenId = didContract.mintDID(publicKey, "");

        uint256 foundTokenId = didContract.getDIDByPublicKey(publicKey);
        assertEq(foundTokenId, tokenId);
    }

    function test_GetDIDInfo_RevertWhen_NotExist() public {
        vm.expectRevert("DID not exist");
        didContract.getDIDInfo(999);
    }

    function test_Locked() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        assertTrue(didContract.locked(tokenId));
    }

    function test_Locked_RevertWhen_TokenNotExist() public {
        vm.expectRevert("Token not exist");
        didContract.locked(999);
    }

    function test_SupportsInterface() public view {
        // ERC721
        assertTrue(didContract.supportsInterface(0x80ac58cd));
        // ERC721Enumerable
        assertTrue(didContract.supportsInterface(0x780e9d63));
        // ERC5192
        assertTrue(didContract.supportsInterface(type(IERC5192).interfaceId));
    }

    // ============ IssuerRegistry Tests ============

    function test_RegisterIssuer() public {
        address newIssuer = address(0x123);

        issuerRegistry.registerIssuer(newIssuer, "University", "Educational institution");

        assertTrue(issuerRegistry.isValidIssuer(newIssuer));

        (string memory name, string memory desc, bool isActive, uint256 registeredAt) =
            issuerRegistry.getIssuerInfo(newIssuer);

        assertEq(name, "University");
        assertEq(desc, "Educational institution");
        assertTrue(isActive);
        assertGt(registeredAt, 0);
    }

    function test_SetIssuerStatus() public {
        assertTrue(issuerRegistry.isValidIssuer(issuer));

        issuerRegistry.setIssuerStatus(issuer, false);
        assertFalse(issuerRegistry.isValidIssuer(issuer));

        issuerRegistry.setIssuerStatus(issuer, true);
        assertTrue(issuerRegistry.isValidIssuer(issuer));
    }

    function test_GetIssuerCount() public {
        assertEq(issuerRegistry.getIssuerCount(), 1); // issuer registered in setUp

        issuerRegistry.registerIssuer(address(0x111), "Issuer 2", "");
        assertEq(issuerRegistry.getIssuerCount(), 2);
    }

    // ============ AgeOver18Verifier Tests ============

    function test_VerifyAndRecord_AgeOver18() public {
        // 1. User mints DID
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        // 2. Issuer signs VC off-chain
        uint256 expiresAt = block.timestamp + 365 days;
        bytes memory vcData = "";

        bytes memory signature =
            _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, expiresAt, vcData, issuerPrivateKey);

        // 3. User verifies and records on-chain
        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit VCVerified(tokenId, issuer, block.timestamp, expiresAt);

        bool success = ageVerifier.verifyAndRecord(tokenId, issuer, expiresAt, signature, vcData);

        assertTrue(success);
        assertTrue(ageVerifier.hasValidVerification(tokenId));

        // 4. Check verification record
        IVCVerifier.VerificationRecord memory record = ageVerifier.getVerification(tokenId);
        assertEq(record.didTokenId, tokenId);
        assertEq(record.issuer, issuer);
        assertEq(record.expiresAt, expiresAt);
        assertTrue(record.isValid);
    }

    function test_VerifyAndRecord_NoExpiry() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        uint256 expiresAt = 0; // Never expires
        bytes memory vcData = "";

        bytes memory signature =
            _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, expiresAt, vcData, issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, expiresAt, signature, vcData);

        assertTrue(ageVerifier.hasValidVerification(tokenId));

        // Fast forward 100 years, still valid
        vm.warp(block.timestamp + 100 * 365 days);
        assertTrue(ageVerifier.hasValidVerification(tokenId));
    }

    function test_RevertWhen_VerifyAndRecord_DIDNotExist() public {
        bytes memory signature = _signVC(address(ageVerifier), "AgeOver18", 999, issuer, 0, "", issuerPrivateKey);

        vm.prank(user);
        vm.expectRevert("DID not exist");
        ageVerifier.verifyAndRecord(999, issuer, 0, signature, "");
    }

    function test_RevertWhen_VerifyAndRecord_NotDIDOwner() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        bytes memory signature = _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, 0, "", issuerPrivateKey);

        // user2 tries to verify for user's DID
        vm.prank(user2);
        vm.expectRevert("Not DID owner");
        ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");
    }

    function test_RevertWhen_VerifyAndRecord_InvalidIssuer() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        address fakeIssuer = address(0x999);
        uint256 fakeIssuerPrivateKey = 0xFA;

        bytes memory signature =
            _signVC(address(ageVerifier), "AgeOver18", tokenId, fakeIssuer, 0, "", fakeIssuerPrivateKey);

        vm.prank(user);
        vm.expectRevert("Invalid issuer");
        ageVerifier.verifyAndRecord(tokenId, fakeIssuer, 0, signature, "");
    }

    function test_RevertWhen_VerifyAndRecord_InvalidSignature() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        // Sign with wrong private key
        bytes memory signature = _signVC(
            address(ageVerifier),
            "AgeOver18",
            tokenId,
            issuer,
            0,
            "",
            userPrivateKey // Wrong private key
        );

        vm.prank(user);
        vm.expectRevert("Invalid signature");
        ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");
    }

    function test_HasValidVerification_ExpiresAfterTime() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        uint256 expiresAt = block.timestamp + 30 days;

        bytes memory signature =
            _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, expiresAt, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, expiresAt, signature, "");

        assertTrue(ageVerifier.hasValidVerification(tokenId));

        // Fast forward to after expiry
        vm.warp(expiresAt + 1);
        assertFalse(ageVerifier.hasValidVerification(tokenId));
    }

    function test_HasValidVerification_IssuerDeactivated() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        bytes memory signature = _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, 0, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");

        assertTrue(ageVerifier.hasValidVerification(tokenId));

        // Deactivate issuer
        issuerRegistry.setIssuerStatus(issuer, false);
        assertFalse(ageVerifier.hasValidVerification(tokenId));

        // Reactivate issuer
        issuerRegistry.setIssuerStatus(issuer, true);
        assertTrue(ageVerifier.hasValidVerification(tokenId));
    }

    function test_RevokeVerification_ByIssuer() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        bytes memory signature = _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, 0, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");

        assertTrue(ageVerifier.hasValidVerification(tokenId));

        // Issuer revokes
        vm.prank(issuer);
        vm.expectEmit(true, true, false, false);
        emit VerificationRevoked(tokenId, issuer);
        ageVerifier.revokeVerification(tokenId);

        assertFalse(ageVerifier.hasValidVerification(tokenId));
    }

    function test_RevokeVerification_ByOwner() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        bytes memory signature = _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, 0, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");

        // Contract owner revokes
        ageVerifier.revokeVerification(tokenId);

        assertFalse(ageVerifier.hasValidVerification(tokenId));
    }

    function test_RevertWhen_RevokeVerification_NoVerification() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        vm.expectRevert("No verification");
        ageVerifier.revokeVerification(tokenId);
    }

    function test_RevertWhen_RevokeVerification_NotAuthorized() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        bytes memory signature = _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, 0, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");

        // user2 tries to revoke (neither issuer nor contract owner)
        vm.prank(user2);
        vm.expectRevert("Not authorized");
        ageVerifier.revokeVerification(tokenId);
    }

    function test_GetVerifiedDIDs() public {
        // Create multiple users and verify
        address[] memory users = new address[](3);
        uint256[] memory privateKeys = new uint256[](3);

        privateKeys[0] = 0x1111;
        privateKeys[1] = 0x2222;
        privateKeys[2] = 0x3333;

        for (uint256 i = 0; i < 3; i++) {
            users[i] = vm.addr(privateKeys[i]);
            vm.deal(users[i], 1 ether);

            vm.prank(users[i]);
            uint256 tokenId = didContract.mintDID(abi.encodePacked(users[i]), "");

            bytes memory signature =
                _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, 0, "", issuerPrivateKey);

            vm.prank(users[i]);
            ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");
        }

        assertEq(ageVerifier.getVerifiedDIDCount(), 3);

        uint256[] memory verifiedDIDs = ageVerifier.getVerifiedDIDs(0, 10);
        assertEq(verifiedDIDs.length, 3);
        assertEq(verifiedDIDs[0], 1);
        assertEq(verifiedDIDs[1], 2);
        assertEq(verifiedDIDs[2], 3);
    }

    function test_GetVerifiedDIDs_Pagination() public {
        // Create 5 verifications
        for (uint256 i = 0; i < 5; i++) {
            uint256 pk = 0x1000 + i;
            address u = vm.addr(pk);
            vm.deal(u, 1 ether);

            vm.prank(u);
            uint256 tokenId = didContract.mintDID(abi.encodePacked(u), "");

            bytes memory signature =
                _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, 0, "", issuerPrivateKey);

            vm.prank(u);
            ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");
        }

        // Paginated retrieval
        uint256[] memory page1 = ageVerifier.getVerifiedDIDs(0, 2);
        assertEq(page1.length, 2);
        assertEq(page1[0], 1);
        assertEq(page1[1], 2);

        uint256[] memory page2 = ageVerifier.getVerifiedDIDs(2, 2);
        assertEq(page2.length, 2);
        assertEq(page2[0], 3);
        assertEq(page2[1], 4);

        uint256[] memory page3 = ageVerifier.getVerifiedDIDs(4, 2);
        assertEq(page3.length, 1);
        assertEq(page3[0], 5);

        // Out of range
        uint256[] memory emptyPage = ageVerifier.getVerifiedDIDs(10, 2);
        assertEq(emptyPage.length, 0);
    }

    function test_GetVCType() public view {
        assertEq(ageVerifier.getVCType(), "AgeOver18");
    }

    function test_GetVCDescription() public view {
        assertEq(ageVerifier.getVCDescription(), "Verifies that the DID holder is 18 years of age or older");
    }

    // ============ VerifierRegistry Tests ============

    function test_GetAllVCTypes() public view {
        string[] memory vcTypes = verifierRegistry.getAllVCTypes();
        assertEq(vcTypes.length, 1);
        assertEq(vcTypes[0], "AgeOver18");
    }

    function test_GetVerifier() public view {
        address verifierAddress = verifierRegistry.getVerifier("AgeOver18");
        assertEq(verifierAddress, address(ageVerifier));
    }

    function test_GetDIDVerifications() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        // Before verification
        (string[] memory types, bool[] memory hasVerification, IVCVerifier.VerificationRecord[] memory records) =
            verifierRegistry.getDIDVerifications(tokenId);

        assertEq(types.length, 1);
        assertEq(types[0], "AgeOver18");
        assertFalse(hasVerification[0]);
        assertEq(records[0].verifiedAt, 0);

        // After verification
        bytes memory signature = _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, 0, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");

        (types, hasVerification, records) = verifierRegistry.getDIDVerifications(tokenId);

        assertTrue(hasVerification[0]);
        assertEq(records[0].didTokenId, tokenId);
        assertEq(records[0].issuer, issuer);
        assertTrue(records[0].isValid);
    }

    function test_GetVerificationsByAddress() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        bytes memory signature = _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, 0, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, 0, signature, "");

        (uint256 returnedTokenId, string[] memory types, bool[] memory hasVerification,) =
            verifierRegistry.getVerificationsByAddress(user);

        assertEq(returnedTokenId, tokenId);
        assertEq(types[0], "AgeOver18");
        assertTrue(hasVerification[0]);
    }

    function test_GetVerificationsByAddress_NoDID() public view {
        (uint256 returnedTokenId, string[] memory types, bool[] memory hasVerification,) =
            verifierRegistry.getVerificationsByAddress(user);

        assertEq(returnedTokenId, 0);
        assertEq(types.length, 0);
        assertEq(hasVerification.length, 0);
    }

    function test_RegisterAndRemoveVerifier() public {
        // Create new verifier
        AgeOver18Verifier newVerifier = new AgeOver18Verifier(address(didContract), address(issuerRegistry));

        // Remove old one
        verifierRegistry.removeVerifier("AgeOver18");
        assertEq(verifierRegistry.getVerifier("AgeOver18"), address(0));

        // Register new one
        verifierRegistry.registerVerifier(address(newVerifier));
        assertEq(verifierRegistry.getVerifier("AgeOver18"), address(newVerifier));
    }

    function test_GetVCTypeCount() public view {
        assertEq(verifierRegistry.getVCTypeCount(), 1);
    }

    // ============ Integration Tests ============

    function test_FullFlow() public {
        // 1. User mints DID
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "ipfs://my-did-doc");
        assertEq(tokenId, 1);

        // 2. Verify DID ownership (challenge-response)
        bytes32 challenge = keccak256("verify ownership");
        bytes32 ethSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", challenge));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, ethSignedMessage);
        bytes memory ownershipSignature = abi.encodePacked(r, s, v);

        assertTrue(didContract.verifyChallenge(tokenId, challenge, ownershipSignature));

        // 3. Get age verification VC signature (simulating issuer signing off-chain)
        uint256 expiresAt = block.timestamp + 365 days;
        bytes memory vcData = "";
        bytes memory vcSignature =
            _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, expiresAt, vcData, issuerPrivateKey);

        // 4. User submits VC verification
        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, expiresAt, vcSignature, vcData);

        // 5. Third party queries verification status
        assertTrue(ageVerifier.hasValidVerification(tokenId));

        (
            uint256 queriedTokenId,
            string[] memory vcTypes,
            bool[] memory hasVerification,
            IVCVerifier.VerificationRecord[] memory records
        ) = verifierRegistry.getVerificationsByAddress(user);

        assertEq(queriedTokenId, tokenId);
        assertEq(vcTypes[0], "AgeOver18");
        assertTrue(hasVerification[0]);
        assertEq(records[0].issuer, issuer);
    }

    function test_UpdateVerification() public {
        vm.prank(user);
        uint256 tokenId = didContract.mintDID(abi.encodePacked(user), "");

        // First verification
        uint256 expiresAt1 = block.timestamp + 30 days;
        bytes memory sig1 =
            _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, expiresAt1, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, expiresAt1, sig1, "");

        IVCVerifier.VerificationRecord memory record1 = ageVerifier.getVerification(tokenId);
        assertEq(record1.expiresAt, expiresAt1);

        // Second verification (update)
        uint256 expiresAt2 = block.timestamp + 365 days;
        bytes memory sig2 =
            _signVC(address(ageVerifier), "AgeOver18", tokenId, issuer, expiresAt2, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId, issuer, expiresAt2, sig2, "");

        IVCVerifier.VerificationRecord memory record2 = ageVerifier.getVerification(tokenId);
        assertEq(record2.expiresAt, expiresAt2);
    }

    function test_MultipleUsersWithDifferentIssuers() public {
        // Register another issuer
        address issuer2 = address(0x456);
        uint256 issuer2PrivateKey = 0xC0C;
        issuer2 = vm.addr(issuer2PrivateKey);
        issuerRegistry.registerIssuer(issuer2, "Another Agency", "Secondary issuer");

        // User1 verified by issuer1
        vm.prank(user);
        uint256 tokenId1 = didContract.mintDID(abi.encodePacked(user), "");

        bytes memory sig1 = _signVC(address(ageVerifier), "AgeOver18", tokenId1, issuer, 0, "", issuerPrivateKey);

        vm.prank(user);
        ageVerifier.verifyAndRecord(tokenId1, issuer, 0, sig1, "");

        // User2 verified by issuer2
        vm.prank(user2);
        uint256 tokenId2 = didContract.mintDID(abi.encodePacked(user2), "");

        bytes memory sig2 = _signVC(address(ageVerifier), "AgeOver18", tokenId2, issuer2, 0, "", issuer2PrivateKey);

        vm.prank(user2);
        ageVerifier.verifyAndRecord(tokenId2, issuer2, 0, sig2, "");

        // Both should be valid
        assertTrue(ageVerifier.hasValidVerification(tokenId1));
        assertTrue(ageVerifier.hasValidVerification(tokenId2));

        // Check different issuers
        IVCVerifier.VerificationRecord memory record1 = ageVerifier.getVerification(tokenId1);
        IVCVerifier.VerificationRecord memory record2 = ageVerifier.getVerification(tokenId2);

        assertEq(record1.issuer, issuer);
        assertEq(record2.issuer, issuer2);
    }

    // ============ Helper Functions ============

    function _signVC(
        address verifierAddress,
        string memory vcType,
        uint256 tokenId,
        address issuerAddr,
        uint256 expiresAt,
        bytes memory vcData,
        uint256 privateKey
    ) internal pure returns (bytes memory) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(verifierAddress, vcType, tokenId, issuerAddr, expiresAt, vcData)
        );

        bytes32 ethSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessage);
        return abi.encodePacked(r, s, v);
    }
}
