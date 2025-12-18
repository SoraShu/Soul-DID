// SPDX-License-Identifier:  MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721Enumerable} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC5192} from "./interfaces/IERC5192.sol";

/// @title SoulboundDID - Decentralized Identity as Soulbound NFT
/// @notice Users mint their public keys as non-transferable NFTs to serve as DIDs
contract SoulboundDID is ERC721Enumerable, IERC5192, Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // DID info structure
    /// forge-lint: disable-next-line(pascal-case-struct)
    struct DIDInfo {
        bytes publicKey; // The user's DID public key
        uint256 createdAt; // Creation timestamp
        string didDocument; // DID document URI (optional)
    }

    // tokenId => DIDInfo
    mapping(uint256 => DIDInfo) public didInfos;

    // publicKeyHash => tokenId (prevent duplicate registration)
    mapping(bytes32 => uint256) public publicKeyToTokenId;

    // wallet address => tokenId (one address can only have one DID)
    mapping(address => uint256) public addressToTokenId;

    uint256 private _nextTokenId;

    // events
    event DIDCreated(uint256 indexed tokenId, address indexed owner, bytes publicKey, uint256 timestamp);

    /// Deprecated: use off-chain verification instead
    event ChallengeVerified(uint256 indexed tokenId, bytes32 challenge, bool success);

    constructor() ERC721("Decentralized Identity", "DID") Ownable(msg.sender) {
        _nextTokenId = 1; // tokenId starts from 1
    }

    /// @notice Mint a DID NFT
    /// @param publicKey The user's DID public key
    /// @param didDocument The DID document URI
    /// forge-lint: disable-next-line(mixed-case-function)
    function mintDID(bytes calldata publicKey, string calldata didDocument) external returns (uint256) {
        require(publicKey.length > 0, "Public key cannot be empty");
        require(addressToTokenId[msg.sender] == 0, "Address already has a DID");

        bytes32 pubKeyHash = keccak256(publicKey);
        require(publicKeyToTokenId[pubKeyHash] == 0, "Public key already registered");

        uint256 tokenId = _nextTokenId++;

        _safeMint(msg.sender, tokenId);

        didInfos[tokenId] = DIDInfo({publicKey: publicKey, createdAt: block.timestamp, didDocument: didDocument});

        publicKeyToTokenId[pubKeyHash] = tokenId;
        addressToTokenId[msg.sender] = tokenId;

        emit DIDCreated(tokenId, msg.sender, publicKey, block.timestamp);
        emit Locked(tokenId); // Soulbound

        return tokenId;
    }

    /// @notice Deprecated: use off-chain verification instead
    /// @notice Verify challenge signature to prove DID ownership
    /// @param tokenId The tokenId of the DID
    /// @param challenge The challenge string
    /// @param signature The signature of the challenge
    function verifyChallenge(uint256 tokenId, bytes32 challenge, bytes calldata signature)
        external
        view
        returns (bool)
    {
        require(_ownerOf(tokenId) != address(0), "DID not exist");

        // Use Ethereum signed message format
        bytes32 ethSignedMessage = challenge.toEthSignedMessageHash();
        address signer = ethSignedMessage.recover(signature);

        // Verify if the signer is the owner of the DID
        return signer == ownerOf(tokenId);
    }

    /// @notice Get DID information
    /// forge-lint: disable-next-line(mixed-case-function)
    function getDIDInfo(uint256 tokenId)
        external
        view
        returns (bytes memory publicKey, uint256 createdAt, string memory didDocument, address owner)
    {
        require(_ownerOf(tokenId) != address(0), "DID not exist");
        DIDInfo storage info = didInfos[tokenId];
        return (info.publicKey, info.createdAt, info.didDocument, ownerOf(tokenId));
    }

    /// @notice Get DID by wallet address
    /// forge-lint: disable-next-line(mixed-case-function)
    function getDIDByAddress(address addr) external view returns (uint256) {
        return addressToTokenId[addr];
    }

    /// @notice Get DID by public key
    /// forge-lint: disable-next-line(mixed-case-function)
    function getDIDByPublicKey(bytes calldata publicKey) external view returns (uint256) {
        return publicKeyToTokenId[keccak256(publicKey)];
    }

    // ========== ERC5192 Soulbound Implementation ==========

    /// @notice Soulbound NFTs are always locked
    function locked(uint256 tokenId) external view override returns (bool) {
        require(_ownerOf(tokenId) != address(0), "Token not exist");
        return true; // Always locked
    }

    /// @notice Prevent transfer
    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);

        // Only allow minting (from == address(0)) and burning (to == address(0))
        if (from != address(0) && to != address(0)) {
            revert("Soulbound:  Transfer not allowed");
        }

        return super._update(to, tokenId, auth);
    }

    /// @notice Supported interfaces
    function supportsInterface(bytes4 interfaceId) public view override(ERC721Enumerable) returns (bool) {
        return interfaceId == type(IERC5192).interfaceId || super.supportsInterface(interfaceId);
    }
}
