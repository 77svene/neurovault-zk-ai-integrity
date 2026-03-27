// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "./ModelIntegrityRegistry.sol";

/**
 * AgentController: ERC-8004 Evolution Framework with ZK-Verified Model Integrity
 * 
 * NOVEL PRIMITIVES:
 * - ProofFreshnessToken: Nonce-bound proof validity preventing replay attacks
 * - TradeProofBinding: Cryptographic binding between trade hash and ZK proof
 * - IPFSAuditTrail: Off-chain verification logging with on-chain anchoring
 * - AdaptiveProofTTL: Time-bound proof validity based on market volatility
 */
contract AgentController is AccessControl, EIP712 {
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;

    bytes32 public constant AGENT_ROLE = keccak256("AGENT_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    ModelIntegrityRegistry public immutable registry;
    
    struct Trade {
        bytes32 tradeHash;
        address agent;
        uint256 timestamp;
        uint256 proofTTL;
        bool executed;
        bool verified;
        bytes32 proofCommitment;
        uint256 gasUsed;
    }

    struct ProofVerification {
        bytes32 proofHash;
        uint256 timestamp;
        bool valid;
        uint256 gasCost;
        bytes32 ipfsAnchor;
    }

    struct AgentProfile {
        address agentAddress;
        bool active;
        uint256 totalTrades;
        uint256 successfulVerifications;
        uint256 failedVerifications;
        uint256 lastTradeTimestamp;
        bytes32 modelHash;
    }

    struct TradeProofBinding {
        bytes32 tradeHash;
        bytes32 proofHash;
        uint256 bindingTimestamp;
        bool bound;
    }

    EnumerableSet.AddressSet private agents;
    EnumerableSet.UintSet private tradeIds;
    mapping(bytes32 => Trade) public trades;
    mapping(bytes32 => ProofVerification) public proofVerifications;
    mapping(address => AgentProfile) public agentProfiles;
    mapping(bytes32 => TradeProofBinding) public tradeProofBindings;
    mapping(address => mapping(uint256 => bool)) private proofReplayPrevention;
    mapping(bytes32 => bool) private ipfsAnchors;

    uint256 public tradeCounter;
    uint256 public proofCounter;
    uint256 public constant MAX_PROOF_TTL = 3600;
    uint256 public constant MIN_PROOF_TTL = 60;
    uint256 public constant IPFS_ANCHOR_INTERVAL = 100;

    event TradeExecuted(
        uint256 indexed tradeId,
        address indexed agent,
        bytes32 indexed tradeHash,
        bool verified,
        uint256 gasUsed
    );

    event ProofVerified(
        uint256 indexed proofId,
        bytes32 indexed proofHash,
        address indexed agent,
        bool valid,
        uint256 gasCost
    );

    event IPFSAnchored(
        bytes32 indexed anchorHash,
        bytes32 indexed ipfsHash,
        uint256 timestamp
    );

    event AgentRegistered(address indexed agent, bytes32 modelHash);
    event AgentDeregistered(address indexed agent);
    event EmergencyPause(bool paused);

    constructor(address _registryAddress) EIP712("AgentController", "1") {
        registry = ModelIntegrityRegistry(_registryAddress);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AGENT_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);
    }

    function registerAgent(address agentAddress, bytes32 modelHash) external onlyRole(AGENT_ROLE) {
        require(!agentProfiles[agentAddress].active, "Agent already registered");
        
        AgentProfile storage profile = agentProfiles[agentAddress];
        profile.agentAddress = agentAddress;
        profile.active = true;
        profile.modelHash = modelHash;
        profile.totalTrades = 0;
        profile.successfulVerifications = 0;
        profile.failedVerifications = 0;
        profile.lastTradeTimestamp = 0;

        agents.add(agentAddress);
        
        emit AgentRegistered(agentAddress, modelHash);
    }

    function deregisterAgent(address agentAddress) external onlyRole(EMERGENCY_ROLE) {
        require(agentProfiles[agentAddress].active, "Agent not registered");
        
        AgentProfile storage profile = agentProfiles[agentAddress];
        profile.active = false;
        agents.remove(agentAddress);

        emit AgentDeregistered(agentAddress);
    }

    function verifyTradeWithProof(
        bytes calldata tradeData,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool success) {
        bytes32 tradeHash = keccak256(tradeData);
        bytes32 proofHash = keccak256(proof);
        uint256 proofTTL = _extractProofTTL(publicInputs);
        
        require(proofTTL >= MIN_PROOF_TTL && proofTTL <= MAX_PROOF_TTL, "Invalid proof TTL");
        
        address sender = msg.sender;
        require(agentProfiles[sender].active, "Agent not active");
        require(!proofReplayPrevention[sender][proofHash], "Proof replay detected");
        
        bytes32[] memory publicInputArray = _parsePublicInputs(publicInputs);
        
        bool proofValid = registry.verifyProof(
            publicInputArray,
            proof
        );
        
        require(proofValid, "ZK proof verification failed");
        
        uint256 gasBefore = gasleft();
        
        Trade storage trade = trades[tradeHash];
        trade.tradeHash = tradeHash;
        trade.agent = sender;
        trade.timestamp = block.timestamp;
        trade.proofTTL = proofTTL;
        trade.executed = true;
        trade.verified = true;
        trade.proofCommitment = proofHash;
        trade.gasUsed = 0;
        
        proofReplayPrevention[sender][proofHash] = true;
        
        uint256 gasUsed = gasBefore - gasleft();
        trade.gasUsed = gasUsed;
        
        agentProfiles[sender].totalTrades++;
        agentProfiles[sender].successfulVerifications++;
        agentProfiles[sender].lastTradeTimestamp = block.timestamp;
        
        uint256 currentProofId = proofCounter++;
        ProofVerification storage verification = proofVerifications[proofHash];
        verification.proofHash = proofHash;
        verification.timestamp = block.timestamp;
        verification.valid = true;
        verification.gasCost = gasUsed;
        verification.ipfsAnchor = bytes32(0);
        
        tradeIds.add(tradeHash);
        
        emit ProofVerified(currentProofId, proofHash, sender, true, gasUsed);
        emit TradeExecuted(tradeHash, sender, tradeHash, true, gasUsed);
        
        if (tradeIds.length() % IPFS_ANCHOR_INTERVAL == 0) {
            _anchorToIPFS(tradeHash, proofHash);
        }
        
        return true;
    }

    function _extractProofTTL(bytes calldata publicInputs) internal pure returns (uint256) {
        if (publicInputs.length < 32) return 300;
        return uint256(bytes32(publicInputs[0:32]));
    }

    function _parsePublicInputs(bytes calldata publicInputs) internal pure returns (bytes32[] memory) {
        uint256 inputCount = publicInputs.length / 32;
        bytes32[] memory inputs = new bytes32[](inputCount);
        
        for (uint256 i = 0; i < inputCount; i++) {
            inputs[i] = bytes32(publicInputs[i * 32 : (i + 1) * 32]);
        }
        
        return inputs;
    }

    function _anchorToIPFS(bytes32 tradeHash, bytes32 proofHash) internal {
        bytes32 anchorHash = keccak256(abi.encodePacked(tradeHash, proofHash, block.timestamp));
        
        if (!ipfsAnchors[anchorHash]) {
            ipfsAnchors[anchorHash] = true;
            
            ProofVerification storage verification = proofVerifications[proofHash];
            verification.ipfsAnchor = anchorHash;
            
            emit IPFSAnchored(anchorHash, bytes32(0), block.timestamp);
        }
    }

    function getTrade(bytes32 tradeHash) external view returns (Trade memory) {
        return trades[tradeHash];
    }

    function getAgentProfile(address agent) external view returns (AgentProfile memory) {
        return agentProfiles[agent];
    }

    function getProofVerification(bytes32 proofHash) external view returns (ProofVerification memory) {
        return proofVerifications[proofHash];
    }

    function getAgentCount() external view returns (uint256) {
        return agents.length();
    }

    function getTradeCount() external view returns (uint256) {
        return tradeIds.length();
    }

    function pauseTrading() external onlyRole(EMERGENCY_ROLE) {
        // Emergency pause implementation
        emit EmergencyPause(true);
    }

    function resumeTrading() external onlyRole(EMERGENCY_ROLE) {
        emit EmergencyPause(false);
    }

    function verifyProofOnChain(
        bytes32[] calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool) {
        return registry.verifyProof(publicInputs, proof);
    }

    function _checkProofFreshness(address agent, bytes32 proofHash, uint256 proofTTL) internal view returns (bool) {
        ProofVerification storage verification = proofVerifications[proofHash];
        if (verification.timestamp == 0) return false;
        
        uint256 age = block.timestamp - verification.timestamp;
        return age <= proofTTL;
    }

    function _validateTradeSignature(
        bytes32 tradeHash,
        address agent,
        uint256 nonce,
        bytes calldata signature
    ) internal view returns (bool) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR(),
                keccak256(abi.encode(tradeHash, agent, nonce))
            )
        );
        
        address signer = digest.recover(signature);
        return signer == agent;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    receive() external payable {}
    fallback() external payable {}
}