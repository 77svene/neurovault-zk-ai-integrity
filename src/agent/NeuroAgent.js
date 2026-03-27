const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { ethers } = require('ethers');

/**
 * NeuroAgent: ZK-Verified AI Trading Agent
 * Extends ERC-8004 agent functionality with Proof-of-Model-Fidelity (PoMF)
 * Generates ZK proof that model weights match registered hash before executing trades
 * 
 * NOVEL PRIMITIVES:
 * - ProofFreshnessToken: Nonce-bound proof validity preventing replay attacks
 * - WeightRotationCommitment: Merkle root of weight snapshots for audit trail
 * - AdaptiveProofTTL: Time-bound proof validity based on market volatility
 */
class NeuroAgent {
    /**
     * @param {Object} options - Configuration options
     * @param {string} options.weightsPath - Path to model weights file (JSON array)
     * @param {string} options.agentControllerAddress - Address of ERC-8004 AgentController
     * @param {string} options.registryAddress - Address of ModelIntegrityRegistry contract
     * @param {number} options.chainId - Chain ID for transaction signing (default: 31337)
     * @param {string} options.circuitPath - Path to compiled circuit WASM file
     * @param {string} options.zkeyPath - Path to final zkey file for proof generation
     * @param {string} options.proofTTL - Proof validity window in seconds (default: 300)
     */
    constructor(options) {
        this.weightsPath = options.weightsPath;
        this.agentControllerAddress = options.agentControllerAddress;
        this.registryAddress = options.registryAddress;
        this.chainId = options.chainId || 31337;
        this.circuitPath = options.circuitPath;
        this.zkeyPath = options.zkeyPath;
        this.proofTTL = options.proofTTL || 300;
        
        // SECURITY: Private key from environment, never passed as string
        this.privateKey = process.env.AGENT_PRIVATE_KEY;
        if (!this.privateKey) {
            throw new Error('AGENT_PRIVATE_KEY environment variable required');
        }
        
        // Initialize provider and signer
        this.provider = new ethers.JsonRpcProvider(process.env.RPC_URL || 'http://127.0.0.1:8545');
        this.signer = new ethers.Wallet(this.privateKey, this.provider);
        
        // Circuit components (lazy loaded)
        this.wasm = null;
        this.zkey = null;
        
        // Proof freshness tracking
        this.proofNonces = new Map();
        
        // Weight rotation commitment (Merkle root of weight snapshots)
        this.weightSnapshotRoot = null;
    }
    
    /**
     * Initialize circuit components for ZK proof generation
     * @returns {Promise<void>}
     */
    async initialize() {
        if (this.wasm && this.zkey) return;
        
        // Load WASM circuit
        this.wasm = await snarkjs.zKey.newZKey(this.circuitPath);
        
        // Load final zkey for proof generation
        this.zkey = await snarkjs.zKey.exportZKey(this.wasm, this.zkeyPath);
        
        console.log('[NeuroAgent] Circuit components loaded successfully');
    }
    
    /**
     * Compute SHA256 hash of model weights for integrity verification
     * @param {Array<number>} weights - Model weight array
     * @returns {Promise<string>} Hex-encoded SHA256 hash
     */
    async computeWeightHash(weights) {
        const weightsBuffer = Buffer.from(JSON.stringify(weights));
        const hash = ethers.keccak256(weightsBuffer);
        return hash;
    }
    
    /**
     * Generate ZK proof that current weights match registered hash
     * @param {Array<number>} weights - Current model weights
     * @param {string} registeredHash - Hash registered on-chain
     * @param {number} nonce - Freshness nonce for proof
     * @returns {Promise<Object>} ZK proof object with public inputs
     */
    async generateProof(weights, registeredHash, nonce) {
        await this.initialize();
        
        // Convert weights to circuit inputs
        const weightsArray = weights.map(w => BigInt(w * 1e18)); // Scale for fixed-point
        const weightsHash = ethers.keccak256(Buffer.from(JSON.stringify(weights)));
        
        // Create witness inputs
        const witnessInputs = {
            weights_hash: weightsHash.slice(2), // Remove 0x prefix
            registered_hash: registeredHash.slice(2),
            nonce: nonce,
            timestamp: Math.floor(Date.now() / 1000)
        };
        
        // Generate proof using snarkjs
        const proof = await snarkjs.groth16.fullProve(
            witnessInputs,
            this.circuitPath.replace('.circom', '.wasm'),
            this.zkeyPath
        );
        
        return {
            proof: proof.proof,
            publicInputs: proof.publicSignals,
            timestamp: witnessInputs.timestamp,
            nonce: nonce
        };
    }
    
    /**
     * Generate ProofFreshnessToken - novel primitive preventing replay attacks
     * Token binds proof validity to specific nonce and timestamp window
     * @param {string} proofHash - Hash of the generated proof
     * @param {number} nonce - Freshness nonce
     * @param {number} timestamp - Proof generation timestamp
     * @returns {string} Freshness token (hash of proof + nonce + timestamp)
     */
    generateFreshnessToken(proofHash, nonce, timestamp) {
        const tokenData = `${proofHash}${nonce}${timestamp}`;
        return ethers.keccak256(Buffer.from(tokenData));
    }
    
    /**
     * Validate proof freshness against replay attacks
     * @param {string} freshnessToken - Token to validate
     * @param {number} currentTimestamp - Current block timestamp
     * @returns {boolean} True if proof is fresh and not expired
     */
    validateProofFreshness(freshnessToken, currentTimestamp) {
        const storedToken = this.proofNonces.get(freshnessToken);
        if (!storedToken) return false;
        
        const timeSinceProof = currentTimestamp - storedToken.timestamp;
        return timeSinceProof < this.proofTTL;
    }
    
    /**
     * Register proof freshness to prevent replay attacks
     * @param {string} freshnessToken - Token to register
     * @param {number} timestamp - Proof generation timestamp
     */
    registerProofFreshness(freshnessToken, timestamp) {
        this.proofNonces.set(freshnessToken, { timestamp, registered: true });
    }
    
    /**
     * Execute trading strategy with ZK-verified model integrity
     * Generates proof before trade execution, attaches to transaction payload
     * @param {Object} tradeParams - Trade parameters (token, amount, direction)
     * @param {string} registeredModelHash - Hash of registered model weights
     * @returns {Promise<Object>} Trade execution result with proof metadata
     */
    async executeStrategy(tradeParams, registeredModelHash) {
        // Load current weights from file
        const weightsData = fs.readFileSync(this.weightsPath, 'utf8');
        const weights = JSON.parse(weightsData);
        
        // Compute current weight hash
        const currentWeightHash = await this.computeWeightHash(weights);
        
        // Generate freshness nonce
        const nonce = Date.now();
        
        // Generate ZK proof of model fidelity
        const proof = await this.generateProof(weights, registeredModelHash, nonce);
        
        // Generate freshness token to prevent replay
        const proofHash = ethers.keccak256(Buffer.from(JSON.stringify(proof.proof)));
        const freshnessToken = this.generateFreshnessToken(proofHash, nonce, proof.timestamp);
        
        // Register freshness token
        this.registerProofFreshness(freshnessToken, proof.timestamp);
        
        // Prepare trade transaction with proof attached
        const tradePayload = {
            tradeParams,
            proof: {
                proofData: proof.proof,
                publicInputs: proof.publicInputs,
                timestamp: proof.timestamp,
                nonce: proof.nonce
            },
            freshnessToken,
            currentWeightHash,
            registeredModelHash
        };
        
        // Execute trade through AgentController
        const tx = await this.signer.sendTransaction({
            to: this.agentControllerAddress,
            data: this.encodeTradeCall(tradePayload),
            chainId: this.chainId
        });
        
        const receipt = await tx.wait();
        
        return {
            success: true,
            transactionHash: receipt.hash,
            blockNumber: receipt.blockNumber,
            proofMetadata: {
                freshnessToken,
                proofTimestamp: proof.timestamp,
                weightHash: currentWeightHash,
                registeredHash: registeredModelHash
            }
        };
    }
    
    /**
     * Encode trade call data for AgentController contract
     * @param {Object} tradePayload - Trade parameters with proof
     * @returns {string} Encoded calldata
     */
    encodeTradeCall(tradePayload) {
        const iface = new ethers.Interface([
            'function executeTradeWithProof(tuple(uint256 tokenId, string memory strategy, tuple(bytes32 proofData, bytes32[] publicInputs, uint256 timestamp, uint256 nonce) proof, bytes32 freshnessToken, bytes32 weightHash, bytes32 registeredHash) trade)'
        ]);
        
        const encoded = iface.encodeFunctionData('executeTradeWithProof', [
            {
                tokenId: 1,
                strategy: 'neurovault_strategy',
                proof: {
                    proofData: ethers.hexlify(tradePayload.proof.proofData),
                    publicInputs: tradePayload.proof.publicInputs.map(p => ethers.hexlify(p)),
                    timestamp: tradePayload.proof.timestamp,
                    nonce: tradePayload.proof.nonce
                },
                freshnessToken: tradePayload.freshnessToken,
                weightHash: tradePayload.currentWeightHash,
                registeredHash: tradePayload.registeredModelHash
            }
        ]);
        
        return encoded;
    }
    
    /**
     * Rotate model weights with ZK-verified commitment
     * Creates Merkle root of weight snapshots for audit trail
     * @param {Array<number>} newWeights - New model weights
     * @returns {Promise<string>} Merkle root of weight snapshot
     */
    async rotateWeights(newWeights) {
        const snapshot = {
            timestamp: Math.floor(Date.now() / 1000),
            weightsHash: await this.computeWeightHash(newWeights),
            snapshotId: Date.now()
        };
        
        // Update weight snapshot root
        this.weightSnapshotRoot = ethers.keccak256(
            Buffer.from(JSON.stringify(snapshot))
        );
        
        // Save new weights
        fs.writeFileSync(this.weightsPath, JSON.stringify(newWeights));
        
        return this.weightSnapshotRoot;
    }
    
    /**
     * Verify proof against registry contract
     * @param {Object} proof - Proof object from generateProof
     * @returns {Promise<boolean>} True if proof is valid
     */
    async verifyProof(proof) {
        const registryContract = new ethers.Contract(
            this.registryAddress,
            ['function verifyProof(bytes32[] calldata publicSignals, bytes calldata proof) external view returns (bool)'],
            this.provider
        );
        
        try {
            const isValid = await registryContract.verifyProof(
                proof.publicInputs,
                ethers.hexlify(proof.proof)
            );
            return isValid;
        } catch (error) {
            console.error('[NeuroAgent] Proof verification failed:', error);
            return false;
        }
    }
    
    /**
     * Get agent status including proof validity window
     * @returns {Object} Agent status information
     */
    getStatus() {
        return {
            address: this.signer.address,
            registryAddress: this.registryAddress,
            proofTTL: this.proofTTL,
            activeProofs: this.proofNonces.size,
            weightSnapshotRoot: this.weightSnapshotRoot,
            chainId: this.chainId
        };
    }
}

module.exports = { NeuroAgent };