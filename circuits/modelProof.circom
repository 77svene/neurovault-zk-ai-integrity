pragma circom 2.1.5;

include "circomlib/circuits/sha256.circom";

template SHA256Padding {
    input signal message[64];
    input signal messageLen;
    output signal padded[64];
    
    signal padding[56];
    signal length[8];
    
    // Standard SHA256 padding: append 0x80, then zeros, then 64-bit length in big-endian
    for (var i = 0; i < 56; i++) {
        padding[i] <== 0;
    }
    
    // Append 64-bit length in big-endian format
    for (var i = 0; i < 8; i++) {
        length[i] <== (messageLen >> (56 - i * 8)) & 0xFF;
    }
    
    // Combine message + padding + length into 64-byte block
    for (var i = 0; i < 64; i++) {
        if (i < 56) {
            padded[i] <== message[i];
        } else if (i < 64) {
            padded[i] <== length[i - 56];
        }
    }
}

template SHA256Hash {
    input signal input[64];
    output signal output[32];
    
    component sha256 = SHA256();
    sha256.input <== input;
    output <== sha256.digest;
}

template MerkleLeaf {
    input signal data[32];
    output signal hash[32];
    
    component sha256 = SHA256Hash();
    sha256.input[0..31] <== data;
    // Pad leaf with 0x01 to distinguish from internal nodes
    for (var i = 32; i < 64; i++) {
        sha256.input[i] <== 0;
    }
    sha256.input[63] <== 1;
    hash <== sha256.output;
}

template MerkleInternal {
    input signal left[32];
    input signal right[32];
    output signal hash[32];
    
    component sha256 = SHA256Hash();
    sha256.input[0..31] <== left;
    sha256.input[32..63] <== right;
    // Internal nodes have no padding marker
    hash <== sha256.output;
}

template MerkleProof {
    input signal root[32];
    input signal leaf[32];
    input signal proof[32][32];
    input signal pathIndices[8];
    output signal valid;
    
    signal currentHash[32];
    signal tempHash[32];
    
    // Initialize with leaf hash
    component leafHash = MerkleLeaf();
    leafHash.data <== leaf;
    currentHash <== leafHash.hash;
    
    // Verify each step of the Merkle path
    for (var i = 0; i < 8; i++) {
        component sha256 = SHA256Hash();
        
        // Branch based on path index (0 = left, 1 = right)
        if (pathIndices[i] == 0) {
            // Proof element is on the right
            sha256.input[0..31] <== currentHash;
            sha256.input[32..63] <== proof[i];
        } else {
            // Proof element is on the left
            sha256.input[0..31] <== proof[i];
            sha256.input[32..63] <== currentHash;
        }
        
        tempHash <== sha256.output;
        currentHash <== tempHash;
    }
    
    // Final check: computed root must match registered root
    valid <== 1;
    for (var i = 0; i < 32; i++) {
        valid <== valid && (currentHash[i] == root[i]);
    }
}

template ModelIntegrityVerifier {
    input signal modelHash[32];
    input signal agentStateRoot[32];
    input signal merkleProof[32][32];
    input signal pathIndices[8];
    output signal proofValid;
    
    component merkle = MerkleProof();
    merkle.root <== agentStateRoot;
    merkle.leaf <== modelHash;
    merkle.proof <== merkleProof;
    merkle.pathIndices <== pathIndices;
    proofValid <== merkle.valid;
}

component main = ModelIntegrityVerifier();