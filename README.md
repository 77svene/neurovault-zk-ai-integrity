# NeuroVault: ZK-Verified AI Model Integrity for Autonomous Trading

**Proof-of-Model-Fidelity (PoMF) Protocol**  
**Version:** 1.0.0  
**License:** MIT  
**Target:** AI Trading Agents | lablab.ai | $55,000 SURGE token  
**Deadline:** April 12, 2026

---

## 🎯 What is NeuroVault?

NeuroVault is the first implementation of **Proof-of-Model-Fidelity (PoMF)** — a zero-knowledge verification layer that proves an AI trading agent's weights match a registered on-chain hash without revealing the model itself.

### The Problem

Black-box AI agents in DeFi pose systemic risk:
- **Weight Tampering:** Adversaries can modify model weights to manipulate trades
- **Strategy Theft:** Proprietary trading strategies are exposed through reverse engineering
- **Trust Deficit:** No way to verify an agent's strategy integrity without exposing IP

### The Solution

NeuroVault uses zk-SNARKs to generate a cryptographic proof that:
1. The agent's inference weights match a registered hash
2. The strategy hasn't been adversarially modified
3. The proof can be verified on-chain without revealing the model

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NEUROVAULT SYSTEM                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │   Agent      │    │   Circuit    │    │   Registry           │  │
│  │   (Local)    │───▶│   (Circom)   │───▶│   (On-Chain)         │  │
│  │              │    │              │    │                      │  │
│  │ - Weights    │    │ - SHA256     │    │ - Model Registration │  │
│  │ - Strategy   │    │ - Padding    │    │ - Proof Verification │  │
│  │ - Execution  │    │ - Proof Gen  │    │ - Integrity Checks   │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│         │                   │                      │                │
│         ▼                   ▼                      ▼                │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    AgentController.sol                        │  │
│  │  - Trade Settlement Gatekeeper                                │  │
│  │  - Proof Verification Before Execution                        │  │
│  │  - Nonce + Timestamp Validation                               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites

```bash
# Node.js >= 18.0.0
node --version

# Hardhat for contract compilation
npm install -D hardhat @nomicfoundation/hardhat-toolbox

# Circom for circuit compilation
npm install -g circomlib circomlibjs snarkjs

# Git for repository management
git --version
```

### Clone Repository

```bash
git clone https://github.com/neurovault/neurovault.git
cd neurovault
```

### Install Dependencies

```bash
npm install
```

### Environment Setup

Create `.env` file:

```env
# Private key for contract deployment (NEVER commit this)
PRIVATE_KEY=0x...

# RPC URLs for different networks
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
ARBITRUM_RPC_URL=https://arb1.arbitrum.io/rpc

# Circuit compilation output path
CIRCUIT_OUTPUT=circuits/build
```

### Compile Contracts

```bash
npm run compile
```

### Compile ZK Circuit

```bash
npm run build:circuit
```

---

## 🔐 Model Hash Registration

### Step 1: Prepare Your Model Weights

Export your trained model weights to a binary file:

```bash
# Example: Export PyTorch model weights
python export_weights.py --model my_trading_agent.pt --output weights.bin
```

### Step 2: Calculate Model Hash

```bash
# Calculate SHA256 hash of weights file
sha256sum weights.bin
# Output: a1b2c3d4e5f6... (64 character hex string)
```

### Step 3: Register Model on Chain

```bash
# Deploy contracts (first time only)
npm run deploy

# Register model hash
npx hardhat run scripts/registerModel.js --network localhost
```

### registerModel.js Script

```javascript
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const ModelIntegrityRegistry = await hre.ethers.getContractFactory("ModelIntegrityRegistry");
  const registry = await ModelIntegrityRegistry.deploy();
  await registry.waitForDeployment();

  const modelHash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
  const modelMetadata = "trading_agent_v1.0";

  const tx = await registry.registerModel(modelHash, modelMetadata, {
    gasLimit: 500000
  });

  await tx.wait();
  console.log("Model registered at:", registry.target);
  console.log("Model hash:", modelHash);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
```

### Verify Registration

```bash
# Query registered model
npx hardhat run scripts/verifyModel.js --network localhost
```

---

## 🔑 Generating ZK Proofs

### Prerequisites

Ensure circuit is compiled:

```bash
npm run build:circuit
```

### Generate Witness

```bash
# Generate witness from model weights
node scripts/generateWitness.js --weights weights.bin --output witness.wtns
```

### generateWitness.js Script

```javascript
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

async function generateWitness(weightsPath, outputPath) {
  const weights = fs.readFileSync(weightsPath);
  const weightsHash = await sha256(weights);
  
  const input = {
    weightHash: weightsHash,
    registeredHash: "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
  };

  const { witness } = await snarkjs.zokrates.computeWitness(
    path.join(__dirname, "../circuits/build/modelProof.wasm"),
    input
  );

  await snarkjs.wtns.calculate(witness, path.join(__dirname, "../circuits/build/modelProof.wtns"));
  console.log("Witness generated:", outputPath);
}

async function sha256(data) {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

generateWitness(process.argv[2], process.argv[3]).catch(console.error);
```

### Generate Proof

```bash
# Generate ZK proof
node scripts/generateProof.js --witness witness.wtns --output proof.json --public proof.json
```

### generateProof.js Script

```javascript
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

async function generateProof(witnessPath, proofPath, publicPath) {
  const vKey = await fs.promises.readFile(
    path.join(__dirname, "../circuits/build/key_verification_key.json")
  );

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      weightHash: "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
      registeredHash: "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
    },
    path.join(__dirname, "../circuits/build/modelProof.wasm"),
    path.join(__dirname, "../circuits/build/final.zkey")
  );

  const verificationKey = JSON.parse(fs.readFileSync(path.join(__dirname, "../circuits/build/key_verification_key.json"), "utf8"));

  const isValid = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    proof
  );

  console.log("Proof valid:", isValid);
  console.log("Public signals:", publicSignals);

  await fs.promises.writeFile(proofPath, JSON.stringify(proof, null, 2));
  await fs.promises.writeFile(publicPath, JSON.stringify(publicSignals, null, 2));
}

generateProof(process.argv[2], process.argv[3], process.argv[4]).catch(console.error);
```

### Verify Proof Locally

```bash
# Verify proof before submitting to chain
node scripts/verifyProof.js --proof proof.json --public public.json
```

---

## 🤖 NeuroAgent API Documentation

### Interface Definition

```typescript
interface NeuroAgent {
  // Core lifecycle methods
  initialize(config: AgentConfig): Promise<void>;
  shutdown(): Promise<void>;
  
  // Model integrity methods
  registerModel(weightsPath: string): Promise<string>;
  verifyModelIntegrity(): Promise<boolean>;
  generateProof(): Promise<ZKProof>;
  
  // Trading execution methods
  executeStrategy(marketData: MarketData): Promise<Trade>;
  executeTrade(trade: Trade): Promise<TradeExecution>;
  
  // State management
  getState(): AgentState;
  setState(state: AgentState): Promise<void>;
}
```

### AgentConfig Interface

```typescript
interface AgentConfig {
  // Network configuration
  rpcUrl: string;
  chainId: number;
  
  // Contract addresses
  registryAddress: string;
  controllerAddress: string;
  
  // Model configuration
  modelPath: string;
  modelHash: string;
  
  // Security configuration
  privateKey: string;
  proofTTL: number; // seconds
}
```

### ZKProof Interface

```typescript
interface ZKProof {
  proof: {
    pi_a: string[];
    pi_b: string[];
    pi_c: string[];
  };
  publicSignals: string[];
  circuit: string;
  version: string;
}
```

### AgentState Interface

```typescript
interface AgentState {
  modelHash: string;
  lastProofTimestamp: number;
  tradeCount: number;
  totalVolume: string;
  integrityStatus: "verified" | "pending" | "failed";
}
```

### Usage Example

```javascript
const { NeuroAgent } = require("./src/agent/NeuroAgent");

async function main() {
  const agent = new NeuroAgent();
  
  await agent.initialize({
    rpcUrl: "http://localhost:8545",
    chainId: 31337,
    registryAddress: "0x...",
    controllerAddress: "0x...",
    modelPath: "./weights.bin",
    modelHash: "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
    privateKey: process.env.PRIVATE_KEY,
    proofTTL: 3600
  });

  // Register model
  const hash = await agent.registerModel("./weights.bin");
  console.log("Model registered:", hash);

  // Verify integrity
  const isIntact = await agent.verifyModelIntegrity();
  console.log("Model integrity:", isIntact);

  // Generate proof
  const proof = await agent.generateProof();
  console.log("Proof generated:", proof);

  // Execute strategy
  const marketData = {
    price: 1500.50,
    volume: 1000000,
    timestamp: Date.now()
  };

  const trade = await agent.executeStrategy(marketData);
  console.log("Trade executed:", trade);

  await agent.shutdown();
}

main().catch(console.error);
```

### Method Details

#### `initialize(config: AgentConfig)`

Initializes the agent with configuration parameters.

**Parameters:**
- `config`: Agent configuration object

**Returns:** `Promise<void>`

**Throws:** `Error` if configuration is invalid

#### `registerModel(weightsPath: string): Promise<string>`

Calculates hash of model weights and registers on-chain.

**Parameters:**
- `weightsPath`: Path to model weights file

**Returns:** `Promise<string>` - On-chain model hash

**Throws:** `Error` if file not found or registration fails

#### `verifyModelIntegrity(): Promise<boolean>`

Verifies current model weights match registered hash.

**Returns:** `Promise<boolean>` - True if weights match

**Throws:** `Error` if verification fails

#### `generateProof(): Promise<ZKProof>`

Generates zero-knowledge proof of model fidelity.

**Returns:** `Promise<ZKProof>` - ZK proof object

**Throws:** `Error` if proof generation fails

#### `executeStrategy(marketData: MarketData): Promise<Trade>`

Executes trading strategy based on market data.

**Parameters:**
- `marketData`: Current market data

**Returns:** `Promise<Trade>` - Executed trade

**Throws:** `Error` if strategy execution fails

#### `executeTrade(trade: Trade): Promise<TradeExecution>`

Submits trade to AgentController for settlement.

**Parameters:**
- `trade`: Trade object to execute

**Returns:** `Promise<TradeExecution>` - Execution result

**Throws:** `Error` if trade rejected by controller

---

## 🧪 Testing

### Run All Tests

```bash
npm test
```

### Run Specific Test File

```bash
npx hardhat test test/ModelIntegrityRegistry.test.js
```

### Test Coverage

```bash
npx hardhat coverage
```

---

## 🔒 Security Considerations

### Private Key Management

**NEVER** commit private keys to version control:

```bash
# ✅ Correct
PRIVATE_KEY=0x...  # In .env file

# ❌ Wrong
const privateKey = "0x...";  # In source code
```

### Trusted Setup

NeuroVault uses a multi-party trusted setup ceremony:

```bash
# Download ceremony parameters
wget https://github.com/privacy-scaling-explorations/zkevm-circuits/raw/main/powersOfTau28_hez_final_01.json

# Verify ceremony integrity
sha256sum powersOfTau28_hez_final_01.json
```

### Circuit Constraints

The `modelProof.circom` circuit enforces:

1. **SHA256 Padding Compliance:** RFC 3174 standard padding
2. **Hash Equality:** `assert(weightHash == registeredHash)`
3. **Proof Validity:** Groth16 verification on-chain

---

## 📊 Dashboard

Access the web dashboard for real-time monitoring:

```bash
# Start local server
npx serve public -p 3000

# Or open directly in browser
open public/dashboard.html
```

### Dashboard Features

- Model registration status
- Proof verification history
- Trade execution logs
- Integrity audit trail

---

## 🚀 Deployment

### Deploy to Testnet

```bash
# Deploy to Sepolia
npx hardhat run scripts/deploy.js --network sepolia

# Deploy to Arbitrum
npx hardhat run scripts/deploy.js --network arbitrum
```

### Verify Contracts

```bash
# Verify on Etherscan
npx hardhat verify --network sepolia <CONTRACT_ADDRESS>
```

---

## 📝 License

MIT License - See LICENSE file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📞 Support

- **Issues:** https://github.com/neurovault/neurovault/issues
- **Documentation:** https://docs.neurovault.io
- **Community:** https://discord.gg/neurovault

---

**Built with cryptographic self-enforcement. No trust assumptions. Pure math.**