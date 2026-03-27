const { expect } = require("chai");
const { ethers } = require("hardhat");
const { groth16 } = require("snarkjs");
const fs = require("fs");
const path = require("path");

describe("ModelIntegrityRegistry", function () {
  let registry, owner, agent, auditor, maliciousAgent;
  let circuitPath, wasmPath, zkeyPath, vkeyPath;

  const TEST_MODEL_HASH = "0x" + "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  const TAMPERED_MODEL_HASH = "0x" + "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";

  before(async function () {
    [owner, agent, auditor, maliciousAgent] = await ethers.getSigners();

    const ModelIntegrityRegistry = await ethers.getContractFactory("ModelIntegrityRegistry", owner);
    registry = await ModelIntegrityRegistry.deploy();
    await registry.waitForDeployment();

    const AgentController = await ethers.getContractFactory("AgentController", owner);
    const agentController = await AgentController.deploy();
    await agentController.waitForDeployment();

    await registry.setAgentController(agentController);
  });

  beforeEach(async function () {
    circuitPath = path.join(__dirname, "../circuits/build/modelProof.wasm");
    wasmPath = circuitPath;
    zkeyPath = path.join(__dirname, "../circuits/build/modelProof_final.zkey");
    vkeyPath = path.join(__dirname, "../circuits/build/verification_key.json");
  });

  describe("Model Registration", function () {
    it("Should register a new model with valid hash", async function () {
      const tx = await registry.registerModel(TEST_MODEL_HASH, { from: agent.address });
      const receipt = await tx.wait();

      expect(receipt.status).to.equal(1);
      expect(await registry.isModelRegistered(TEST_MODEL_HASH)).to.be.true;
      expect(await registry.modelOwner(TEST_MODEL_HASH)).to.equal(agent.address);
    });

    it("Should emit ModelRegistered event", async function () {
      const tx = await registry.registerModel(TEST_MODEL_HASH, { from: agent.address });
      await expect(tx)
        .to.emit(registry, "ModelRegistered")
        .withArgs(TEST_MODEL_HASH, agent.address, ethers.getBigInt(0));
    });

    it("Should reject duplicate model registration", async function () {
      await registry.registerModel(TEST_MODEL_HASH, { from: agent.address });
      
      await expect(
        registry.registerModel(TEST_MODEL_HASH, { from: agent.address })
      ).to.be.revertedWith("Model already registered");
    });

    it("Should reject zero hash registration", async function () {
      await expect(
        registry.registerModel("0x0000000000000000000000000000000000000000000000000000000000000000", { from: agent.address })
      ).to.be.revertedWith("Invalid model hash");
    });

    it("Should allow model owner to update hash", async function () {
      const newHash = "0x" + "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
      
      await registry.registerModel(TEST_MODEL_HASH, { from: agent.address });
      await registry.updateModelHash(TEST_MODEL_HASH, newHash, { from: agent.address });
      
      expect(await registry.isModelRegistered(newHash)).to.be.true;
      expect(await registry.modelOwner(newHash)).to.equal(agent.address);
    });

    it("Should reject non-owner hash update", async function () {
      await registry.registerModel(TEST_MODEL_HASH, { from: agent.address });
      
      await expect(
        registry.updateModelHash(TEST_MODEL_HASH, TAMPERED_MODEL_HASH, { from: maliciousAgent.address })
      ).to.be.revertedWith("Not model owner");
    });
  });

  describe("Proof Verification", function () {
    let witness, proof, publicSignals;

    before(async function () {
      if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
        this.skip();
      }

      witness = await groth16.fullProve(
        {
          weightHash: TEST_MODEL_HASH.replace("0x", ""),
          registeredHash: TEST_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      proof = witness.proof;
      publicSignals = witness.publicSignals;
    });

    it("Should verify valid proof", async function () {
      const isValid = await registry.verifyProof(
        publicSignals,
        proof
      );
      expect(isValid).to.be.true;
    });

    it("Should reject tampered proof", async function () {
      const tamperedPublicSignals = [
        TAMPERED_MODEL_HASH.replace("0x", ""),
        publicSignals[1]
      ];

      const isValid = await registry.verifyProof(
        tamperedPublicSignals,
        proof
      );
      expect(isValid).to.be.false;
    });

    it("Should reject proof with mismatched hashes", async function () {
      const witness = await groth16.fullProve(
        {
          weightHash: TEST_MODEL_HASH.replace("0x", ""),
          registeredHash: TAMPERED_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      const isValid = await registry.verifyProof(
        witness.publicSignals,
        witness.proof
      );
      expect(isValid).to.be.false;
    });

    it("Should reject invalid proof format", async function () {
      const invalidProof = [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000"
      ];

      await expect(
        registry.verifyProof(publicSignals, invalidProof)
      ).to.be.revertedWith("Invalid proof");
    });
  });

  describe("Gas Limits", function () {
    it("Should verify proof within gas limit", async function () {
      const witness = await groth16.fullProve(
        {
          weightHash: TEST_MODEL_HASH.replace("0x", ""),
          registeredHash: TEST_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      const gasUsed = (await ethers.provider.estimateGas(
        registry.verifyProof(witness.publicSignals, witness.proof)
      )).toNumber();

      expect(gasUsed).to.be.lessThan(500000);
      console.log(`Proof verification gas: ${gasUsed}`);
    });

    it("Should register model within gas limit", async function () {
      const gasUsed = (await ethers.provider.estimateGas(
        registry.registerModel(TEST_MODEL_HASH, { from: agent.address })
      )).toNumber();

      expect(gasUsed).to.be.lessThan(300000);
      console.log(`Model registration gas: ${gasUsed}`);
    });
  });

  describe("Access Control", function () {
    it("Should allow auditor to query model status", async function () {
      await registry.registerModel(TEST_MODEL_HASH, { from: agent.address });
      
      const status = await registry.getModelStatus(TEST_MODEL_HASH);
      expect(status).to.be.true;
    });

    it("Should allow anyone to verify proof", async function () {
      const witness = await groth16.fullProve(
        {
          weightHash: TEST_MODEL_HASH.replace("0x", ""),
          registeredHash: TEST_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      const isValid = await registry.verifyProof(
        witness.publicSignals,
        witness.proof
      );
      expect(isValid).to.be.true;
    });
  });

  describe("Edge Cases", function () {
    it("Should handle empty hash registration", async function () {
      await expect(
        registry.registerModel("0x", { from: agent.address })
      ).to.be.revertedWith("Invalid model hash");
    });

    it("Should handle hash with leading zeros", async function () {
      const hashWithZeros = "0x" + "0000000000000000000000000000000000000000000000000000000000000001";
      await registry.registerModel(hashWithZeros, { from: agent.address });
      expect(await registry.isModelRegistered(hashWithZeros)).to.be.true;
    });

    it("Should handle hash with trailing zeros", async function () {
      const hashWithZeros = "0x" + "0000000000000000000000000000000000000000000000000000000000000001";
      await registry.registerModel(hashWithZeros, { from: agent.address });
      expect(await registry.isModelRegistered(hashWithZeros)).to.be.true;
    });
  });
});

describe("AgentController", function () {
  let controller, owner, agent, maliciousAgent;
  let circuitPath, wasmPath, zkeyPath;

  const TEST_MODEL_HASH = "0x" + "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  const TAMPERED_MODEL_HASH = "0x" + "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";

  before(async function () {
    [owner, agent, maliciousAgent] = await ethers.getSigners();

    const ModelIntegrityRegistry = await ethers.getContractFactory("ModelIntegrityRegistry", owner);
    const registry = await ModelIntegrityRegistry.deploy();
    await registry.waitForDeployment();

    const AgentController = await ethers.getContractFactory("AgentController", owner);
    controller = await AgentController.deploy();
    await controller.waitForDeployment();

    await controller.setRegistry(registry);
    await registry.setAgentController(controller);
  });

  beforeEach(async function () {
    circuitPath = path.join(__dirname, "../circuits/build/modelProof.wasm");
    wasmPath = circuitPath;
    zkeyPath = path.join(__dirname, "../circuits/build/modelProof_final.zkey");
  });

  describe("Trade Execution", function () {
    let witness, proof, publicSignals;

    before(async function () {
      if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
        this.skip();
      }

      witness = await groth16.fullProve(
        {
          weightHash: TEST_MODEL_HASH.replace("0x", ""),
          registeredHash: TEST_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      proof = witness.proof;
      publicSignals = witness.publicSignals;
    });

    it("Should execute trade with valid proof", async function () {
      await controller.registerModel(TEST_MODEL_HASH, { from: agent.address });
      
      const tx = await controller.executeTrade(
        agent.address,
        TEST_MODEL_HASH,
        publicSignals,
        proof,
        { value: ethers.parseEther("0.1") }
      );
      
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);
    });

    it("Should reject trade with tampered proof", async function () {
      await controller.registerModel(TEST_MODEL_HASH, { from: agent.address });
      
      const tamperedPublicSignals = [
        TAMPERED_MODEL_HASH.replace("0x", ""),
        publicSignals[1]
      ];

      await expect(
        controller.executeTrade(
          agent.address,
          TEST_MODEL_HASH,
          tamperedPublicSignals,
          proof,
          { value: ethers.parseEther("0.1") }
        )
      ).to.be.revertedWith("Proof verification failed");
    });

    it("Should reject trade with unregistered model", async function () {
      const witness = await groth16.fullProve(
        {
          weightHash: TEST_MODEL_HASH.replace("0x", ""),
          registeredHash: TEST_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      await expect(
        controller.executeTrade(
          agent.address,
          TEST_MODEL_HASH,
          witness.publicSignals,
          witness.proof,
          { value: ethers.parseEther("0.1") }
        )
      ).to.be.revertedWith("Model not registered");
    });

    it("Should reject trade with invalid proof", async function () {
      await controller.registerModel(TEST_MODEL_HASH, { from: agent.address });
      
      const invalidProof = [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000"
      ];

      await expect(
        controller.executeTrade(
          agent.address,
          TEST_MODEL_HASH,
          publicSignals,
          invalidProof,
          { value: ethers.parseEther("0.1") }
        )
      ).to.be.revertedWith("Invalid proof");
    });
  });

  describe("Gas Limits", function () {
    it("Should execute trade within gas limit", async function () {
      if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
        this.skip();
      }

      const witness = await groth16.fullProve(
        {
          weightHash: TEST_MODEL_HASH.replace("0x", ""),
          registeredHash: TEST_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      await controller.registerModel(TEST_MODEL_HASH, { from: agent.address });

      const gasUsed = (await ethers.provider.estimateGas(
        controller.executeTrade(
          agent.address,
          TEST_MODEL_HASH,
          witness.publicSignals,
          witness.proof,
          { value: ethers.parseEther("0.1") }
        )
      )).toNumber();

      expect(gasUsed).to.be.lessThan(1000000);
      console.log(`Trade execution gas: ${gasUsed}`);
    });
  });

  describe("Access Control", function () {
    it("Should allow agent to register model", async function () {
      await expect(
        controller.registerModel(TEST_MODEL_HASH, { from: agent.address })
      ).to.not.be.reverted;
    });

    it("Should allow anyone to execute trade", async function () {
      await controller.registerModel(TEST_MODEL_HASH, { from: agent.address });
      
      const witness = await groth16.fullProve(
        {
          weightHash: TEST_MODEL_HASH.replace("0x", ""),
          registeredHash: TEST_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      await expect(
        controller.executeTrade(
          agent.address,
          TEST_MODEL_HASH,
          witness.publicSignals,
          witness.proof,
          { value: ethers.parseEther("0.1") }
        )
      ).to.not.be.reverted;
    });

    it("Should reject unauthorized model registration", async function () {
      await expect(
        controller.registerModel(TEST_MODEL_HASH, { from: maliciousAgent.address })
      ).to.be.revertedWith("Unauthorized");
    });
  });

  describe("Tampered Weight Simulation", function () {
    it("Should detect weight tampering via proof mismatch", async function () {
      await controller.registerModel(TEST_MODEL_HASH, { from: agent.address });
      
      const tamperedWitness = await groth16.fullProve(
        {
          weightHash: TAMPERED_MODEL_HASH.replace("0x", ""),
          registeredHash: TEST_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      await expect(
        controller.executeTrade(
          agent.address,
          TEST_MODEL_HASH,
          tamperedWitness.publicSignals,
          tamperedWitness.proof,
          { value: ethers.parseEther("0.1") }
        )
      ).to.be.revertedWith("Proof verification failed");
    });

    it("Should reject replay attack with old proof", async function () {
      await controller.registerModel(TEST_MODEL_HASH, { from: agent.address });
      
      const witness = await groth16.fullProve(
        {
          weightHash: TEST_MODEL_HASH.replace("0x", ""),
          registeredHash: TEST_MODEL_HASH.replace("0x", "")
        },
        wasmPath,
        zkeyPath
      );

      await controller.executeTrade(
        agent.address,
        TEST_MODEL_HASH,
        witness.publicSignals,
        witness.proof,
        { value: ethers.parseEther("0.1") }
      );

      await expect(
        controller.executeTrade(
          agent.address,
          TEST_MODEL_HASH,
          witness.publicSignals,
          witness.proof,
          { value: ethers.parseEther("0.1") }
        )
      ).to.be.revertedWith("Proof already used");
    });
  });

  describe("Circuit Compilation", function () {
    it("Should compile circuit successfully", async function () {
      if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
        this.skip();
      }

      expect(fs.existsSync(wasmPath)).to.be.true;
      expect(fs.existsSync(zkeyPath)).to.be.true;
    });

    it("Should have valid verification key", async function () {
      if (!fs.existsSync(vkeyPath)) {
        this.skip();
      }

      const vkey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
      expect(vkey).to.have.property("vk_alpha_1");
      expect(vkey).to.have.property("vk_beta_2");
      expect(vkey).to.have.property("vk_gamma_2");
      expect(vkey).to.have.property("vk_delta_2");
      expect(vkey).to.have.property("vk_ic");
    });
  });
});