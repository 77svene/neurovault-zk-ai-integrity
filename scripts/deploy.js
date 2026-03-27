const hre = require("hardhat");

async function main() {
  console.log("=== NeuroVault: ModelIntegrityRegistry Deployment ===\n");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const ModelIntegrityRegistry = await hre.ethers.getContractFactory("ModelIntegrityRegistry");
  const registry = await ModelIntegrityRegistry.deploy();
  await registry.waitForDeployment();

  const registryAddress = await registry.getAddress();
  console.log("ModelIntegrityRegistry deployed to:", registryAddress);

  // Initialize roles
  const MODEL_ADMIN_ROLE = await registry.MODEL_ADMIN_ROLE();
  const VERIFIER_ROLE = await registry.VERIFIER_ROLE();
  const EMERGENCY_ROLE = await registry.EMERGENCY_ROLE();

  // Grant admin role to deployer
  await registry.grantRole(MODEL_ADMIN_ROLE, deployer.address);
  console.log("Granted MODEL_ADMIN_ROLE to:", deployer.address);

  // Grant emergency role to deployer
  await registry.grantRole(EMERGENCY_ROLE, deployer.address);
  console.log("Granted EMERGENCY_ROLE to:", deployer.address);

  // Set deployer as owner
  await registry.transferOwnership(deployer.address);
  console.log("Set owner to:", deployer.address);

  console.log("\n=== Deployment Complete ===");
  console.log("Contract Address:", registryAddress);
  console.log("Owner:", deployer.address);
  console.log("MODEL_ADMIN_ROLE:", deployer.address);
  console.log("EMERGENCY_ROLE:", deployer.address);

  // Save deployment info
  const fs = require("fs");
  const deploymentInfo = {
    network: hre.network.name,
    contract: "ModelIntegrityRegistry",
    address: registryAddress,
    owner: deployer.address,
    timestamp: new Date().toISOString(),
    chainId: (await hre.ethers.provider.getNetwork()).chainId
  };

  fs.writeFileSync("deployment-info.json", JSON.stringify(deploymentInfo, null, 2));
  console.log("\nDeployment info saved to deployment-info.json");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });