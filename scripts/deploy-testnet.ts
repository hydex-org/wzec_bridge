#!/usr/bin/env ts-node

/**
 * Deployment script for wzec_bridge to Solana Testnet
 * 
 * Prerequisites:
 * 1. Built program: anchor build
 * 2. Solana CLI configured for testnet: solana config set --url testnet
 * 3. Wallet with SOL: solana airdrop 2 (may need to run multiple times)
 * 4. Environment variables set in .env
 * 
 * Usage:
 *   ts-node scripts/deploy-testnet.ts
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { WzecBridge } from "../target/types/wzec_bridge";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import * as fs from "fs";
import * as dotenv from "dotenv";

// Load environment variables
dotenv.config();

async function main() {
  console.log("\n========================================");
  console.log("  wZEC Bridge Testnet Deployment");
  console.log("========================================\n");

  // Configure provider
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.WzecBridge as Program<WzecBridge>;
  
  console.log("Configuration:");
  console.log("- RPC:", provider.connection.rpcEndpoint);
  console.log("- Program ID:", program.programId.toString());
  console.log("- Wallet:", provider.wallet.publicKey.toString());
  
  // Check wallet balance
  const balance = await provider.connection.getBalance(provider.wallet.publicKey);
  console.log("- Wallet Balance:", balance / anchor.web3.LAMPORTS_PER_SOL, "SOL");
  
  if (balance < 0.5 * anchor.web3.LAMPORTS_PER_SOL) {
    console.error("\n❌ Insufficient balance! Need at least 0.5 SOL");
    console.log("Run: solana airdrop 2");
    process.exit(1);
  }

  // Derive PDAs
  const [bridgeConfigPda, bridgeConfigBump] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("bridge-config")],
    program.programId
  );

  const [mintAuthorityPda, mintAuthorityBump] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("mint-authority")],
    program.programId
  );

  console.log("\nDerived PDAs:");
  console.log("- Bridge Config:", bridgeConfigPda.toString(), `(bump: ${bridgeConfigBump})`);
  console.log("- Mint Authority:", mintAuthorityPda.toString(), `(bump: ${mintAuthorityBump})`);

  // Check if already initialized
  try {
    const existingConfig = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    console.log("\n⚠️  Bridge already initialized!");
    console.log("Existing configuration:");
    console.log("- Admin:", existingConfig.admin.toString());
    console.log("- wZEC Mint:", existingConfig.wzecMint.toString());
    console.log("- Enclave Authority:", existingConfig.enclaveAuthority.toString());
    console.log("- Deposit Nonce:", existingConfig.depositNonce.toString());
    console.log("- Withdrawal Nonce:", existingConfig.withdrawalNonce.toString());
    
    // Save addresses
    saveDeployment({
      programId: program.programId.toString(),
      bridgeConfig: bridgeConfigPda.toString(),
      wzecMint: existingConfig.wzecMint.toString(),
      mintAuthority: mintAuthorityPda.toString(),
      admin: existingConfig.admin.toString(),
      enclaveAuthority: existingConfig.enclaveAuthority.toString(),
    });
    
    console.log("\n✅ Deployment info saved to deployments/testnet.json");
    return;
  } catch (err) {
    console.log("\n✓ Bridge not yet initialized, proceeding with deployment...");
  }

  // Generate wZEC mint keypair
  const wzecMint = anchor.web3.Keypair.generate();
  console.log("\nGenerated Mint:");
  console.log("- wZEC Mint:", wzecMint.publicKey.toString());

  // Get configuration from environment or use defaults
  const admin = provider.wallet.publicKey;
  
  // IMPORTANT: Replace these with real values from your bridge-custody setup
  const enclaveAuthority = process.env.ENCLAVE_AUTHORITY_PUBKEY 
    ? new anchor.web3.PublicKey(process.env.ENCLAVE_AUTHORITY_PUBKEY)
    : anchor.web3.Keypair.generate().publicKey; // Temp for testing

  const mpcQuorumPubkeys = [
    hexToArray(process.env.MPC_NODE_1_PUBKEY || "01".repeat(32)),
    hexToArray(process.env.MPC_NODE_2_PUBKEY || "02".repeat(32)),
    hexToArray(process.env.MPC_NODE_3_PUBKEY || "03".repeat(32)),
  ];

  // CRITICAL: Use real UFVK from bridge-custody
  const bridgeUfvk = process.env.BRIDGE_UFVK
    ? Array.from(Buffer.from(process.env.BRIDGE_UFVK))
    : Array.from(Buffer.from("PLACEHOLDER_UFVK_REPLACE_WITH_REAL_FROM_MPC_NODES"));

  console.log("\nBridge Configuration:");
  console.log("- Admin:", admin.toString());
  console.log("- Enclave Authority:", enclaveAuthority.toString());
  console.log("- MPC Quorum Size:", mpcQuorumPubkeys.length);
  console.log("- UFVK Length:", bridgeUfvk.length, "bytes");
  
  if (bridgeUfvk.length < 90) {
    console.warn("\n⚠️  Warning: UFVK seems to be placeholder. Update BRIDGE_UFVK in .env");
  }

  // Deploy
  console.log("\n🚀 Initializing bridge...");
  
  try {
    const tx = await program.methods
      .initBridge(admin, enclaveAuthority, mpcQuorumPubkeys, bridgeUfvk)
      .accounts({
        payer: provider.wallet.publicKey,
        bridgeConfig: bridgeConfigPda,
        wzecMint: wzecMint.publicKey,
        mintAuthority: mintAuthorityPda,
        systemProgram: anchor.web3.SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .signers([wzecMint])
      .rpc({ commitment: "confirmed" });

    console.log("\n✅ Bridge initialized successfully!");
    console.log("Transaction:", tx);
    console.log(`Explorer: https://explorer.solana.com/tx/${tx}?cluster=testnet`);

    // Verify
    const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    console.log("\nVerified Configuration:");
    console.log("- Admin:", config.admin.toString());
    console.log("- wZEC Mint:", config.wzecMint.toString());
    console.log("- Enclave Authority:", config.enclaveAuthority.toString());
    console.log("- MPC Quorum:", config.mpcQuorumPubkeys.length, "keys");
    console.log("- Deposit Nonce:", config.depositNonce.toString());
    console.log("- Withdrawal Nonce:", config.withdrawalNonce.toString());

    // Save deployment info
    const deployment = {
      programId: program.programId.toString(),
      bridgeConfig: bridgeConfigPda.toString(),
      wzecMint: wzecMint.publicKey.toString(),
      mintAuthority: mintAuthorityPda.toString(),
      admin: admin.toString(),
      enclaveAuthority: enclaveAuthority.toString(),
      deployedAt: new Date().toISOString(),
      transaction: tx,
      network: "testnet",
    };

    saveDeployment(deployment);

    console.log("\n📝 Deployment saved to deployments/testnet.json");
    console.log("\n========================================");
    console.log("  Deployment Complete!");
    console.log("========================================");
    console.log("\nNext Steps:");
    console.log("1. Update frontend with these addresses");
    console.log("2. Configure bridge-custody to use this program");
    console.log("3. Initialize Arcium computation definitions");
    console.log("4. Test deposit flow with test tokens");
    
  } catch (error) {
    console.error("\n❌ Deployment failed:");
    console.error(error);
    process.exit(1);
  }
}

function hexToArray(hex: string): number[] {
  const cleaned = hex.replace(/^0x/, "");
  const bytes = [];
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes.push(parseInt(cleaned.substr(i, 2), 16));
  }
  // Pad to 32 bytes if needed
  while (bytes.length < 32) {
    bytes.push(0);
  }
  return bytes.slice(0, 32);
}

function saveDeployment(data: any) {
  const dir = "./deployments";
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
  }
  
  fs.writeFileSync(
    `${dir}/testnet.json`,
    JSON.stringify(data, null, 2)
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

