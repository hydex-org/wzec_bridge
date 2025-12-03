#!/usr/bin/env ts-node

/**
 * Deployment script for wzec_bridge to Solana Devnet
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { WzecBridge } from "../target/types/wzec_bridge";
import * as fs from "fs";
import * as path from "path";

const CONFIG = {
  dkgResultPath: "../../bridge-custody/data/node1/node1_dkg_result.json",
  network: "devnet" as const,
};

interface DkgResult {
  node_id: number;
  group_verifying_key: number[];
  bridge_ua: string;
  full_viewing_key: string;
}

async function main() {
  console.log("\n========================================");
  console.log("  wZEC Bridge Devnet Deployment");
  console.log("========================================\n");

  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.WzecBridge as Program<WzecBridge>;

  console.log("Configuration:");
  console.log("- RPC:", provider.connection.rpcEndpoint);
  console.log("- Program ID:", program.programId.toString());
  console.log("- Wallet:", provider.wallet.publicKey.toString());

  const balance = await provider.connection.getBalance(provider.wallet.publicKey);
  console.log("- Wallet Balance:", balance / anchor.web3.LAMPORTS_PER_SOL, "SOL");

  if (balance < 0.5 * anchor.web3.LAMPORTS_PER_SOL) {
    console.error("\n[ERROR] Insufficient balance!");
    console.log("Run: solana airdrop 2 --url devnet");
    process.exit(1);
  }

  // Load DKG result
  console.log("\nLoading DKG result...");
  let dkgResult: DkgResult;
  try {
    const dkgPath = path.resolve(__dirname, CONFIG.dkgResultPath);
    console.log("- Path:", dkgPath);
    const dkgContent = fs.readFileSync(dkgPath, "utf-8");
    dkgResult = JSON.parse(dkgContent);
    console.log("- Bridge UA:", dkgResult.bridge_ua);
    console.log("- UFVK:", dkgResult.full_viewing_key.substring(0, 50) + "...");
  } catch (err) {
    console.error("\n[ERROR] Failed to load DKG result");
    console.error("Make sure bridge-custody DKG has been run first.");
    process.exit(1);
  }

  // Derive PDAs manually for logging
  const [bridgeConfigPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("bridge-config")],
    program.programId
  );

  const [arciumBalanceStatePda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("arcium-balance-state")],
    program.programId
  );

  console.log("\nDerived PDAs:");
  console.log("- Bridge Config:", bridgeConfigPda.toString());
  console.log("- Arcium Balance State:", arciumBalanceStatePda.toString());

  // Check if already initialized
  try {
    const existingConfig = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    console.log("\n[INFO] Bridge already initialized!");
    console.log("Existing configuration:");
    console.log("- Admin:", existingConfig.admin.toString());
    console.log("- Enclave Authority:", existingConfig.enclaveAuthority.toString());
    console.log("- Deposit Nonce:", existingConfig.depositNonce.toString());
    console.log("- Withdrawal Nonce:", existingConfig.withdrawalNonce.toString());

    saveDeployment({
      programId: program.programId.toString(),
      bridgeConfig: bridgeConfigPda.toString(),
      arciumBalanceState: arciumBalanceStatePda.toString(),
      admin: existingConfig.admin.toString(),
      enclaveAuthority: existingConfig.enclaveAuthority.toString(),
      bridgeUa: dkgResult.bridge_ua,
      network: CONFIG.network,
    });

    console.log("\n[OK] Deployment info saved to deployments/devnet.json");
    return;
  } catch (err) {
    console.log("\n[INFO] Bridge not yet initialized, proceeding...");
  }

  // Build configuration
  const admin = provider.wallet.publicKey;

  // Placeholder enclave authority - update after enclave is running
  const enclaveAuthority = anchor.web3.Keypair.generate().publicKey;
  console.log("\n[WARN] Using placeholder enclave authority!");
  console.log("       Update after enclave is running.");

  // MPC quorum pubkeys
  const mpcQuorumPubkeys: number[][] = [
    dkgResult.group_verifying_key,
    dkgResult.group_verifying_key,
    dkgResult.group_verifying_key,
  ];

  // Bridge UFVK as bytes
  const bridgeUfvk = Buffer.from(dkgResult.full_viewing_key, "utf-8");

  console.log("\nBridge Configuration:");
  console.log("- Admin:", admin.toString());
  console.log("- Enclave Authority:", enclaveAuthority.toString());
  console.log("- MPC Quorum Size:", mpcQuorumPubkeys.length);
  console.log("- UFVK Length:", bridgeUfvk.length, "bytes");

  console.log("\n[...] Initializing bridge...");

  try {
    const tx = await program.methods
      .initBridge(
        admin,
        enclaveAuthority,
        mpcQuorumPubkeys,
        bridgeUfvk
      )
      .accountsStrict({
        payer: provider.wallet.publicKey,
        bridgeConfig: bridgeConfigPda,
        arciumBalanceState: arciumBalanceStatePda,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .rpc({ commitment: "confirmed" });

    console.log("\n[OK] Bridge initialized successfully!");
    console.log("Transaction:", tx);
    console.log(`Explorer: https://explorer.solana.com/tx/${tx}?cluster=${CONFIG.network}`);

    // Verify
    const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    console.log("\nVerified Configuration:");
    console.log("- Admin:", config.admin.toString());
    console.log("- Enclave Authority:", config.enclaveAuthority.toString());
    console.log("- MPC Quorum:", config.mpcQuorumPubkeys.length, "keys");
    console.log("- Deposit Nonce:", config.depositNonce.toString());
    console.log("- Withdrawal Nonce:", config.withdrawalNonce.toString());

    const deployment = {
      programId: program.programId.toString(),
      bridgeConfig: bridgeConfigPda.toString(),
      arciumBalanceState: arciumBalanceStatePda.toString(),
      admin: admin.toString(),
      enclaveAuthority: enclaveAuthority.toString(),
      bridgeUa: dkgResult.bridge_ua,
      ufvk: dkgResult.full_viewing_key,
      deployedAt: new Date().toISOString(),
      transaction: tx,
      network: CONFIG.network,
    };

    saveDeployment(deployment);
    console.log("\n[OK] Deployment saved to deployments/devnet.json");

  } catch (error) {
    console.error("\n[ERROR] Deployment failed:");
    console.error(error);
    process.exit(1);
  }

  console.log("\n========================================");
  console.log("  Deployment Complete!");
  console.log("========================================");
  console.log("\nNext Steps:");
  console.log("1. Start enclave and get its pubkey");
  console.log("2. Update enclave_authority if needed");
  console.log("3. Start bridge-custody nodes");
  console.log("4. Test deposit flow");
}

function saveDeployment(data: any) {
  const dir = "./deployments";
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
  }
  fs.writeFileSync(
    `${dir}/devnet.json`,
    JSON.stringify(data, null, 2)
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });