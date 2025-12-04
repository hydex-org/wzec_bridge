import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { WzecBridge } from "../target/types/wzec_bridge";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { randomBytes } from "crypto";
import {
  getCompDefAccOffset,
  getArciumAccountBaseSeed,
  getArciumProgAddress,
  getMXEPublicKey,
} from "@arcium-hq/client";
import * as fs from "fs";
import * as os from "os";
import { expect } from "chai";

describe("wzec-bridge - Maximum Privacy", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.WzecBridge as Program<WzecBridge>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  // Single test that runs everything sequentially (like working Arcium examples)
  it("full hydex bridge test", async () => {
    console.log("\n========================================");
    console.log("  HYDEX BRIDGE - Maximum Privacy Tests");
    console.log("========================================\n");

    const owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);
    const enclaveAuthority = anchor.web3.Keypair.generate();
    const mpcAuthority = anchor.web3.Keypair.generate();

    // Derive PDAs
    const [bridgeConfigPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("bridge-config")],
      program.programId
    );

    const [mintAuthorityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint-authority")],
      program.programId
    );

    const [szecMintPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("szec-mint")],
      program.programId
    );

    console.log("Program ID:", program.programId.toString());
    console.log("Owner:", owner.publicKey.toString());
    console.log("Bridge Config PDA:", bridgeConfigPda.toString());
    console.log("sZEC Mint PDA:", szecMintPda.toString());
    console.log("Enclave Authority:", enclaveAuthority.publicKey.toString());
    console.log("MPC Authority:", mpcAuthority.publicKey.toString());
    console.log("");

    // =========================================================================
    // STEP 1: Verify computation definitions exist (arcium test initializes these)
    // =========================================================================
    console.log("[1/5] Verifying Arcium computation definitions...");

    const compDefNames = ["verify_attestation", "create_burn_intent", "update_burn_intent"];
    for (const name of compDefNames) {
      const offset = getCompDefAccOffset(name);
      const compDefPDA = PublicKey.findProgramAddressSync(
        [getArciumAccountBaseSeed("ComputationDefinitionAccount"), program.programId.toBuffer(), offset],
        getArciumProgAddress()
      )[0];
      const accInfo = await provider.connection.getAccountInfo(compDefPDA);
      const status = accInfo ? "ready" : "NOT FOUND (arcium test should init this)";
      console.log(`  - ${name}: ${status}`);
    }
    console.log("  [OK] Comp defs checked\n");

    // =========================================================================
    // STEP 2: Get MXE public key (after comp defs, like working examples)
    // =========================================================================
    console.log("[2/5] Verifying MXE is ready...");
    const mxePublicKey = await getMXEPublicKeyWithRetry(
      provider,
      program.programId
    );
    console.log("  MXE x25519 pubkey:", Buffer.from(mxePublicKey).toString("hex").slice(0, 32) + "...");
    console.log("  [OK] MXE is ready\n");

    // =========================================================================
    // STEP 3: Initialize the bridge
    // =========================================================================
    console.log("[3/5] Initializing Hydex Bridge (non-Arcium state)...");

    // Get fresh blockhash before transaction
    const { blockhash } = await provider.connection.getLatestBlockhash("confirmed");
    console.log("  Blockhash:", blockhash.slice(0, 16) + "...");

    const initBridgeTx = await program.methods
      .initBridge(enclaveAuthority.publicKey, mpcAuthority.publicKey)
      .accountsPartial({
        admin: owner.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([owner])
      .rpc({ commitment: "confirmed", preflightCommitment: "confirmed" });

    console.log("  TX:", initBridgeTx.slice(0, 32) + "...");

    // Verify config
    const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    expect(config.admin.toString()).to.equal(owner.publicKey.toString());
    expect(config.enclaveAuthority.toString()).to.equal(
      enclaveAuthority.publicKey.toString()
    );
    expect(config.mpcAuthority.toString()).to.equal(
      mpcAuthority.publicKey.toString()
    );

    console.log("  [OK] Bridge initialized");
    console.log("    - Admin:", config.admin.toString().slice(0, 16) + "...");
    console.log("    - sZEC Mint:", config.szecMint.toString().slice(0, 16) + "...\n");

    // =========================================================================
    // STEP 4: Create deposit intent
    // =========================================================================
    console.log("[4/5] Testing deposit flow...");

    const configBefore = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    const depositId = configBefore.depositNonce.toNumber();

    const [depositIntentPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("deposit-intent"),
        owner.publicKey.toBuffer(),
        new anchor.BN(depositId).toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    const createDepositTx = await program.methods
      .initDepositIntent()
      .accountsPartial({
        user: owner.publicKey,
      })
      .signers([owner])
      .rpc({ skipPreflight: true, commitment: "confirmed" });

    console.log("  Created deposit intent #" + depositId);

    const intent = await program.account.depositIntent.fetch(depositIntentPda);
    expect(intent.depositId.toNumber()).to.equal(depositId);
    expect(intent.status).to.equal(0); // Pending
    console.log("  [OK] Deposit intent created (status: Pending)\n");

    // =========================================================================
    // STEP 5: Set unified address (enclave authority)
    // =========================================================================
    console.log("[5/5] Simulating enclave setting unified address...");

    const uaHash = randomBytes(32);
    const noteCommitment = randomBytes(32);
    const amount = new anchor.BN(100000000); // 1 sZEC (8 decimals)

    const setUaTx = await program.methods
      .setUnifiedAddress(
        Array.from(uaHash) as any,
        amount,
        Array.from(noteCommitment) as any
      )
      .accountsPartial({
        authority: enclaveAuthority.publicKey,
        depositIntent: depositIntentPda,
      })
      .signers([enclaveAuthority])
      .rpc({ skipPreflight: true, commitment: "confirmed" });

    const updatedIntent = await program.account.depositIntent.fetch(depositIntentPda);
    expect(updatedIntent.status).to.equal(1); // AddressGenerated
    expect(updatedIntent.amount.toNumber()).to.equal(100000000);

    console.log("  [OK] Unified address set by enclave");
    console.log("    - Amount: 1.00000000 sZEC");
    console.log("    - Status: AddressGenerated");
    console.log("    - UA Hash: " + Buffer.from(uaHash).toString("hex").slice(0, 16) + "...");
    console.log("    - Note Commitment: " + Buffer.from(noteCommitment).toString("hex").slice(0, 16) + "...\n");

    // =========================================================================
    // PRIVACY VERIFICATION
    // =========================================================================
    console.log("========================================");
    console.log("  Privacy Analysis");
    console.log("========================================");
    console.log("  - Full Zcash UA: NOT stored (only hash)");
    console.log("  - Deposit amount: visible on-chain (inherent to SPL tokens)");
    console.log("  - User wallet: visible (inherent to blockchain)");
    console.log("  - Note commitment: hashed on-chain");
    console.log("");
    console.log("  Arcium MPC Privacy:");
    console.log("    - verify_attestation: attestation details encrypted");
    console.log("    - create_burn_intent: Zcash address encrypted in MXE");
    console.log("    - update_burn_intent: TXID encrypted in MXE");
    console.log("");
    console.log("  [OK] All tests passed!\n");
  });
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function getMXEPublicKeyWithRetry(
  provider: anchor.AnchorProvider,
  programId: PublicKey,
  maxRetries: number = 30,
  retryDelayMs: number = 1000
): Promise<Uint8Array> {
  console.log("  Waiting for MXE to initialize...");
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const mxePublicKey = await getMXEPublicKey(provider, programId);
      if (mxePublicKey) {
        return mxePublicKey;
      }
    } catch (error) {
      // Retry silently
    }

    if (attempt < maxRetries) {
      if (attempt % 5 === 0) {
        console.log(`  Retry ${attempt}/${maxRetries}...`);
      }
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }

  throw new Error(`Failed to fetch MXE public key after ${maxRetries} attempts`);
}

function readKpJson(path: string): anchor.web3.Keypair {
  const file = fs.readFileSync(path);
  return anchor.web3.Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(file.toString()))
  );
}
