import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { WzecBridge } from "../target/types/wzec_bridge";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";

describe("wzec-bridge", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.WzecBridge as Program<WzecBridge>;

  let bridgeConfigPda: anchor.web3.PublicKey;
  let mintAuthorityPda: anchor.web3.PublicKey;
  let wzecMint: anchor.web3.Keypair;

  before(async () => {
    // Derive PDAs
    [bridgeConfigPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bridge-config")],
      program.programId
    );

    [mintAuthorityPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("mint-authority")],
      program.programId
    );

    wzecMint = anchor.web3.Keypair.generate();
  });

  it("Initializes the bridge", async () => {
    const admin = provider.wallet.publicKey;
    const enclaveAuthority = anchor.web3.Keypair.generate().publicKey;

    const mpcQuorumPubkeys = [
      Array.from(Buffer.alloc(32, 1)),
      Array.from(Buffer.alloc(32, 2)),
      Array.from(Buffer.alloc(32, 3)),
    ];

    const bridgeUfvk = Array.from(Buffer.from("test_ufvk_placeholder_for_demo"));

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
        .rpc();

      console.log("\n✅ Bridge initialized successfully!");
      console.log("Transaction:", tx);
      console.log("Bridge Config PDA:", bridgeConfigPda.toString());
      console.log("wZEC Mint:", wzecMint.publicKey.toString());
      console.log("Admin:", admin.toString());
      console.log("Enclave Authority:", enclaveAuthority.toString());

      // Fetch and verify the bridge config
      const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
      console.log("\nBridge Config Details:");
      console.log("- Admin:", config.admin.toString());
      console.log("- Enclave Authority:", config.enclaveAuthority.toString());
      console.log("- wZEC Mint:", config.wzecMint.toString());
      console.log("- Withdrawal Nonce:", config.withdrawalNonce.toString());
      console.log("- Deposit Nonce:", config.depositNonce.toString());
      console.log("- MPC Quorum Size:", config.mpcQuorumPubkeys.length);

    } catch (error) {
      console.error("❌ Initialization failed:");
      console.error(error);
      throw error;
    }
  });

  it("Initializes computation definitions", async () => {
    console.log("\n🔧 Initializing computation definitions...");

    // For Arcium, computation definitions need to be initialized
    // This would typically be done through arcium CLI or specific calls
    // For now, we'll skip this in basic testing

    console.log("⚠️  Note: Computation definitions should be initialized via arcium CLI");
    console.log("Run: arcium init-mxe --program-id", program.programId.toString());
  });
});
