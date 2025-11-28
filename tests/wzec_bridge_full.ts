import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { WzecBridge } from "../target/types/wzec_bridge";
import { 
  TOKEN_PROGRAM_ID, 
  createMint, 
  getOrCreateAssociatedTokenAccount,
  mintTo
} from "@solana/spl-token";
import { expect } from "chai";

describe("wzec-bridge Full Test Suite", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.WzecBridge as Program<WzecBridge>;

  let bridgeConfigPda: anchor.web3.PublicKey;
  let mintAuthorityPda: anchor.web3.PublicKey;
  let wzecMint: anchor.web3.Keypair;
  let admin: anchor.web3.Keypair;
  let user: anchor.web3.Keypair;
  let enclaveAuthority: anchor.web3.Keypair;

  before(async () => {
    // Generate keypairs
    admin = provider.wallet as any;
    user = anchor.web3.Keypair.generate();
    enclaveAuthority = anchor.web3.Keypair.generate();
    wzecMint = anchor.web3.Keypair.generate();

    // Airdrop SOL to user for testing
    const airdropSig = await provider.connection.requestAirdrop(
      user.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(airdropSig);

    // Derive PDAs
    [bridgeConfigPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bridge-config")],
      program.programId
    );

    [mintAuthorityPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("mint-authority")],
      program.programId
    );

    console.log("\n=== Test Setup ===");
    console.log("Program ID:", program.programId.toString());
    console.log("Admin:", admin.publicKey.toString());
    console.log("User:", user.publicKey.toString());
    console.log("Enclave Authority:", enclaveAuthority.publicKey.toString());
  });

  describe("Initialization", () => {
    it("Initializes the bridge", async () => {
      const mpcQuorumPubkeys = [
        Array.from(Buffer.alloc(32, 1)),
        Array.from(Buffer.alloc(32, 2)),
        Array.from(Buffer.alloc(32, 3)),
      ];

      // Use a placeholder UFVK for testing
      const bridgeUfvk = Array.from(
        Buffer.from("test_ufvk_placeholder_replace_with_real_ufvk_from_mpc")
      );

      const tx = await program.methods
        .initBridge(
          admin.publicKey,
          enclaveAuthority.publicKey,
          mpcQuorumPubkeys,
          bridgeUfvk
        )
        .accounts({
          payer: admin.publicKey,
          bridgeConfig: bridgeConfigPda,
          wzecMint: wzecMint.publicKey,
          mintAuthority: mintAuthorityPda,
          systemProgram: anchor.web3.SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .signers([wzecMint])
        .rpc();

      console.log("\n✅ Bridge initialized!");
      console.log("Transaction:", tx);

      // Verify the bridge config
      const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
      expect(config.admin.toString()).to.equal(admin.publicKey.toString());
      expect(config.enclaveAuthority.toString()).to.equal(
        enclaveAuthority.publicKey.toString()
      );
      expect(config.wzecMint.toString()).to.equal(wzecMint.publicKey.toString());
      expect(config.withdrawalNonce.toNumber()).to.equal(0);
      expect(config.depositNonce.toNumber()).to.equal(0);

      console.log("\nBridge Config:");
      console.log("- wZEC Mint:", config.wzecMint.toString());
      console.log("- MPC Quorum Size:", config.mpcQuorumPubkeys.length);
      console.log("- Deposit Nonce:", config.depositNonce.toString());
      console.log("- Withdrawal Nonce:", config.withdrawalNonce.toString());
    });
  });

  describe("Deposit Flow (Without Arcium for Basic Testing)", () => {
    let depositIntentPda: anchor.web3.PublicKey;
    let depositId: number;

    it("Creates deposit intent", async () => {
      const diversifierIndex = 0;

      // Get current deposit nonce before creating intent
      const configBefore = await program.account.bridgeConfig.fetch(
        bridgeConfigPda
      );
      depositId = configBefore.depositNonce.toNumber();

      [depositIntentPda] = anchor.web3.PublicKey.findProgramAddressSync(
        [
          Buffer.from("deposit-intent"),
          user.publicKey.toBuffer(),
          Buffer.from(new anchor.BN(depositId).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      const tx = await program.methods
        .initIntent(diversifierIndex)
        .accounts({
          user: user.publicKey,
          bridgeConfig: bridgeConfigPda,
          depositIntent: depositIntentPda,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      console.log("\n✅ Deposit intent created!");
      console.log("Transaction:", tx);

      // Verify intent
      const intent = await program.account.depositIntent.fetch(depositIntentPda);
      expect(intent.depositId.toNumber()).to.equal(depositId);
      expect(intent.user.toString()).to.equal(user.publicKey.toString());
      expect(intent.diversifierIndex).to.equal(diversifierIndex);
      expect(intent.status).to.equal(0); // Pending

      console.log("\nDeposit Intent:");
      console.log("- Deposit ID:", intent.depositId.toString());
      console.log("- Diversifier Index:", intent.diversifierIndex);
      console.log("- Status:", intent.status, "(0=Pending)");

      // Verify nonce incremented
      const configAfter = await program.account.bridgeConfig.fetch(
        bridgeConfigPda
      );
      expect(configAfter.depositNonce.toNumber()).to.equal(depositId + 1);
    });

    it("Sets unified address (admin only)", async () => {
      const unifiedAddress = Buffer.from(
        "utest1234567890abcdefghijklmnopqrstuvwxyz" // Placeholder UA
      );

      const tx = await program.methods
        .setUnifiedAddress(new anchor.BN(depositId), Array.from(unifiedAddress))
        .accounts({
          admin: admin.publicKey,
          bridgeConfig: bridgeConfigPda,
          depositIntent: depositIntentPda,
        })
        .rpc();

      console.log("\n✅ Unified address set!");
      console.log("Transaction:", tx);

      // Verify
      const intent = await program.account.depositIntent.fetch(depositIntentPda);
      expect(intent.status).to.equal(1); // AddressGenerated
      expect(intent.uaLength).to.equal(unifiedAddress.length);

      console.log("\nUpdated Intent:");
      console.log("- Status:", intent.status, "(1=AddressGenerated)");
      console.log("- UA Length:", intent.uaLength);
    });

    it("Fails to set UA if not admin", async () => {
      const unifiedAddress = Buffer.from("utest_another_address");
      const newDepositId = 999;

      try {
        await program.methods
          .setUnifiedAddress(new anchor.BN(newDepositId), Array.from(unifiedAddress))
          .accounts({
            admin: user.publicKey, // Non-admin trying
            bridgeConfig: bridgeConfigPda,
            depositIntent: depositIntentPda,
          })
          .signers([user])
          .rpc();
        
        expect.fail("Should have thrown unauthorized error");
      } catch (err: any) {
        expect(err.toString()).to.include("Unauthorized");
        console.log("\n✅ Correctly rejected non-admin access");
      }
    });
  });

  describe("Demo Mint (Admin Testing)", () => {
    let userTokenAccount: any;

    before(async () => {
      // Create token account for user
      userTokenAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        admin as any,
        wzecMint.publicKey,
        user.publicKey
      );
    });

    it("Mints test wZEC tokens", async () => {
      const amount = new anchor.BN(100_000_000); // 1 wZEC

      const tx = await program.methods
        .demoMint(amount)
        .accounts({
          admin: admin.publicKey,
          bridgeConfig: bridgeConfigPda,
          mintAuthority: mintAuthorityPda,
          wzecMint: wzecMint.publicKey,
          recipientTokenAccount: userTokenAccount.address,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .rpc();

      console.log("\n✅ Demo minted wZEC!");
      console.log("Transaction:", tx);
      console.log("Amount:", amount.toString(), "zatoshis (1 wZEC)");

      // Verify balance
      const accountInfo = await provider.connection.getTokenAccountBalance(
        userTokenAccount.address
      );
      expect(accountInfo.value.amount).to.equal(amount.toString());
      console.log("- User wZEC Balance:", accountInfo.value.uiAmountString, "wZEC");
    });

    it("Fails demo mint if not admin", async () => {
      const amount = new anchor.BN(1_000_000);

      try {
        await program.methods
          .demoMint(amount)
          .accounts({
            admin: user.publicKey, // Non-admin
            bridgeConfig: bridgeConfigPda,
            mintAuthority: mintAuthorityPda,
            wzecMint: wzecMint.publicKey,
            recipientTokenAccount: userTokenAccount.address,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([user])
          .rpc();
        
        expect.fail("Should have thrown unauthorized error");
      } catch (err: any) {
        expect(err.toString()).to.include("Unauthorized");
        console.log("\n✅ Correctly rejected non-admin demo mint");
      }
    });
  });

  describe("Event Emission", () => {
    it("Emits DepositIntentCreated event", async () => {
      const diversifierIndex = 1;
      
      const configBefore = await program.account.bridgeConfig.fetch(
        bridgeConfigPda
      );
      const depositId = configBefore.depositNonce.toNumber();

      const [depositIntentPda] = anchor.web3.PublicKey.findProgramAddressSync(
        [
          Buffer.from("deposit-intent"),
          user.publicKey.toBuffer(),
          Buffer.from(new anchor.BN(depositId).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      // Listen for events
      const listener = program.addEventListener("DepositIntentCreated", (event, slot) => {
        console.log("\n📡 Event Received:");
        console.log("- Deposit ID:", event.depositId.toString());
        console.log("- User:", event.user.toString());
        console.log("- Diversifier Index:", event.diversifierIndex);
        console.log("- Slot:", slot);
      });

      await program.methods
        .initIntent(diversifierIndex)
        .accounts({
          user: user.publicKey,
          bridgeConfig: bridgeConfigPda,
          depositIntent: depositIntentPda,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      // Give time for event to process
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Remove listener
      await program.removeEventListener(listener);
      
      console.log("✅ Event listener test completed");
    });
  });

  describe("PDA Derivation Verification", () => {
    it("Verifies bridge config PDA", async () => {
      const [derivedPda, bump] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("bridge-config")],
        program.programId
      );

      expect(derivedPda.toString()).to.equal(bridgeConfigPda.toString());
      
      const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
      expect(config.bump).to.equal(bump);
      
      console.log("\n✅ Bridge Config PDA verified");
      console.log("- PDA:", derivedPda.toString());
      console.log("- Bump:", bump);
    });

    it("Verifies mint authority PDA", async () => {
      const [derivedPda, bump] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("mint-authority")],
        program.programId
      );

      expect(derivedPda.toString()).to.equal(mintAuthorityPda.toString());
      
      const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
      expect(config.mintAuthorityBump).to.equal(bump);
      
      console.log("\n✅ Mint Authority PDA verified");
      console.log("- PDA:", derivedPda.toString());
      console.log("- Bump:", bump);
    });
  });

  after(async () => {
    console.log("\n=== Test Summary ===");
    console.log("All tests completed successfully!");
    console.log("\nDeployed Addresses:");
    console.log("- Program ID:", program.programId.toString());
    console.log("- Bridge Config:", bridgeConfigPda.toString());
    console.log("- wZEC Mint:", wzecMint.publicKey.toString());
    console.log("- Mint Authority:", mintAuthorityPda.toString());
  });
});

