import * as anchor from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Connection, Keypair } from "@solana/web3.js";
import * as fs from "fs";
import * as crypto from "crypto";

/**
 * Setup a deposit intent for a user so the MPC can mint when ZEC is received.
 * 
 * This creates the on-chain state needed for mint_simple to work:
 * 1. Creates deposit intent (status = 0)
 * 2. Sets unified address (status = 1)
 * 
 * After running this, send ZEC to the deposit address and the enclave/MPC will mint.
 */
async function main() {
    // Setup connection and wallet (MPC wallet = both enclave and MPC authority)
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");
    const walletPath = "/Users/fb/testing/bridge-custody/data/node1/solana-keypair.json";
    const secretKey = JSON.parse(fs.readFileSync(walletPath, "utf8"));
    const payer = Keypair.fromSecretKey(Uint8Array.from(secretKey));
    const wallet = new anchor.Wallet(payer);
    const provider = new anchor.AnchorProvider(connection, wallet, { commitment: "confirmed" });
    anchor.setProvider(provider);

    const programId = new PublicKey("B12pxSGTH8bt8LtVcdbEXf2CPpf2sFJuj7SctsFuvcQc");
    const idl = JSON.parse(fs.readFileSync("./target/idl/wzec_bridge.json", "utf8"));
    idl.address = programId.toBase58();
    const program = new anchor.Program(idl as anchor.Idl, provider);

    // The user who will receive sZEC (from frontend wallet)
    // This should match the solana_pubkey in address_mappings.json
    const userPubkey = new PublicKey("7KBxEDRnuUU51KqvV9czkoZrhGZKoXvas8CxQPJjj9Vz");

    console.log("=== Setting up deposit for user ===");
    console.log("User Solana wallet:", userPubkey.toBase58());
    console.log("MPC Authority:", payer.publicKey.toBase58());

    // Derive PDAs
    const [bridgeConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("bridge-config")],
        programId
    );

    // Check bridge state
    let config: any;
    try {
        config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
        console.log("\nBridge config:");
        console.log("  Enclave Authority:", config.enclaveAuthority.toBase58());
        console.log("  MPC Authority:", config.mpcAuthority.toBase58());
        console.log("  Deposit Nonce:", config.depositNonce.toString());
    } catch (e) {
        console.error("Bridge not initialized! Run test-mint.ts first.");
        return;
    }

    const depositId = config.depositNonce.toNumber();
    const [depositIntent] = PublicKey.findProgramAddressSync(
        [
            Buffer.from("deposit-intent"),
            userPubkey.toBuffer(),
            new anchor.BN(depositId).toArrayLike(Buffer, "le", 8)
        ],
        programId
    );

    console.log("\nDeposit Intent PDA:", depositIntent.toBase58());
    console.log("Deposit ID:", depositId);

    // Step 1: Create deposit intent for the USER (not payer)
    // Note: The user needs to sign this, but for testing we can use a different approach
    // We'll create an intent where the MPC is the "user" but tokens go to the real user
    // Actually, let's create it properly - the user field will be set to userPubkey

    // Check if deposit intent already exists
    let intentExists = false;
    let intentStatus = -1;
    try {
        const existingIntent = await (program.account as any).depositIntent.fetch(depositIntent);
        intentExists = true;
        intentStatus = existingIntent.status;
        console.log("\nDeposit intent already exists!");
        console.log("  Status:", intentStatus);
        console.log("  User:", existingIntent.user.toBase58());
    } catch (e) {
        console.log("\nDeposit intent does not exist, creating...");
    }

    if (!intentExists) {
        // For this to work, we need to create the intent as the USER
        // But we don't have the user's keypair
        // 
        // WORKAROUND: Create the intent using MPC wallet as user
        // Then the mint will go to MPC wallet (for testing)
        // 
        // For production, the frontend should call initDepositIntent with user's wallet
        console.log("\nCreating deposit intent (MPC as user for testing)...");

        const [depositIntentMpc] = PublicKey.findProgramAddressSync(
            [
                Buffer.from("deposit-intent"),
                payer.publicKey.toBuffer(),
                new anchor.BN(depositId).toArrayLike(Buffer, "le", 8)
            ],
            programId
        );

        try {
            const tx = await (program.methods as any)
                .initDepositIntent()
                .accounts({
                    user: payer.publicKey,
                    bridgeConfig,
                    depositIntent: depositIntentMpc,
                    systemProgram: SystemProgram.programId,
                })
                .rpc({ skipPreflight: true });
            console.log("  TX:", tx);
            console.log("  Created deposit intent for MPC wallet");

            // Now set unified address
            console.log("\nSetting unified address...");
            const noteCommitment = crypto.randomBytes(32);
            const uaHash = crypto.randomBytes(32);
            const amount = new anchor.BN(0); // Will be set by mint

            const tx2 = await (program.methods as any)
                .setUnifiedAddress(
                    Array.from(uaHash),
                    amount,
                    Array.from(noteCommitment)
                )
                .accounts({
                    authority: payer.publicKey,
                    bridgeConfig,
                    depositIntent: depositIntentMpc,
                })
                .rpc({ skipPreflight: true });
            console.log("  TX:", tx2);
            console.log("  Status set to 1 (AddressGenerated)");

            console.log("\n=== READY FOR DEPOSIT ===");
            console.log("Send ZEC to your deposit address.");
            console.log("Enclave will detect it and MPC will mint sZEC to:", payer.publicKey.toBase58());

        } catch (e: any) {
            console.log("Error:", e.message);
            if (e.logs) e.logs.forEach((l: string) => console.log("  ", l));
        }
    } else if (intentStatus === 0) {
        // Intent exists but needs unified address set
        console.log("\nSetting unified address for existing intent...");
        const noteCommitment = crypto.randomBytes(32);
        const uaHash = crypto.randomBytes(32);
        const amount = new anchor.BN(0);

        try {
            const tx = await (program.methods as any)
                .setUnifiedAddress(
                    Array.from(uaHash),
                    amount,
                    Array.from(noteCommitment)
                )
                .accounts({
                    authority: payer.publicKey,
                    bridgeConfig,
                    depositIntent,
                })
                .rpc({ skipPreflight: true });
            console.log("  TX:", tx);
            console.log("  Status set to 1 (AddressGenerated)");
        } catch (e: any) {
            console.log("Error:", e.message);
        }
    } else if (intentStatus === 1) {
        console.log("\n=== ALREADY READY ===");
        console.log("Deposit intent exists with status = 1");
        console.log("Send ZEC to your deposit address and the MPC will mint!");
    } else if (intentStatus === 3) {
        console.log("\n=== ALREADY MINTED ===");
        console.log("This deposit was already minted. Create a new one.");
    }
}

main().catch(console.error);

