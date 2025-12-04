/**
 * Test script for burn_for_withdrawal instruction
 * 
 * This tests the withdrawal flow by:
 * 1. Checking user's sZEC balance
 * 2. Creating a burn intent
 * 3. Verifying the BurnIntent PDA was created
 */

import * as anchor from "@coral-xyz/anchor";
import { Connection, PublicKey, Keypair } from "@solana/web3.js";
import { getAssociatedTokenAddress, getAccount } from "@solana/spl-token";
import * as fs from "fs";
import * as crypto from "crypto";

// Load IDL
const idl = JSON.parse(fs.readFileSync("./target/idl/wzec_bridge.json", "utf8"));

const PROGRAM_ID = new PublicKey("B12pxSGTH8bt8LtVcdbEXf2CPpf2sFJuj7SctsFuvcQc");

async function main() {
    console.log("\n=== Testing burn_for_withdrawal ===\n");

    // Setup connection
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");
    
    // Load keypair
    const keypairPath = process.env.SOLANA_KEYPAIR || `${process.env.HOME}/.config/solana/id.json`;
    const keypairData = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
    const payer = Keypair.fromSecretKey(new Uint8Array(keypairData));
    
    console.log("Payer:", payer.publicKey.toBase58());

    // Setup Anchor
    const wallet = new anchor.Wallet(payer);
    const provider = new anchor.AnchorProvider(connection, wallet, { commitment: "confirmed" });
    const program = new anchor.Program(idl, provider);

    // Derive PDAs
    const [bridgeConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("bridge-config")],
        PROGRAM_ID
    );
    const [szecMint] = PublicKey.findProgramAddressSync(
        [Buffer.from("szec-mint")],
        PROGRAM_ID
    );

    console.log("Bridge Config:", bridgeConfig.toBase58());
    console.log("sZEC Mint:", szecMint.toBase58());

    // Get current burn nonce
    let config;
    try {
        config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
        console.log("\nBridge Config State:");
        console.log("  Deposit Nonce:", config.depositNonce.toString());
        console.log("  Burn Nonce:", config.burnNonce.toString());
        console.log("  Total Minted:", config.totalMinted.toString());
        console.log("  Total Burned:", config.totalBurned.toString());
    } catch (e: any) {
        console.error("Failed to fetch bridge config:", e.message);
        return;
    }

    const burnId = config.burnNonce.toNumber();
    console.log("\nNext burn ID will be:", burnId);

    // Check user's sZEC balance
    const userTokenAccount = await getAssociatedTokenAddress(szecMint, payer.publicKey);
    console.log("User Token Account:", userTokenAccount.toBase58());

    let balance = BigInt(0);
    try {
        const tokenAccount = await getAccount(connection, userTokenAccount);
        balance = tokenAccount.amount;
        console.log("sZEC Balance:", balance.toString(), "zatoshi");
    } catch (e) {
        console.log("sZEC Balance: 0 (no token account)");
    }

    if (balance === BigInt(0)) {
        console.log("\n[!] No sZEC to burn. You need to deposit first.");
        console.log("    Run: npx ts-node scripts/test-mint.ts");
        return;
    }

    // Create burn intent
    const burnAmount = new anchor.BN(Math.min(Number(balance), 1_000_000)); // Burn 0.01 ZEC or whatever we have
    console.log("\nBurning:", burnAmount.toString(), "zatoshi");

    // Create a fake Zcash address hash (in production this would be encrypted)
    const zcashAddress = "utest1qg5dl5ptvxz9j2ynhqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsqqqqqqqqqqqqqqqqqqqqqquqd5hq";
    const zcashAddressHash = crypto.createHash("sha256").update(zcashAddress).digest();
    console.log("Zcash address hash:", zcashAddressHash.toString("hex").slice(0, 16) + "...");

    // Derive burn intent PDA
    const [burnIntentPda] = PublicKey.findProgramAddressSync(
        [
            Buffer.from("burn-intent"),
            payer.publicKey.toBuffer(),
            new anchor.BN(burnId).toArrayLike(Buffer, "le", 8),
        ],
        PROGRAM_ID
    );
    console.log("Burn Intent PDA:", burnIntentPda.toBase58());

    try {
        console.log("\nSubmitting burn transaction...");
        
        const tx = await (program.methods as any)
            .burnForWithdrawal(
                burnAmount,
                Array.from(zcashAddressHash)
            )
            .accounts({
                user: payer.publicKey,
                bridgeConfig,
                burnIntent: burnIntentPda,
                szecMint,
                userTokenAccount,
                tokenProgram: anchor.utils.token.TOKEN_PROGRAM_ID,
                systemProgram: anchor.web3.SystemProgram.programId,
            })
            .rpc({ skipPreflight: true });

        console.log("Transaction:", tx);
        console.log("\n[OK] Burn intent created!");

        // Fetch the burn intent to verify
        const burnIntent = await (program.account as any).burnIntent.fetch(burnIntentPda);
        console.log("\nBurn Intent State:");
        console.log("  Burn ID:", burnIntent.burnId.toString());
        console.log("  User:", burnIntent.user.toBase58());
        console.log("  Amount:", burnIntent.amount.toString());
        console.log("  Status:", burnIntent.status, "(0=Pending, 1=Processing, 2=Completed, 3=Failed)");
        console.log("  Encrypted Data Hash:", Buffer.from(burnIntent.encryptedDataHash).toString("hex").slice(0, 16) + "...");

        // Check updated balance
        try {
            const updatedAccount = await getAccount(connection, userTokenAccount);
            console.log("\nUpdated sZEC Balance:", updatedAccount.amount.toString(), "zatoshi");
        } catch (e) {
            console.log("\nUpdated sZEC Balance: 0");
        }

        // Check updated config
        const updatedConfig = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
        console.log("Updated Total Burned:", updatedConfig.totalBurned.toString());

    } catch (e: any) {
        console.error("\n[ERROR] Failed to create burn intent:");
        console.error(e.message);
        if (e.logs) {
            console.error("\nProgram logs:");
            e.logs.forEach((log: string) => console.error("  ", log));
        }
    }
}

main().catch(console.error);

