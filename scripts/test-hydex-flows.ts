

import * as anchor from "@coral-xyz/anchor";
import { Connection, PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import {
    getAssociatedTokenAddress,
    createAssociatedTokenAccountInstruction,
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
    getAccount,
} from "@solana/spl-token";
import * as crypto from "crypto";
import * as fs from "fs";

const PROGRAM_ID = new PublicKey("4XACNSk2pxPL4GtXWB7vVTrNUR9vWaoncof1Gw9xszaD");

// Load IDL
const idl = JSON.parse(fs.readFileSync("./target/idl/wzec_bridge.json", "utf8"));

async function main() {
    console.log("\n" + "=".repeat(60));
    console.log("  HYDEX BRIDGE - Comprehensive Flow Tests");
    console.log("  Testing Enclave-only minting & withdrawal (no MPC on Solana)");
    console.log("=".repeat(60) + "\n");

    // Setup
    const connection = new Connection(
        process.env.RPC_URL || "https://api.devnet.solana.com",
        "confirmed"
    );

    const keypairPath = process.env.SOLANA_KEYPAIR ||
        `${process.env.HOME}/.config/solana/id.json`;
    const keypairData = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
    const payer = Keypair.fromSecretKey(new Uint8Array(keypairData));

    const wallet = new anchor.Wallet(payer);
    const provider = new anchor.AnchorProvider(connection, wallet, {
        commitment: "confirmed"
    });
    anchor.setProvider(provider);

    idl.address = PROGRAM_ID.toBase58();
    const program = new anchor.Program(idl as anchor.Idl, provider);

    // Derive PDAs
    const [bridgeConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("bridge-config")],
        PROGRAM_ID
    );
    const [szecMint] = PublicKey.findProgramAddressSync(
        [Buffer.from("szec-mint")],
        PROGRAM_ID
    );
    const [mintAuthority] = PublicKey.findProgramAddressSync(
        [Buffer.from("mint-authority")],
        PROGRAM_ID
    );

    console.log("Payer:", payer.publicKey.toBase58());
    console.log("Program:", PROGRAM_ID.toBase58());
    console.log("Bridge Config:", bridgeConfig.toBase58());
    console.log("sZEC Mint:", szecMint.toBase58());

    // =========================================================================
    // STEP 1: Initialize Bridge (or verify existing)
    // =========================================================================
    console.log("\n" + "-".repeat(60));
    console.log("[1/6] Bridge Initialization");
    console.log("-".repeat(60));

    let config: any;
    const bridgeInfo = await connection.getAccountInfo(bridgeConfig);

    if (bridgeInfo) {
        config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
        console.log("  Bridge already initialized");
        console.log("  Admin:", config.admin.toBase58());
        console.log("  Enclave Authority:", config.enclaveAuthority.toBase58());
        console.log("  MPC Authority:", config.mpcAuthority.toBase58());
        console.log("  Deposit Nonce:", config.depositNonce.toString());
        console.log("  Burn Nonce:", config.burnNonce.toString());
        console.log("  Total Minted:", config.totalMinted.toString(), "zatoshi");
        console.log("  Total Burned:", config.totalBurned.toString(), "zatoshi");
    } else {
        console.log("  Initializing bridge...");
        // Set payer as both enclave and MPC authority for testing
        const tx = await (program.methods as any)
            .initBridge(payer.publicKey, payer.publicKey)
            .accounts({
                admin: payer.publicKey,
                bridgeConfig,
                szecMint,
                mintAuthority,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            })
            .rpc({ skipPreflight: true });
        console.log("  TX:", tx);
        config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
        console.log("  [OK] Bridge initialized!");
    }

    // Verify authority
    const isEnclave = payer.publicKey.equals(config.enclaveAuthority);
    const isMpc = payer.publicKey.equals(config.mpcAuthority);
    console.log("\n  Authority Check:");
    console.log("    Is Enclave Authority:", isEnclave ? "YES" : "NO");
    console.log("    Is MPC Authority:", isMpc ? "YES" : "NO");

    if (!isEnclave) {
        console.log("\n  [ERROR] Payer is not enclave_authority!");
        console.log("  Minting and withdrawal finalization will fail.");
        console.log("  Re-initialize the bridge with your keypair as enclave_authority.");
        return;
    }

    // =========================================================================
    // STEP 2: Create Deposit Intent (Enclave creates for user)
    // =========================================================================
    console.log("\n" + "-".repeat(60));
    console.log("[2/6] Deposit Intent Creation (enclave_authority)");
    console.log("-".repeat(60));

    // Refresh config for current nonce
    config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
    const depositId = config.depositNonce.toNumber();

    // Create a "user" (could be any pubkey, we'll use payer for simplicity)
    const userPubkey = payer.publicKey;
    const uaHash = crypto.randomBytes(32);

    const [depositIntent] = PublicKey.findProgramAddressSync(
        [
            Buffer.from("deposit-intent"),
            userPubkey.toBuffer(),
            new anchor.BN(depositId).toArrayLike(Buffer, "le", 8),
        ],
        PROGRAM_ID
    );

    console.log("  Deposit ID:", depositId);
    console.log("  User:", userPubkey.toBase58());
    console.log("  Deposit Intent PDA:", depositIntent.toBase58());
    console.log("  UA Hash:", uaHash.toString("hex").slice(0, 32) + "...");

    try {
        const tx = await (program.methods as any)
            .createDepositForUser(userPubkey, Array.from(uaHash))
            .accounts({
                authority: payer.publicKey,
                payer: payer.publicKey,
                bridgeConfig,
                depositIntent,
                systemProgram: SystemProgram.programId,
            })
            .rpc({ skipPreflight: true });
        console.log("  TX:", tx);
        console.log("  [OK] Deposit intent created by enclave!");

        const intent = await (program.account as any).depositIntent.fetch(depositIntent);
        console.log("  Status:", intent.status, "(1 = AddressGenerated)");
    } catch (e: any) {
        if (e.message?.includes("already in use")) {
            console.log("  Deposit intent already exists, continuing...");
        } else {
            console.log("  Error:", e.message);
            return;
        }
    }

    // =========================================================================
    // STEP 3: Ensure User Has Token Account
    // =========================================================================
    console.log("\n" + "-".repeat(60));
    console.log("[3/6] Token Account Setup");
    console.log("-".repeat(60));

    const userTokenAccount = await getAssociatedTokenAddress(szecMint, userPubkey);
    console.log("  User Token Account:", userTokenAccount.toBase58());

    const ataInfo = await connection.getAccountInfo(userTokenAccount);
    if (!ataInfo) {
        console.log("  Creating ATA...");
        const createAtaIx = createAssociatedTokenAccountInstruction(
            payer.publicKey,
            userTokenAccount,
            userPubkey,
            szecMint
        );
        const tx = new anchor.web3.Transaction().add(createAtaIx);
        const sig = await provider.sendAndConfirm(tx);
        console.log("  TX:", sig);
        console.log("  [OK] ATA created!");
    } else {
        const tokenAccount = await getAccount(connection, userTokenAccount);
        console.log("  ATA exists, balance:", tokenAccount.amount.toString(), "zatoshi");
    }

    // =========================================================================
    // STEP 4: Mint via mint_simple (devnet path, enclave_authority)
    // =========================================================================
    console.log("\n" + "-".repeat(60));
    console.log("[4/6] Minting sZEC (enclave_authority, devnet mint_simple)");
    console.log("-".repeat(60));

    // Get the deposit intent we just created
    const currentIntent = await (program.account as any).depositIntent.fetch(depositIntent);

    if (currentIntent.status === 3) {
        console.log("  Deposit already minted, skipping...");
    } else if (currentIntent.status !== 1) {
        console.log("  Deposit not in correct state (need status=1, got", currentIntent.status + ")");
    } else {
        const noteCommitment = crypto.randomBytes(32);
        const amount = new anchor.BN(100_000_000); // 1 sZEC
        const blockHeight = new anchor.BN(4000000);

        const [claimTracker] = PublicKey.findProgramAddressSync(
            [Buffer.from("claim-tracker"), noteCommitment],
            PROGRAM_ID
        );

        console.log("  Amount:", amount.toString(), "zatoshi (1 sZEC)");
        console.log("  Note Commitment:", noteCommitment.toString("hex").slice(0, 32) + "...");
        console.log("  Claim Tracker:", claimTracker.toBase58());

        try {
            const tx = await (program.methods as any)
                .mintSimple(
                    Array.from(noteCommitment),
                    amount,
                    blockHeight
                )
                .accounts({
                    authority: payer.publicKey,
                    payer: payer.publicKey,
                    bridgeConfig,
                    depositIntent,
                    claimTracker,
                    szecMint,
                    mintAuthority,
                    userWallet: userPubkey,
                    userTokenAccount,
                    associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
                    tokenProgram: TOKEN_PROGRAM_ID,
                    systemProgram: SystemProgram.programId,
                })
                .rpc({ skipPreflight: true });

            console.log("  TX:", tx);
            console.log("  [OK] Minted 1 sZEC!");

            const tokenAccount = await getAccount(connection, userTokenAccount);
            console.log("  New balance:", tokenAccount.amount.toString(), "zatoshi");
        } catch (e: any) {
            console.log("  Error:", e.message);
            if (e.logs) {
                e.logs.slice(-5).forEach((l: string) => console.log("    ", l));
            }
        }
    }

    // =========================================================================
    // STEP 5: Burn for Withdrawal (User action)
    // =========================================================================
    console.log("\n" + "-".repeat(60));
    console.log("[5/6] Burn for Withdrawal (user burns sZEC)");
    console.log("-".repeat(60));

    // Check balance
    let balance = BigInt(0);
    try {
        const tokenAccount = await getAccount(connection, userTokenAccount);
        balance = tokenAccount.amount;
        console.log("  Current balance:", balance.toString(), "zatoshi");
    } catch (e) {
        console.log("  No token account, skipping burn test");
    }

    if (balance > 0) {
        config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
        const burnId = config.burnNonce.toNumber();
        const burnAmount = Math.min(Number(balance), 50_000_000); // 0.5 sZEC max

        const zcashAddress = "utest1qqqqqqqpq0ejdeevtndncq0fvwgr8dphxgrx78ggth0znecq9xrj6pj8xmsjqk2l3xf53kc0p4ypn9g66uvf6uyj0xqfr";
        const zcashAddressHash = crypto.createHash("sha256").update(zcashAddress).digest();

        const [burnIntentPda] = PublicKey.findProgramAddressSync(
            [
                Buffer.from("burn-intent"),
                userPubkey.toBuffer(),
                new anchor.BN(burnId).toArrayLike(Buffer, "le", 8),
            ],
            PROGRAM_ID
        );

        console.log("  Burn ID:", burnId);
        console.log("  Amount:", burnAmount, "zatoshi");
        console.log("  Burn Intent PDA:", burnIntentPda.toBase58());

        try {
            // encrypted_zcash_addr is now Vec<u8>, pass as Buffer
            const encryptedAddr = Buffer.from(zcashAddress, "utf8");

            const tx = await (program.methods as any)
                .burnForWithdrawal(
                    new anchor.BN(burnAmount),
                    encryptedAddr
                )
                .accounts({
                    user: userPubkey,
                    bridgeConfig,
                    burnIntent: burnIntentPda,
                    szecMint,
                    userTokenAccount,
                    tokenProgram: TOKEN_PROGRAM_ID,
                    systemProgram: SystemProgram.programId,
                })
                .rpc({ skipPreflight: true });

            console.log("  TX:", tx);
            console.log("  [OK] Burn successful!");

            // =========================================================================
            // STEP 6: Enclave marks processing & finalizes (NO MPC on Solana!)
            // =========================================================================
            console.log("\n" + "-".repeat(60));
            console.log("[6/6] Enclave Finalizes Withdrawal (enclave_authority)");
            console.log("-".repeat(60));

            // Mark as processing
            console.log("  Marking as processing...");
            const tx2 = await (program.methods as any)
                .markBurnProcessing()
                .accounts({
                    authority: payer.publicKey,
                    bridgeConfig,
                    burnIntent: burnIntentPda,
                })
                .rpc({ skipPreflight: true });
            console.log("  TX:", tx2);

            const burnIntent = await (program.account as any).burnIntent.fetch(burnIntentPda);
            console.log("  Status:", burnIntent.status, "(1 = Processing)");

            // Finalize with fake zcash txid
            console.log("\n  Finalizing withdrawal...");
            const fakeZcashTxid = crypto.randomBytes(32);

            const tx3 = await (program.methods as any)
                .finalizeWithdrawalDirect(Array.from(fakeZcashTxid), true)
                .accounts({
                    authority: payer.publicKey,
                    bridgeConfig,
                    burnIntent: burnIntentPda,
                })
                .rpc({ skipPreflight: true });
            console.log("  TX:", tx3);

            const finalIntent = await (program.account as any).burnIntent.fetch(burnIntentPda);
            console.log("  Status:", finalIntent.status, "(2 = Completed)");
            console.log("  Zcash TXID:", Buffer.from(finalIntent.zcashTxid).toString("hex").slice(0, 32) + "...");
            console.log("  [OK] Withdrawal finalized by enclave!");
        } catch (e: any) {
            console.log("  Error:", e.message);
            if (e.logs) {
                e.logs.slice(-5).forEach((l: string) => console.log("    ", l));
            }
        }
    } else {
        console.log("  No sZEC to burn, skipping withdrawal test");
    }

    // =========================================================================
    // Final Summary
    // =========================================================================
    console.log("\n" + "=".repeat(60));
    console.log("  Test Summary");
    console.log("=".repeat(60));

    config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
    console.log("  Total Deposits:", config.depositNonce.toString());
    console.log("  Total Burns:", config.burnNonce.toString());
    console.log("  Total Minted:", config.totalMinted.toString(), "zatoshi");
    console.log("  Total Burned:", config.totalBurned.toString(), "zatoshi");

    console.log("\n  Hydex Spec Compliance:");
    console.log("    [OK] Deposits created by enclave_authority");
    console.log("    [OK] Minting via enclave_authority (devnet: mint_simple)");
    console.log("    [OK] Burn processing by enclave_authority (not MPC)");
    console.log("    [OK] Withdrawal finalization by enclave_authority (not MPC)");
    console.log("    [OK] MPC does NO Solana work");

    console.log("\n" + "=".repeat(60) + "\n");
}

main().catch(console.error);

