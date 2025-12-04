import * as anchor from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Connection, Keypair } from "@solana/web3.js";
import {
    getAssociatedTokenAddress,
    createAssociatedTokenAccountInstruction,
    TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import * as crypto from "crypto";
import * as fs from "fs";

async function main() {
    // Setup connection and wallet
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");
    const walletPath = process.env.ANCHOR_WALLET || "/Users/fb/testing/bridge-custody/data/node1/solana-keypair.json";
    const secretKey = JSON.parse(fs.readFileSync(walletPath, "utf8"));
    const payer = Keypair.fromSecretKey(Uint8Array.from(secretKey));
    const wallet = new anchor.Wallet(payer);
    const provider = new anchor.AnchorProvider(connection, wallet, { commitment: "confirmed" });
    anchor.setProvider(provider);

    const programId = new PublicKey("B12pxSGTH8bt8LtVcdbEXf2CPpf2sFJuj7SctsFuvcQc");

    // Load IDL from local file and set program address explicitly
    const idl = JSON.parse(fs.readFileSync("./target/idl/wzec_bridge.json", "utf8"));
    idl.address = programId.toBase58(); // Ensure program ID matches
    const program = new anchor.Program(idl as anchor.Idl, provider);

    console.log("Payer/Authority:", payer.publicKey.toBase58());
    console.log("Program ID:", program.programId.toBase58());

    // Derive all PDAs
    const [bridgeConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("bridge-config")],
        programId
    );
    const [szecMint] = PublicKey.findProgramAddressSync(
        [Buffer.from("szec-mint")],
        programId
    );
    const [mintAuthority] = PublicKey.findProgramAddressSync(
        [Buffer.from("mint-authority")],
        programId
    );

    console.log("Bridge Config:", bridgeConfig.toBase58());
    console.log("sZEC Mint:", szecMint.toBase58());

    // First, check if accounts exist
    const bridgeInfo = await connection.getAccountInfo(bridgeConfig);
    const mintInfo = await connection.getAccountInfo(szecMint);

    console.log("\n--- Account Status ---");
    console.log("Bridge Config exists:", bridgeInfo !== null);
    console.log("sZEC Mint exists:", mintInfo !== null);

    // Step 1: Check if bridge is initialized
    let config: any;
    if (bridgeInfo) {
        try {
            config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
            console.log("\n[1/5] Bridge already initialized");
            console.log("  Enclave Authority:", config.enclaveAuthority.toBase58());
            console.log("  MPC Authority:", config.mpcAuthority.toBase58());
            console.log("  Deposit Nonce:", config.depositNonce.toString());
        } catch (e: any) {
            console.log("  Error fetching bridge config:", e.message);
            return;
        }
    } else {
        console.log("\n[1/5] Initializing bridge...");
        try {
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
                .rpc({ skipPreflight: false }); // Try with preflight for better errors
            console.log("  TX:", tx);
            config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
            console.log("  Bridge initialized!");
        } catch (e: any) {
            console.log("  Init failed:", e.message);
            if (e.logs) {
                console.log("  Logs:");
                e.logs.forEach((l: string) => console.log("    ", l));
            }
            return;
        }
    }

    // Verify we have authority
    const isEnclave = payer.publicKey.equals(config.enclaveAuthority);
    const isMpc = payer.publicKey.equals(config.mpcAuthority);
    console.log("  Is Enclave Authority:", isEnclave);
    console.log("  Is MPC Authority:", isMpc);

    if (!isEnclave && !isMpc) {
        console.log("\nERROR: Your wallet is not authorized!");
        console.log("You need to be either enclave_authority or mpc_authority to mint.");
        return;
    }

    // Continue with rest of flow...
    console.log("\n[2/5] Creating deposit intent...");
    const depositId = config.depositNonce.toNumber();
    const [depositIntent] = PublicKey.findProgramAddressSync(
        [
            Buffer.from("deposit-intent"),
            payer.publicKey.toBuffer(),
            new anchor.BN(depositId).toArrayLike(Buffer, "le", 8)
        ],
        programId
    );

    console.log("\n[2/5] Creating deposit intent...");
    console.log("  Deposit ID:", depositId);
    console.log("  Deposit Intent PDA:", depositIntent.toBase58());

    try {
        const tx = await (program.methods as any)
            .initDepositIntent()
            .accounts({
                user: payer.publicKey,
                bridgeConfig,
                depositIntent,
                payer: payer.publicKey,
                systemProgram: SystemProgram.programId,
            })
            .rpc({ skipPreflight: true });
        console.log("  TX:", tx);
        console.log("  Deposit intent created!");
    } catch (e: any) {
        if (e.message?.includes("already in use") || e.logs?.some((l: string) => l.includes("already in use"))) {
            console.log("  Deposit intent already exists, skipping...");
        } else {
            console.log("  Error:", e.message);
        }
    }

    // Step 3: Set unified address
    console.log("\n[3/5] Setting unified address...");

    const noteCommitment = crypto.randomBytes(32);
    const uaHash = crypto.randomBytes(32);
    const amount = new anchor.BN(30_000_000);

    let depositState: any;
    try {
        depositState = await (program.account as any).depositIntent.fetch(depositIntent);
        console.log("  Current status:", depositState.status);

        if (depositState.status === 0) {
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
            console.log("  Unified address set! Status -> 1");
        } else {
            console.log("  Status already >= 1, skipping...");
        }
    } catch (e: any) {
        console.log("  Error:", e.message);
        return;
    }

    // Step 4: Ensure user has ATA
    console.log("\n[4/5] Checking token account...");
    const userTokenAccount = await getAssociatedTokenAddress(szecMint, payer.publicKey);
    console.log("  User Token Account:", userTokenAccount.toBase58());

    const ataInfo = await connection.getAccountInfo(userTokenAccount);
    if (!ataInfo) {
        console.log("  Creating ATA...");
        const createAtaIx = createAssociatedTokenAccountInstruction(
            payer.publicKey,
            userTokenAccount,
            payer.publicKey,
            szecMint
        );
        const tx = new anchor.web3.Transaction().add(createAtaIx);
        const sig = await provider.sendAndConfirm(tx);
        console.log("  ATA created! TX:", sig);
    } else {
        console.log("  ATA exists");
    }

    // Step 5: Mint
    console.log("\n[5/5] Minting tokens...");

    const updatedDeposit = await (program.account as any).depositIntent.fetch(depositIntent);
    const noteCommitmentToUse = Buffer.from(updatedDeposit.noteCommitment);

    const [claimTracker] = PublicKey.findProgramAddressSync(
        [Buffer.from("claim-tracker"), noteCommitmentToUse],
        programId
    );
    console.log("  Claim Tracker:", claimTracker.toBase58());
    console.log("  Note Commitment:", noteCommitmentToUse.toString("hex"));

    try {
        const tx = await (program.methods as any)
            .mintSimple(
                Array.from(noteCommitmentToUse),
                updatedDeposit.amount,
                new anchor.BN(3716989)
            )
            .accounts({
                authority: payer.publicKey,
                payer: payer.publicKey,
                bridgeConfig,
                depositIntent,
                claimTracker,
                szecMint,
                mintAuthority,
                userTokenAccount,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
            })
            .rpc({ skipPreflight: true });

        console.log("\n=== MINT SUCCESSFUL! ===");
        console.log("TX:", tx);
    } catch (e: any) {
        console.error("\nMint failed:", e.message);
        if (e.logs) {
            console.error("Logs:");
            e.logs.forEach((l: string) => console.error("  ", l));
        }
    }
}

main().catch(console.error);