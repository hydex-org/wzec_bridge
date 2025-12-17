import * as anchor from "@coral-xyz/anchor";
import { Connection, PublicKey, Keypair } from "@solana/web3.js";
import * as fs from "fs";

const PROGRAM_ID = new PublicKey("4XACNSk2pxPL4GtXWB7vVTrNUR9vWaoncof1Gw9xszaD");
const idl = JSON.parse(fs.readFileSync("./target/idl/wzec_bridge.json", "utf8"));

// Target authority - set via NEW_AUTHORITY env var or defaults to local keypair
const NEW_AUTHORITY = process.env.NEW_AUTHORITY
    ? new PublicKey(process.env.NEW_AUTHORITY)
    : null;

async function main() {
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");
    const keypairPath = process.env.SOLANA_KEYPAIR || `${process.env.HOME}/.config/solana/id.json`;
    const adminKeypair = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(keypairPath, "utf8"))));

    const wallet = new anchor.Wallet(adminKeypair);
    const provider = new anchor.AnchorProvider(connection, wallet, { commitment: "confirmed" });
    anchor.setProvider(provider);

    idl.address = PROGRAM_ID.toBase58();
    const program = new anchor.Program(idl as anchor.Idl, provider);

    const [bridgeConfig] = PublicKey.findProgramAddressSync([Buffer.from("bridge-config")], PROGRAM_ID);

    // Fetch current config
    const config = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
    console.log("Current admin:", config.admin.toBase58());
    console.log("Current enclave:", config.enclaveAuthority.toBase58());
    console.log("Current MPC:", config.mpcAuthority.toBase58());
    console.log("Signing keypair:", adminKeypair.publicKey.toBase58());

    // The admin must sign
    if (config.admin.toBase58() !== adminKeypair.publicKey.toBase58()) {
        console.log("\nERROR: You are not the admin.");
        console.log("Only", config.admin.toBase58(), "can update authorities.");
        console.log("\nSet SOLANA_KEYPAIR to the admin keypair and try again.");
        return;
    }

    // Use NEW_AUTHORITY if set, otherwise use the signing keypair
    const targetAuthority = NEW_AUTHORITY || adminKeypair.publicKey;

    console.log("\nUpdating authorities to:", targetAuthority.toBase58());

    const tx = await (program.methods as any)
        .updateAuthorities(targetAuthority, targetAuthority)
        .accounts({
            admin: adminKeypair.publicKey,
            bridgeConfig,
        })
        .rpc();

    console.log("TX:", tx);
    console.log("\nAuthorities updated successfully!");

    // Verify
    const newConfig = await (program.account as any).bridgeConfig.fetch(bridgeConfig);
    console.log("\nNew enclave:", newConfig.enclaveAuthority.toBase58());
    console.log("New MPC:", newConfig.mpcAuthority.toBase58());
}

main().catch(console.error);

