import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { WzecBridge } from "../target/types/wzec_bridge";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { PublicKey } from "@solana/web3.js";

async function main() {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const program = anchor.workspace.WzecBridge as Program<WzecBridge>;

    const enclaveAuthority = new PublicKey("7snpAB6ZU68NFLdU9GeqaxcGHwXUJcVNx4HLDeJu1vv9");
    const mpcAuthority = new PublicKey("9jcHoQ3gghMm3RD7JsZ3H1myRB2gJdfqRrD242uSWHe7");

    // Derive PDAs
    const [bridgeConfigPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("bridge-config")],
        program.programId
    );
    const [szecMintPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("szec-mint")],
        program.programId
    );
    const [mintAuthorityPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("mint-authority")],
        program.programId
    );

    console.log("Initializing bridge...");
    console.log("Program ID:", program.programId.toString());
    console.log("Bridge Config PDA:", bridgeConfigPda.toString());
    console.log("sZEC Mint PDA:", szecMintPda.toString());
    console.log("Enclave Authority:", enclaveAuthority.toString());
    console.log("MPC Authority:", mpcAuthority.toString());

    const tx = await program.methods
        .initBridge(enclaveAuthority, mpcAuthority)
        .accountsPartial({
            admin: provider.wallet.publicKey,
            bridgeConfig: bridgeConfigPda,
            szecMint: szecMintPda,
            mintAuthority: mintAuthorityPda,
            tokenProgram: TOKEN_PROGRAM_ID,
            systemProgram: anchor.web3.SystemProgram.programId,
            rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();

    console.log("\nBridge initialized!");
    console.log("Transaction:", tx);

    // Verify
    const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    console.log("\nBridge Config:");
    console.log("- Admin:", config.admin.toString());
    console.log("- sZEC Mint:", config.szecMint.toString());
}

main().catch(console.error);