import { createUmi } from "@metaplex-foundation/umi-bundle-defaults";
import { createMetadataAccountV3 } from "@metaplex-foundation/mpl-token-metadata";
import { publicKey, signerIdentity } from "@metaplex-foundation/umi";
import { createSignerFromKeypair } from "@metaplex-foundation/umi";
import * as fs from "fs";

async function main() {
    const umi = createUmi("https://devnet.helius-rpc.com/?api-key=288ee798-eaa4-49ff-8a3b-7095385a7cc8");

    // Load wallet
    const walletPath = "/Users/fb/testing/bridge-custody/data/node1/solana-keypair.json";
    const secretKey = JSON.parse(fs.readFileSync(walletPath, "utf8"));
    const keypair = umi.eddsa.createKeypairFromSecretKey(new Uint8Array(secretKey));
    const signer = createSignerFromKeypair(umi, keypair);
    umi.use(signerIdentity(signer));

    // Your sZEC mint address (get from test output)
    const mintAddress = publicKey("96p2Rhb4DsuZVC8yBGjGPimFbH111NqaYAxE42Y2Poza");

    // Mint authority PDA (same keypair that can sign for it)
    const mintAuthority = signer; // Adjust if different

    await createMetadataAccountV3(umi, {
        mint: mintAddress,
        mintAuthority: mintAuthority,
        payer: signer,
        updateAuthority: signer.publicKey,
        data: {
            name: "Shielded ZEC",
            symbol: "sZEC",
            uri: "", // Add JSON metadata URL if you want an image
            sellerFeeBasisPoints: 0,
            creators: null,
            collection: null,
            uses: null,
        },
        isMutable: true,
        collectionDetails: null,
    }).sendAndConfirm(umi);

    console.log("Metadata added! Token is now named sZEC");
}

main().catch(console.error);