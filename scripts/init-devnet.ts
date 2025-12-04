import * as anchor from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";

async function main() {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const programId = new PublicKey("5PLQ9ZSbYq4qfYic3dCwyr1BR8GMVfCKWsbTan2VWE45");
  const idl = JSON.parse(require("fs").readFileSync("target/idl/wzec_bridge.json", "utf8"));
  const program = new anchor.Program(idl, provider);

  console.log("Initializing comp defs on devnet...");
  
  // Initialize verify_attestation comp def
  try {
    await program.methods.initVerifyAttestationCompDef().rpc();
    console.log("  verify_attestation: OK");
  } catch (e) { console.log("  verify_attestation:", e.message); }

  // Initialize create_burn_intent comp def  
  try {
    await program.methods.initCreateBurnIntentCompDef().rpc();
    console.log("  create_burn_intent: OK");
  } catch (e) { console.log("  create_burn_intent:", e.message); }

  // Initialize update_burn_intent comp def
  try {
    await program.methods.initUpdateBurnIntentCompDef().rpc();
    console.log("  update_burn_intent: OK");
  } catch (e) { console.log("  update_burn_intent:", e.message); }

  console.log("Done!");
}

main();
