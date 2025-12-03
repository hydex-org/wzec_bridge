import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, BpfLoader, BPF_LOADER_PROGRAM_ID } from "@solana/web3.js";
import { WzecBridge } from "../target/types/wzec_bridge";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { randomBytes } from "crypto";
import {
  awaitComputationFinalization,
  getArciumEnv,
  getCompDefAccOffset,
  getArciumAccountBaseSeed,
  getArciumProgAddress,
  buildFinalizeCompDefTx,
  getMXEAccAddress,
  getMXEPublicKey,
  getMempoolAccAddress,
  getCompDefAccAddress,
  getExecutingPoolAccAddress,
  getComputationAccAddress,
} from "@arcium-hq/client";
import * as fs from "fs";
import * as os from "os";
import { expect } from "chai";

describe("wzec-bridge", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.WzecBridge as Program<WzecBridge>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  type Event = anchor.IdlEvents<(typeof program)["idl"]>;
  const awaitEvent = async <E extends keyof Event>(
    eventName: E
  ): Promise<Event[E]> => {
    let listenerId: number;
    const event = await new Promise<Event[E]>((res) => {
      listenerId = program.addEventListener(eventName, (event) => {
        res(event);
      });
    });
    await program.removeEventListener(listenerId);
    return event;
  };

  const arciumEnv = getArciumEnv();

  // PDAs
  let bridgeConfigPda: PublicKey;
  let mintAuthorityPda: PublicKey;
  let szecMintPda: PublicKey;

  // Keypairs
  let owner: anchor.web3.Keypair;
  let enclaveAuthority: anchor.web3.Keypair;
  let mpcAuthority: anchor.web3.Keypair;

  before(async () => {
    console.log("Setting up test environment...");
    owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);
    enclaveAuthority = anchor.web3.Keypair.generate();
    mpcAuthority = anchor.web3.Keypair.generate();

    // Deploy the program (since arcium test doesn't use [[test.genesis]])
    console.log("Deploying program...");
    try {
      const programBuffer = fs.readFileSync("target/deploy/wzec_bridge.so");
      const deployedProgramId = await deployProgram(
        provider,
        programBuffer,
        program.programId
      );
      console.log("Program deployed:", deployedProgramId.toString());
    } catch (error) {
      console.error("Failed to deploy program:", error);
      throw error;
    }

    // Derive PDAs
    [bridgeConfigPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("bridge-config")],
      program.programId
    );

    [mintAuthorityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint-authority")],
      program.programId
    );

    [szecMintPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("szec-mint")],
      program.programId
    );

    console.log("Program ID:", program.programId.toString());
    console.log("Owner:", owner.publicKey.toString());
    console.log("Bridge Config PDA:", bridgeConfigPda.toString());
    console.log("sZEC Mint PDA:", szecMintPda.toString());
  });

  it("initializes computation definitions", async () => {
    console.log("\nInitializing computation definitions...");

    // Initialize verify_attestation comp def
    const initVerifyAttSig = await initCompDef(
      program,
      owner,
      "verify_attestation",
      "initVerifyAttestationCompDef"
    );
    console.log("verify_attestation comp def initialized:", initVerifyAttSig);

    // Initialize create_burn_intent comp def
    const initCreateBurnSig = await initCompDef(
      program,
      owner,
      "create_burn_intent",
      "initCreateBurnIntentCompDef"
    );
    console.log("create_burn_intent comp def initialized:", initCreateBurnSig);

    // Initialize update_burn_intent comp def
    const initUpdateBurnSig = await initCompDef(
      program,
      owner,
      "update_burn_intent",
      "initUpdateBurnIntentCompDef"
    );
    console.log("update_burn_intent comp def initialized:", initUpdateBurnSig);

    // Wait for MXE to be ready
    const mxePublicKey = await getMXEPublicKeyWithRetry(
      provider,
      program.programId
    );
    console.log("MXE x25519 pubkey:", Buffer.from(mxePublicKey).toString("hex"));
  });

  it("initializes the bridge", async () => {
    console.log("\nInitializing bridge...");

    const tx = await program.methods
      .initBridge(enclaveAuthority.publicKey, mpcAuthority.publicKey)
      .accounts({
        admin: owner.publicKey,
        bridgeConfig: bridgeConfigPda,
        szecMint: szecMintPda,
        mintAuthority: mintAuthorityPda,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .signers([owner])
      .rpc();

    console.log("Bridge initialized! TX:", tx);

    // Verify config
    const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    expect(config.admin.toString()).to.equal(owner.publicKey.toString());
    expect(config.enclaveAuthority.toString()).to.equal(
      enclaveAuthority.publicKey.toString()
    );
    expect(config.mpcAuthority.toString()).to.equal(
      mpcAuthority.publicKey.toString()
    );
    console.log("Bridge config verified!");
  });

  it("creates deposit intent", async () => {
    console.log("\nCreating deposit intent...");

    const configBefore = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    const depositId = configBefore.depositNonce.toNumber();

    const [depositIntentPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("deposit-intent"),
        owner.publicKey.toBuffer(),
        new anchor.BN(depositId).toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    const tx = await program.methods
      .initDepositIntent()
      .accounts({
        user: owner.publicKey,
        bridgeConfig: bridgeConfigPda,
        depositIntent: depositIntentPda,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([owner])
      .rpc();

    console.log("Deposit intent created! TX:", tx);

    const intent = await program.account.depositIntent.fetch(depositIntentPda);
    expect(intent.depositId.toNumber()).to.equal(depositId);
    expect(intent.status).to.equal(0); // Pending
    console.log("Deposit intent ID:", depositId);
  });

  it("sets unified address (enclave authority)", async () => {
    console.log("\nSetting unified address...");

    const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
    const depositId = config.depositNonce.toNumber() - 1; // Last created

    const [depositIntentPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("deposit-intent"),
        owner.publicKey.toBuffer(),
        new anchor.BN(depositId).toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    const uaHash = randomBytes(32);
    const noteCommitment = randomBytes(32);
    const amount = new anchor.BN(100000000); // 1 sZEC

    const tx = await program.methods
      .setUnifiedAddress(Array.from(uaHash) as any, amount, Array.from(noteCommitment) as any)
      .accounts({
        authority: enclaveAuthority.publicKey,
        bridgeConfig: bridgeConfigPda,
        depositIntent: depositIntentPda,
      })
      .signers([enclaveAuthority])
      .rpc();

    console.log("Unified address set! TX:", tx);

    const intent = await program.account.depositIntent.fetch(depositIntentPda);
    expect(intent.status).to.equal(1); // AddressGenerated
    expect(intent.amount.toNumber()).to.equal(100000000);
    console.log("Deposit status: AddressGenerated");
  });
});

// Helper to initialize computation definition
async function initCompDef(
  program: Program<WzecBridge>,
  owner: anchor.web3.Keypair,
  compDefName: string,
  methodName: string
): Promise<string> {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const baseSeedCompDefAcc = getArciumAccountBaseSeed("ComputationDefinitionAccount");
  const offset = getCompDefAccOffset(compDefName);

  const compDefPDA = PublicKey.findProgramAddressSync(
    [baseSeedCompDefAcc, program.programId.toBuffer(), offset],
    getArciumProgAddress()
  )[0];

  console.log(`  ${compDefName} comp def PDA:`, compDefPDA.toString());

  // Call the appropriate init method
  const sig = await (program.methods as any)[methodName]()
    .accounts({
      compDefAccount: compDefPDA,
      payer: owner.publicKey,
      mxeAccount: getMXEAccAddress(program.programId),
    })
    .signers([owner])
    .rpc();

  // Finalize the comp def
  const finalizeTx = await buildFinalizeCompDefTx(
    provider,
    Buffer.from(offset).readUInt32LE(),
    program.programId
  );

  const latestBlockhash = await provider.connection.getLatestBlockhash();
  finalizeTx.recentBlockhash = latestBlockhash.blockhash;
  finalizeTx.lastValidBlockHeight = latestBlockhash.lastValidBlockHeight;
  finalizeTx.sign(owner);

  await provider.sendAndConfirm(finalizeTx);

  return sig;
}

async function getMXEPublicKeyWithRetry(
  provider: anchor.AnchorProvider,
  programId: PublicKey,
  maxRetries: number = 20,
  retryDelayMs: number = 500
): Promise<Uint8Array> {
  console.log("Waiting for MXE to initialize...");
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const mxePublicKey = await getMXEPublicKey(provider, programId);
      if (mxePublicKey) {
        return mxePublicKey;
      }
    } catch (error) {
      // Retry
    }

    if (attempt < maxRetries) {
      console.log(`  Retry ${attempt}/${maxRetries}...`);
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }

  throw new Error(`Failed to fetch MXE public key after ${maxRetries} attempts`);
}

function readKpJson(path: string): anchor.web3.Keypair {
  const file = fs.readFileSync(path);
  return anchor.web3.Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(file.toString()))
  );
}

async function deployProgram(
  provider: anchor.AnchorProvider,
  programBuffer: Buffer,
  programId: PublicKey
): Promise<PublicKey> {
  // Read the program keypair
  const programKeypair = readKpJson("target/deploy/wzec_bridge-keypair.json");

  // Verify the keypair matches the expected program ID
  if (!programKeypair.publicKey.equals(programId)) {
    throw new Error(
      `Program keypair mismatch! Expected ${programId.toString()}, got ${programKeypair.publicKey.toString()}`
    );
  }

  console.log(`  Loading program ${programId.toString()}...`);
  console.log(`  Program size: ${programBuffer.length} bytes`);

  // Deploy using BPF loader
  await BpfLoader.load(
    provider.connection,
    (provider.wallet as anchor.Wallet).payer,
    programKeypair,
    programBuffer,
    BPF_LOADER_PROGRAM_ID
  );

  console.log(`  Program deployed successfully!`);
  return programId;
}
