#!/usr/bin/env ts-node

/**
 * Interactive script to test wzec_bridge on testnet
 * 
 * Usage:
 *   ts-node scripts/interact.ts <command> [args]
 * 
 * Commands:
 *   info              - Show bridge configuration
 *   create-deposit    - Create a deposit intent
 *   demo-mint <amount> - Mint test wZEC tokens (admin only)
 *   balance <address> - Check wZEC balance
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { WzecBridge } from "../target/types/wzec_bridge";
import { 
  TOKEN_PROGRAM_ID,
  getOrCreateAssociatedTokenAccount,
  getAccount
} from "@solana/spl-token";
import * as fs from "fs";

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command) {
    console.log("Usage: ts-node scripts/interact.ts <command> [args]");
    console.log("\nCommands:");
    console.log("  info              - Show bridge configuration");
    console.log("  create-deposit    - Create a deposit intent");
    console.log("  demo-mint <amount> - Mint test wZEC (admin only)");
    console.log("  balance <address> - Check wZEC balance");
    process.exit(1);
  }

  // Setup
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.WzecBridge as Program<WzecBridge>;

  // Load deployment
  const deployment = JSON.parse(
    fs.readFileSync("./deployments/testnet.json", "utf-8")
  );

  const bridgeConfigPda = new anchor.web3.PublicKey(deployment.bridgeConfig);
  const wzecMint = new anchor.web3.PublicKey(deployment.wzecMint);

  switch (command) {
    case "info":
      await showInfo(program, bridgeConfigPda, wzecMint);
      break;
    case "create-deposit":
      await createDeposit(program, provider, bridgeConfigPda);
      break;
    case "demo-mint":
      const amount = parseFloat(args[1] || "1");
      await demoMint(program, provider, deployment, amount);
      break;
    case "balance":
      const address = args[1] || provider.wallet.publicKey.toString();
      await checkBalance(provider, wzecMint, address);
      break;
    default:
      console.error("Unknown command:", command);
      process.exit(1);
  }
}

async function showInfo(
  program: Program<WzecBridge>,
  bridgeConfigPda: anchor.web3.PublicKey,
  wzecMint: anchor.web3.PublicKey
) {
  console.log("\n=== Bridge Information ===\n");
  
  const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
  
  console.log("Program ID:", program.programId.toString());
  console.log("Bridge Config:", bridgeConfigPda.toString());
  console.log("wZEC Mint:", config.wzecMint.toString());
  console.log("\nConfiguration:");
  console.log("- Admin:", config.admin.toString());
  console.log("- Enclave Authority:", config.enclaveAuthority.toString());
  console.log("- MPC Quorum Size:", config.mpcQuorumPubkeys.length);
  console.log("- Deposit Nonce:", config.depositNonce.toString());
  console.log("- Withdrawal Nonce:", config.withdrawalNonce.toString());
  console.log("- UFVK Length:", config.bridgeUfvk.length, "bytes");
  
  console.log(`\nExplorer: https://explorer.solana.com/address/${bridgeConfigPda}?cluster=testnet`);
}

async function createDeposit(
  program: Program<WzecBridge>,
  provider: anchor.AnchorProvider,
  bridgeConfigPda: anchor.web3.PublicKey
) {
  console.log("\n=== Creating Deposit Intent ===\n");
  
  const config = await program.account.bridgeConfig.fetch(bridgeConfigPda);
  const depositId = config.depositNonce.toNumber();
  const diversifierIndex = 0; // Default to 0
  
  const [depositIntentPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [
      Buffer.from("deposit-intent"),
      provider.wallet.publicKey.toBuffer(),
      Buffer.from(new anchor.BN(depositId).toArrayLike(Buffer, "le", 8)),
    ],
    program.programId
  );
  
  console.log("Creating deposit intent...");
  console.log("- User:", provider.wallet.publicKey.toString());
  console.log("- Deposit ID:", depositId);
  console.log("- Diversifier Index:", diversifierIndex);
  
  const tx = await program.methods
    .initIntent(diversifierIndex)
    .accounts({
      user: provider.wallet.publicKey,
      bridgeConfig: bridgeConfigPda,
      depositIntent: depositIntentPda,
      systemProgram: anchor.web3.SystemProgram.programId,
    })
    .rpc();
  
  console.log("\n✅ Deposit intent created!");
  console.log("Transaction:", tx);
  console.log("Deposit Intent PDA:", depositIntentPda.toString());
  console.log(`\nExplorer: https://explorer.solana.com/tx/${tx}?cluster=testnet`);
  console.log("\n📝 Next: Call bridge-custody API to get your Zcash deposit address");
  console.log(`   POST /api/deposit-address with solana_pubkey=${provider.wallet.publicKey}`);
}

async function demoMint(
  program: Program<WzecBridge>,
  provider: anchor.AnchorProvider,
  deployment: any,
  amountZec: number
) {
  console.log("\n=== Demo Minting wZEC ===\n");
  
  const wzecMint = new anchor.web3.PublicKey(deployment.wzecMint);
  const bridgeConfigPda = new anchor.web3.PublicKey(deployment.bridgeConfig);
  const mintAuthorityPda = new anchor.web3.PublicKey(deployment.mintAuthority);
  
  const amount = new anchor.BN(amountZec * 100_000_000); // Convert to zatoshis
  
  console.log("Minting:", amountZec, "wZEC");
  console.log("To:", provider.wallet.publicKey.toString());
  
  // Get or create token account
  const tokenAccount = await getOrCreateAssociatedTokenAccount(
    provider.connection,
    provider.wallet as any,
    wzecMint,
    provider.wallet.publicKey
  );
  
  const tx = await program.methods
    .demoMint(amount)
    .accounts({
      admin: provider.wallet.publicKey,
      bridgeConfig: bridgeConfigPda,
      mintAuthority: mintAuthorityPda,
      wzecMint: wzecMint,
      recipientTokenAccount: tokenAccount.address,
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .rpc();
  
  console.log("\n✅ Minted!", amountZec, "wZEC");
  console.log("Transaction:", tx);
  console.log("Token Account:", tokenAccount.address.toString());
  console.log(`\nExplorer: https://explorer.solana.com/tx/${tx}?cluster=testnet`);
}

async function checkBalance(
  provider: anchor.AnchorProvider,
  wzecMint: anchor.web3.PublicKey,
  addressStr: string
) {
  console.log("\n=== Checking wZEC Balance ===\n");
  
  const address = new anchor.web3.PublicKey(addressStr);
  console.log("Address:", address.toString());
  
  try {
    // Try to get token account
    const tokenAccounts = await provider.connection.getTokenAccountsByOwner(
      address,
      { mint: wzecMint }
    );
    
    if (tokenAccounts.value.length === 0) {
      console.log("Balance: 0 wZEC (no token account)");
      return;
    }
    
    const accountInfo = await provider.connection.getTokenAccountBalance(
      tokenAccounts.value[0].pubkey
    );
    
    console.log("Balance:", accountInfo.value.uiAmountString, "wZEC");
    console.log("Raw amount:", accountInfo.value.amount, "zatoshis");
    console.log("Token Account:", tokenAccounts.value[0].pubkey.toString());
    
  } catch (error) {
    console.error("Error checking balance:", error);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

