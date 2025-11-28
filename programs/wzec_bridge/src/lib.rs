use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

// Computation definition offsets for private balance operations
const COMP_DEF_OFFSET_MINT_PRIVATE: u32 = comp_def_offset("mint_private");
const COMP_DEF_OFFSET_TRANSFER_PRIVATE: u32 = comp_def_offset("transfer_private");
const COMP_DEF_OFFSET_BURN_PRIVATE: u32 = comp_def_offset("burn_private");
const COMP_DEF_OFFSET_GET_BALANCE: u32 = comp_def_offset("get_balance");
const COMP_DEF_OFFSET_FINALIZE_WITHDRAWAL: u32 = comp_def_offset("finalize_private_withdrawal");

declare_id!("HefTNtytDcQgSQmBpPuwjGipbVcJTMRHnppU9poWRXhD");

// Output types from encrypted instructions
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct EncryptedData {
    pub ciphertexts: Vec<[u8; 32]>,
    pub nonce: u128,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct MintPrivateOutput {
    pub field_0: EncryptedData,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TransferPrivateOutput {
    pub field_0: EncryptedData,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct GetBalanceOutput {
    pub field_0: EncryptedData,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct BurnPrivateOutput {
    pub field_0: EncryptedData,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct FinalizePrivateWithdrawalOutput {
    pub field_0: EncryptedData,
}

#[arcium_program]
pub mod wzec_bridge {
    use super::*;

    // ========================================================================
    // INITIALIZATION INSTRUCTIONS
    // ========================================================================

    /// Initialize the bridge configuration with enclave and MPC setup
    /// Note: This version uses PRIVATE encrypted balances, not public SPL tokens
    pub fn init_bridge(
        ctx: Context<InitBridge>,
        admin: Pubkey,
        enclave_authority: Pubkey,
        mpc_quorum_pubkeys: Vec<[u8; 32]>,
        bridge_ufvk: Vec<u8>,  // Full Viewing Key for enclave
    ) -> Result<()> {
        let bridge_config = &mut ctx.accounts.bridge_config;
        bridge_config.bump = ctx.bumps.bridge_config;
        bridge_config.admin = admin;
        bridge_config.enclave_authority = enclave_authority;
        
        // Initialize encrypted balance state (Arcium)
        bridge_config.arcium_balance_state = ctx.accounts.arcium_balance_state.key();
        bridge_config.balance_merkle_root = [0u8; 32];  // Empty tree initially
        bridge_config.total_supply_commitment = [0u8; 32];  // Zero supply
        
        bridge_config.withdrawal_nonce = 0;
        bridge_config.deposit_nonce = 0;
        bridge_config.mpc_quorum_pubkeys = mpc_quorum_pubkeys;
        bridge_config.bridge_ufvk = bridge_ufvk;

        msg!("Bridge initialized with PRIVATE encrypted balances");
        msg!("Arcium Balance State: {}", ctx.accounts.arcium_balance_state.key());
        msg!("Admin: {}", admin);
        msg!("Enclave Authority: {}", enclave_authority);
        msg!("Privacy: All balances encrypted in Arcium MPC");

        Ok(())
    }

    /// Initialize computation definitions (one-time setup for private operations)
    pub fn init_mint_private_comp_def(ctx: Context<InitMintPrivateCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, 0, None, None)?;
        Ok(())
    }

    pub fn init_transfer_private_comp_def(ctx: Context<InitTransferPrivateCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, 0, None, None)?;
        Ok(())
    }

    pub fn init_burn_private_comp_def(ctx: Context<InitBurnPrivateCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, 0, None, None)?;
        Ok(())
    }

    pub fn init_get_balance_comp_def(ctx: Context<InitGetBalanceCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, 0, None, None)?;
        Ok(())
    }

    // ========================================================================
    // DEPOSIT FLOW (ZEC → wZEC)
    // ========================================================================

    /// Step 1: User initiates deposit and receives a unique UA
    pub fn init_intent(
        ctx: Context<InitIntent>,
        diversifier_index: u32,
    ) -> Result<()> {
        let bridge_config = &mut ctx.accounts.bridge_config;
        let deposit_intent = &mut ctx.accounts.deposit_intent;
        
        // Assign unique deposit ID
        let deposit_id = bridge_config.deposit_nonce;
        bridge_config.deposit_nonce += 1;

        deposit_intent.bump = ctx.bumps.deposit_intent;
        deposit_intent.deposit_id = deposit_id;
        deposit_intent.user = ctx.accounts.user.key();
        deposit_intent.diversifier_index = diversifier_index;
        deposit_intent.status = DepositStatus::Pending as u8;
        deposit_intent.amount = 0;
        deposit_intent.note_commitment = [0; 32];
        deposit_intent.unified_address = [0; 256];
        deposit_intent.ua_length = 0;
        deposit_intent.created_at = Clock::get()?.unix_timestamp;

        emit!(DepositIntentCreated {
            deposit_id,
            user: ctx.accounts.user.key(),
            diversifier_index,
        });

        msg!("Deposit intent created: ID {}", deposit_id);
        msg!("User must fetch UA from MPC/API");

        Ok(())
    }

    /// Step 2: Update intent with the generated UA (called by MPC or API)
    pub fn set_unified_address(
        ctx: Context<SetUnifiedAddress>,
        deposit_id: u64,
        unified_address: Vec<u8>,
    ) -> Result<()> {
        require!(
            ctx.accounts.admin.key() == ctx.accounts.bridge_config.admin,
            BridgeError::Unauthorized
        );

        let deposit_intent = &mut ctx.accounts.deposit_intent;
        require!(
            deposit_intent.deposit_id == deposit_id,
            BridgeError::InvalidDepositId
        );
        require!(
            unified_address.len() <= 256,
            BridgeError::InvalidAddress
        );

        let ua_len = unified_address.len();
        deposit_intent.unified_address[..ua_len].copy_from_slice(&unified_address);
        deposit_intent.ua_length = ua_len as u16;
        deposit_intent.status = DepositStatus::AddressGenerated as u8;

        emit!(UnifiedAddressSet {
            deposit_id,
            ua_length: ua_len as u16,
        });

        msg!("UA set for deposit {}", deposit_id);

        Ok(())
    }

    /// Step 3: Mint PRIVATE wZEC after enclave attestation (fully encrypted)
    /// This updates the user's encrypted balance in Arcium, not a public token
    pub fn mint_private_with_attestation(
        ctx: Context<MintPrivateWithAttestation>,
        computation_offset: u64,
        deposit_id: u64,
        encrypted_attestation: [u8; 32],  // Encrypted attestation from enclave
        encrypted_user_key: [u8; 32],     // User's encryption key
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        let deposit_intent = &mut ctx.accounts.deposit_intent;
        
        require!(
            deposit_intent.deposit_id == deposit_id,
            BridgeError::InvalidDepositId
        );
        require!(
            deposit_intent.status == DepositStatus::AddressGenerated as u8,
            BridgeError::InvalidDepositStatus
        );

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        // Queue confidential computation to verify attestation AND mint private balance
        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::EncryptedU8(encrypted_attestation),
            Argument::EncryptedU8(encrypted_user_key),
            Argument::PlaintextU64(deposit_id),
            Argument::PlaintextBytes(deposit_intent.user.to_bytes().to_vec()),  // User pubkey
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![MintPrivateCallback::callback_ix(&[])],
            1,
        )?;

        msg!("Private mint queued for deposit {} (fully encrypted)", deposit_id);

        Ok(())
    }

    /// Callback after attestation is verified - update PRIVATE encrypted balance
    /// NO PUBLIC TOKEN MINTING - balance stays encrypted in Arcium
    #[arcium_callback(encrypted_ix = "mint_private")]
    pub fn mint_private_callback(
        ctx: Context<MintPrivateCallback>,
        output: ComputationOutputs<MintPrivateOutput>,
    ) -> Result<()> {
        let balance_update = match output {
            ComputationOutputs::Success(MintPrivateOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::AttestationFailed.into()),
        };

        let deposit_intent = &mut ctx.accounts.deposit_intent;
        let bridge_config = &mut ctx.accounts.bridge_config;
        let claim_tracker = &mut ctx.accounts.claim_tracker;

        // Mark note as claimed to prevent double-spend
        claim_tracker.bump = ctx.bumps.claim_tracker;
        claim_tracker.note_commitment = deposit_intent.note_commitment;
        claim_tracker.claimed_at = Clock::get()?.unix_timestamp;
        claim_tracker.deposit_id = deposit_intent.deposit_id;

        // Update on-chain commitment to encrypted balance tree
        // (The actual balance is encrypted in Arcium, this is just a commitment)
        bridge_config.balance_merkle_root = balance_update.ciphertexts[0];
        bridge_config.total_supply_commitment = balance_update.ciphertexts[1];

        // Update deposit status
        deposit_intent.status = DepositStatus::Minted as u8;

        emit!(PrivateBalanceMinted {
            deposit_id: deposit_intent.deposit_id,
            user: deposit_intent.user,
            // NO AMOUNT - keep it private!
            balance_commitment: balance_update.ciphertexts[0],
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Private balance updated for deposit {} (amount hidden)", deposit_intent.deposit_id);

        Ok(())
    }

    // ========================================================================
    // PRIVATE TRANSFER (User-to-user encrypted transfer)
    // ========================================================================

    pub fn transfer_private(
        ctx: Context<TransferPrivate>,
        computation_offset: u64,
        encrypted_amount: [u8; 32],
        encrypted_sender_proof: [u8; 32],
        receiver_pubkey: Pubkey,
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        require!(
            ctx.accounts.sender.key() != receiver_pubkey,
            BridgeError::InvalidAddress
        );

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        // Queue confidential transfer computation
        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::EncryptedU8(encrypted_amount),
            Argument::EncryptedU8(encrypted_sender_proof),
            Argument::PlaintextBytes(ctx.accounts.sender.key().to_bytes().to_vec()),
            Argument::PlaintextBytes(receiver_pubkey.to_bytes().to_vec()),
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![TransferPrivateCallback::callback_ix(&[])],
            1,
        )?;

        msg!("Private transfer queued (amount hidden)");

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "transfer_private")]
    pub fn transfer_private_callback(
        ctx: Context<TransferPrivateCallback>,
        output: ComputationOutputs<TransferPrivateOutput>,
    ) -> Result<()> {
        let transfer_result = match output {
            ComputationOutputs::Success(TransferPrivateOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::ComputationFailed.into()),
        };

        // Update balance commitment
        let bridge_config = &mut ctx.accounts.bridge_config;
        bridge_config.balance_merkle_root = transfer_result.ciphertexts[0];

        emit!(PrivateTransferCompleted {
            // No sender/receiver/amount - all private!
            balance_commitment: transfer_result.ciphertexts[0],
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Private transfer completed (details hidden)");

        Ok(())
    }

    // ========================================================================
    // GET BALANCE (User queries their own encrypted balance)
    // ========================================================================

    pub fn get_balance(
        ctx: Context<GetBalance>,
        computation_offset: u64,
        encrypted_user_key: [u8; 32],
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        // Queue balance query (encrypted)
        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::EncryptedU8(encrypted_user_key),
            Argument::PlaintextBytes(ctx.accounts.user.key().to_bytes().to_vec()),
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![GetBalanceCallback::callback_ix(&[])],
            1,
        )?;

        msg!("Balance query queued for user");

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "get_balance")]
    pub fn get_balance_callback(
        ctx: Context<GetBalanceCallback>,
        output: ComputationOutputs<GetBalanceOutput>,
    ) -> Result<()> {
        let encrypted_balance = match output {
            ComputationOutputs::Success(GetBalanceOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::ComputationFailed.into()),
        };

        // Return encrypted balance (user decrypts client-side)
        emit!(BalanceQueried {
            user: ctx.accounts.user.key(),
            encrypted_balance: encrypted_balance.ciphertexts[0],
            nonce: encrypted_balance.nonce.to_le_bytes(),
        });

        msg!("Balance returned (encrypted)");

        Ok(())
    }

    // ========================================================================
    // REDEMPTION FLOW (wZEC → ZEC)
    // ========================================================================

    /// Burn PRIVATE wZEC and create encrypted withdrawal intent
    /// Amount and destination are fully encrypted
    pub fn burn_private_for_withdrawal(
        ctx: Context<BurnPrivateForWithdrawal>,
        computation_offset: u64,
        encrypted_amount: [u8; 32],
        encrypted_zcash_address: [u8; 32],
        encrypted_user_proof: [u8; 32],
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        // Get burn ID and increment
        let bridge_config = &mut ctx.accounts.bridge_config;
        let burn_id = bridge_config.withdrawal_nonce;
        bridge_config.withdrawal_nonce += 1;

        // Queue confidential burn (checks balance, creates burn intent, all encrypted)
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        
        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::EncryptedU8(encrypted_amount),
            Argument::EncryptedU8(encrypted_zcash_address),
            Argument::EncryptedU8(encrypted_user_proof),
            Argument::PlaintextU64(burn_id),
            Argument::PlaintextBytes(ctx.accounts.user.key().to_bytes().to_vec()),
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![BurnPrivateCallback::callback_ix(&[])],
            1,
        )?;

        msg!("Private burn queued: ID {} (amount and destination hidden)", burn_id);

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "burn_private")]
    pub fn burn_private_callback(
        ctx: Context<BurnPrivateCallback>,
        output: ComputationOutputs<BurnPrivateOutput>,
    ) -> Result<()> {
        let burn_result = match output {
            ComputationOutputs::Success(BurnPrivateOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::InsufficientBalance.into()),
        };

        // Update balance commitment after burn
        let bridge_config = &mut ctx.accounts.bridge_config;
        bridge_config.balance_merkle_root = burn_result.ciphertexts[0];
        bridge_config.total_supply_commitment = burn_result.ciphertexts[1];

        emit!(PrivateBurnCompleted {
            burn_id: 0, // Kept private
            encrypted_burn_data: burn_result.ciphertexts[2],  // Contains amount + address
            balance_commitment: burn_result.ciphertexts[0],
            nonce: burn_result.nonce.to_le_bytes(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Private burn completed (details hidden)");

        Ok(())
    }

    /// MPC nodes call this after broadcasting Zcash TX (finalization still encrypted)
    pub fn finalize_private_withdrawal(
        ctx: Context<FinalizePrivateWithdrawal>,
        computation_offset: u64,
        encrypted_burn_id: [u8; 32],
        encrypted_txid: [u8; 32],
        encrypted_mpc_proof: [u8; 32],
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::EncryptedU8(encrypted_burn_id),
            Argument::EncryptedU8(encrypted_txid),
            Argument::EncryptedU8(encrypted_mpc_proof),
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![FinalizePrivateWithdrawalCallback::callback_ix(&[])],
            1,
        )?;

        msg!("Private withdrawal finalization queued (encrypted)");

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "finalize_private_withdrawal")]
    pub fn finalize_private_withdrawal_callback(
        ctx: Context<FinalizePrivateWithdrawalCallback>,
        output: ComputationOutputs<FinalizePrivateWithdrawalOutput>,
    ) -> Result<()> {
        let finalization = match output {
            ComputationOutputs::Success(FinalizePrivateWithdrawalOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::ComputationFailed.into()),
        };

        emit!(PrivateWithdrawalFinalized {
            encrypted_burn_id: finalization.ciphertexts[0],
            encrypted_txid: finalization.ciphertexts[1],
            nonce: finalization.nonce.to_le_bytes(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Private withdrawal finalized (all details hidden)");

        Ok(())
    }
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

#[account]
pub struct BridgeConfig {
    pub bump: u8,
    pub admin: Pubkey,
    pub enclave_authority: Pubkey,
    
    // PRIVATE BALANCE STATE (no more public SPL mint!)
    pub arcium_balance_state: Pubkey,      // Arcium account holding encrypted balances
    pub balance_merkle_root: [u8; 32],     // Commitment to balance tree
    pub total_supply_commitment: [u8; 32], // Commitment to total supply (encrypted)
    
    pub withdrawal_nonce: u64,
    pub deposit_nonce: u64,
    pub mpc_quorum_pubkeys: Vec<[u8; 32]>,
    pub bridge_ufvk: Vec<u8>,  // Full Viewing Key for deposit detection
}

impl BridgeConfig {
    // Updated size calculation (removed mint fields, added Arcium fields)
    pub const MAX_SIZE: usize = 8 + 1 + 32 + 32 + 32 + 32 + 32 + 8 + 8 + (4 + 32 * 10) + (4 + 512);
}

#[account]
pub struct DepositIntent {
    pub bump: u8,
    pub deposit_id: u64,
    pub user: Pubkey,
    pub diversifier_index: u32,
    pub status: u8,
    pub amount: u64,
    pub note_commitment: [u8; 32],
    pub unified_address: [u8; 256],
    pub ua_length: u16,
    pub created_at: i64,
}

impl DepositIntent {
    pub const MAX_SIZE: usize = 8 + 1 + 8 + 32 + 4 + 1 + 8 + 32 + 256 + 2 + 8;
}

#[account]
pub struct ClaimTracker {
    pub bump: u8,
    pub note_commitment: [u8; 32],
    pub claimed_at: i64,
    pub deposit_id: u64,
}

impl ClaimTracker {
    pub const SIZE: usize = 8 + 1 + 32 + 8 + 8;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum DepositStatus {
    Pending = 0,
    AddressGenerated = 1,
    Detected = 2,
    Minted = 3,
    Failed = 4,
}

// ============================================================================
// CONTEXTS
// ============================================================================

#[derive(Accounts)]
#[instruction(admin: Pubkey, enclave_authority: Pubkey, mpc_quorum_pubkeys: Vec<[u8; 32]>, bridge_ufvk: Vec<u8>)]
pub struct InitBridge<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = BridgeConfig::MAX_SIZE,
        seeds = [b"bridge-config"],
        bump
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,

    /// Arcium account for encrypted balance state
    /// CHECK: This will be initialized by Arcium
    #[account(
        mut,
        seeds = [b"arcium-balance-state"],
        bump
    )]
    pub arcium_balance_state: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(diversifier_index: u32)]
pub struct InitIntent<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(
        init,
        payer = user,
        space = DepositIntent::MAX_SIZE,
        seeds = [
            b"deposit-intent",
            user.key().as_ref(),
            &bridge_config.deposit_nonce.to_le_bytes()
        ],
        bump
    )]
    pub deposit_intent: Account<'info, DepositIntent>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(deposit_id: u64, unified_address: Vec<u8>)]
pub struct SetUnifiedAddress<'info> {
    pub admin: Signer<'info>,

    #[account(
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(
        mut,
        seeds = [
            b"deposit-intent",
            deposit_intent.user.as_ref(),
            &deposit_id.to_le_bytes()
        ],
        bump = deposit_intent.bump,
    )]
    pub deposit_intent: Account<'info, DepositIntent>,
}

#[queue_computation_accounts("mint_private", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, deposit_id: u64)]
pub struct MintPrivateWithAttestation<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,

    #[account(
        mut,
        seeds = [
            b"deposit-intent",
            deposit_intent.user.as_ref(),
            &deposit_id.to_le_bytes()
        ],
        bump = deposit_intent.bump,
    )]
    pub deposit_intent: Box<Account<'info, DepositIntent>>,

    // Arcium accounts
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Box<Account<'info, SignerAccount>>,
    
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    
    #[account(mut, address = derive_mempool_pda!())]
    /// CHECK: checked by arcium
    pub mempool_account: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_execpool_pda!())]
    /// CHECK: checked by arcium
    pub executing_pool: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    /// CHECK: checked by arcium
    pub computation_account: UncheckedAccount<'info>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_VERIFY_ATTESTATION))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(mut, address = derive_cluster_pda!(mxe_account, BridgeError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("mint_private")]
#[derive(Accounts)]
pub struct MintPrivateCallback<'info> {
    #[account(mut)]
    pub deposit_intent: Box<Account<'info, DepositIntent>>,

    #[account(
        mut,
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,

    #[account(
        init,
        payer = payer,
        space = ClaimTracker::SIZE,
        seeds = [
            b"claim-tracker",
            deposit_intent.note_commitment.as_ref()
        ],
        bump
    )]
    pub claim_tracker: Box<Account<'info, ClaimTracker>>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_MINT_PRIVATE))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

#[queue_computation_accounts("transfer_private", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct TransferPrivate<'info> {
    #[account(mut)]
    pub sender: Signer<'info>,

    #[account(
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,

    // Arcium accounts
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Box<Account<'info, SignerAccount>>,
    
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    
    #[account(mut, address = derive_mempool_pda!())]
    /// CHECK: checked by arcium
    pub mempool_account: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_execpool_pda!())]
    /// CHECK: checked by arcium
    pub executing_pool: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    /// CHECK: checked by arcium
    pub computation_account: UncheckedAccount<'info>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_TRANSFER_PRIVATE))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(mut, address = derive_cluster_pda!(mxe_account, BridgeError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("transfer_private")]
#[derive(Accounts)]
pub struct TransferPrivateCallback<'info> {
    #[account(
        mut,
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,

    pub arcium_program: Program<'info, Arcium>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_TRANSFER_PRIVATE))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

#[queue_computation_accounts("get_balance", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct GetBalance<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,

    // Arcium accounts
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Box<Account<'info, SignerAccount>>,
    
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    
    #[account(mut, address = derive_mempool_pda!())]
    /// CHECK: checked by arcium
    pub mempool_account: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_execpool_pda!())]
    /// CHECK: checked by arcium
    pub executing_pool: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    /// CHECK: checked by arcium
    pub computation_account: UncheckedAccount<'info>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_GET_BALANCE))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(mut, address = derive_cluster_pda!(mxe_account, BridgeError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("get_balance")]
#[derive(Accounts)]
pub struct GetBalanceCallback<'info> {
    pub user: AccountInfo<'info>,

    pub arcium_program: Program<'info, Arcium>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_GET_BALANCE))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

#[queue_computation_accounts("burn_private", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct BurnPrivateForWithdrawal<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,

    // Arcium accounts
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Box<Account<'info, SignerAccount>>,
    
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    
    #[account(mut, address = derive_mempool_pda!())]
    /// CHECK: checked by arcium
    pub mempool_account: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_execpool_pda!())]
    /// CHECK: checked by arcium
    pub executing_pool: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    /// CHECK: checked by arcium
    pub computation_account: UncheckedAccount<'info>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_BURN_PRIVATE))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(mut, address = derive_cluster_pda!(mxe_account, BridgeError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("burn_private")]
#[derive(Accounts)]
pub struct BurnPrivateCallback<'info> {
    #[account(
        mut,
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,

    pub arcium_program: Program<'info, Arcium>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_BURN_PRIVATE))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

#[queue_computation_accounts("finalize_private_withdrawal", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct FinalizePrivateWithdrawal<'info> {
    #[account(mut)]
    pub mpc_node: Signer<'info>,

    #[account(
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,

    // Arcium accounts
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Box<Account<'info, SignerAccount>>,
    
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    
    #[account(mut, address = derive_mempool_pda!())]
    /// CHECK: checked by arcium
    pub mempool_account: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_execpool_pda!())]
    /// CHECK: checked by arcium
    pub executing_pool: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    /// CHECK: checked by arcium
    pub computation_account: UncheckedAccount<'info>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_FINALIZE_WITHDRAWAL))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(mut, address = derive_cluster_pda!(mxe_account, BridgeError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("finalize_private_withdrawal")]
#[derive(Accounts)]
pub struct FinalizePrivateWithdrawalCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_FINALIZE_WITHDRAWAL))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

// Computation definition initialization contexts
#[init_computation_definition_accounts("mint_private", payer)]
#[derive(Accounts)]
pub struct InitMintPrivateCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by arcium
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("transfer_private", payer)]
#[derive(Accounts)]
pub struct InitTransferPrivateCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by arcium
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("burn_private", payer)]
#[derive(Accounts)]
pub struct InitBurnPrivateCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by arcium
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("get_balance", payer)]
#[derive(Accounts)]
pub struct InitGetBalanceCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by arcium
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

// ============================================================================
// EVENTS
// ============================================================================

#[event]
pub struct DepositIntentCreated {
    pub deposit_id: u64,
    pub user: Pubkey,
    pub diversifier_index: u32,
}

#[event]
pub struct UnifiedAddressSet {
    pub deposit_id: u64,
    pub ua_length: u16,
}

#[event]
pub struct PrivateBalanceMinted {
    pub deposit_id: u64,
    pub user: Pubkey,
    pub balance_commitment: [u8; 32],  // Merkle root, NOT the amount!
    pub timestamp: i64,
}

#[event]
pub struct PrivateTransferCompleted {
    pub balance_commitment: [u8; 32],
    pub timestamp: i64,
    // NO sender, receiver, or amount - fully private!
}

#[event]
pub struct PrivateBurnCompleted {
    pub burn_id: u64,
    pub encrypted_burn_data: [u8; 32],
    pub balance_commitment: [u8; 32],
    pub nonce: [u8; 16],
    pub timestamp: i64,
}

#[event]
pub struct PrivateWithdrawalFinalized {
    pub encrypted_burn_id: [u8; 32],
    pub encrypted_txid: [u8; 32],
    pub nonce: [u8; 16],
    pub timestamp: i64,
}

#[event]
pub struct BalanceQueried {
    pub user: Pubkey,
    pub encrypted_balance: [u8; 32],
    pub nonce: [u8; 16],
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum BridgeError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Invalid address format")]
    InvalidAddress,
    #[msg("Invalid deposit ID")]
    InvalidDepositId,
    #[msg("Invalid deposit status")]
    InvalidDepositStatus,
    #[msg("Attestation verification failed")]
    AttestationFailed,
    #[msg("Note already claimed (double-spend prevented)")]
    NoteAlreadyClaimed,
    #[msg("Confidential computation failed")]
    ComputationFailed,
    #[msg("Cluster not set")]
    ClusterNotSet,
    #[msg("Insufficient encrypted balance")]
    InsufficientBalance,
    #[msg("Invalid encryption key")]
    InvalidEncryptionKey,
    #[msg("Balance proof verification failed")]
    InvalidBalanceProof,
    #[msg("Encrypted state corrupted")]
    CorruptedState,
}