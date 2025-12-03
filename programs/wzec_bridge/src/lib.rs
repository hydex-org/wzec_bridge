use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, MintTo, Burn};
use arcium_anchor::prelude::*;

// Computation definition offsets - only 3 now
const COMP_DEF_OFFSET_VERIFY_ATTESTATION: u32 = comp_def_offset("verify_attestation");
const COMP_DEF_OFFSET_CREATE_BURN_INTENT: u32 = comp_def_offset("create_burn_intent");
const COMP_DEF_OFFSET_UPDATE_BURN_INTENT: u32 = comp_def_offset("update_burn_intent");

declare_id!("HefTNtytDcQgSQmBpPuwjGipbVcJTMRHnppU9poWRXhD");

#[arcium_program]
pub mod wzec_bridge {
    use super::*;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    /// Initialize the bridge with admin, enclave authority, and sZEC mint
    pub fn init_bridge(
        ctx: Context<InitBridge>,
        enclave_authority: Pubkey,
        mpc_authority: Pubkey,
    ) -> Result<()> {
        let config = &mut ctx.accounts.bridge_config;
        config.bump = ctx.bumps.bridge_config;
        config.admin = ctx.accounts.admin.key();
        config.enclave_authority = enclave_authority;
        config.mpc_authority = mpc_authority;
        config.szec_mint = ctx.accounts.szec_mint.key();
        config.deposit_nonce = 0;
        config.burn_nonce = 0;
        config.total_minted = 0;
        config.total_burned = 0;
        msg!("Bridge initialized with sZEC mint: {}", config.szec_mint);
        Ok(())
    }

    /// Initialize computation definitions (call once per instruction)
    pub fn init_verify_attestation_comp_def(ctx: Context<InitVerifyAttestationCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, 0, None, None)?;
        Ok(())
    }

    pub fn init_create_burn_intent_comp_def(ctx: Context<InitCreateBurnIntentCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, 0, None, None)?;
        Ok(())
    }

    pub fn init_update_burn_intent_comp_def(ctx: Context<InitUpdateBurnIntentCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, 0, None, None)?;
        Ok(())
    }

    // ========================================================================
    // DEPOSIT FLOW
    // ========================================================================

    /// Step 1: User creates deposit intent, gets unique deposit_id
    pub fn init_deposit_intent(ctx: Context<InitDepositIntent>) -> Result<()> {
        let config = &mut ctx.accounts.bridge_config;
        let intent = &mut ctx.accounts.deposit_intent;
        
        let deposit_id = config.deposit_nonce;
        config.deposit_nonce += 1;
        
        intent.bump = ctx.bumps.deposit_intent;
        intent.deposit_id = deposit_id;
        intent.user = ctx.accounts.user.key();
        intent.status = DepositStatus::Pending as u8;
        intent.amount = 0;
        intent.note_commitment = [0; 32];
        intent.unified_address = [0; 256];
        intent.ua_length = 0;
        intent.created_at = Clock::get()?.unix_timestamp;
        intent.updated_at = intent.created_at;
        
        emit!(DepositIntentCreated {
            deposit_id,
            user: intent.user,
        });
        
        Ok(())
    }

    /// Step 2: Backend sets the UA after enclave generates it
    pub fn set_unified_address(
        ctx: Context<SetUnifiedAddress>,
        unified_address: Vec<u8>,
    ) -> Result<()> {
        // Only enclave authority can set UA
        require!(
            ctx.accounts.authority.key() == ctx.accounts.bridge_config.enclave_authority,
            BridgeError::Unauthorized
        );
        
        let intent = &mut ctx.accounts.deposit_intent;
        require!(intent.status == DepositStatus::Pending as u8, BridgeError::InvalidStatus);
        require!(unified_address.len() <= 256, BridgeError::InvalidAddress);
        
        let ua_len = unified_address.len();
        intent.unified_address[..ua_len].copy_from_slice(&unified_address);
        intent.ua_length = ua_len as u16;
        intent.status = DepositStatus::AddressGenerated as u8;
        intent.updated_at = Clock::get()?.unix_timestamp;
        
        emit!(UnifiedAddressSet {
            deposit_id: intent.deposit_id,
            ua_length: ua_len as u16,
        });
        
        Ok(())
    }

    /// Step 3: After ZEC detected, submit attestation for verification
    /// This queues the Arcium verify_attestation computation
    pub fn mint_with_attestation(
        ctx: Context<MintWithAttestation>,
        computation_offset: u64,
        encrypted_attestation: Vec<[u8; 32]>,
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        let intent = &ctx.accounts.deposit_intent;
        require!(
            intent.status == DepositStatus::AddressGenerated as u8,
            BridgeError::InvalidStatus
        );
        
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        
        // Build Arcium arguments
        let mut args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
        ];
        for ciphertext in encrypted_attestation.iter() {
            args.push(Argument::EncryptedU8(*ciphertext));
        }
        
        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![VerifyAttestationCallback::callback_ix(&[])],
            1,
        )?;
        
        Ok(())
    }

    /// Callback: Arcium returns verification result, mint if valid
    #[arcium_callback(encrypted_ix = "verify_attestation")]
    pub fn verify_attestation_callback(
        ctx: Context<VerifyAttestationCallback>,
        output: ComputationOutputs<VerifyAttestationOutput>,
    ) -> Result<()> {
        // Extract the boolean result
        let is_valid = match output {
            ComputationOutputs::Success(VerifyAttestationOutput { field_0 }) => {
                // Interpret ciphertext as boolean (non-zero = true)
                !field_0.ciphertexts.is_empty() && field_0.ciphertexts[0][0] != 0
            }
            _ => false,
        };
        
        require!(is_valid, BridgeError::AttestationFailed);
        
        let intent = &mut ctx.accounts.deposit_intent;
        let config = &mut ctx.accounts.bridge_config;
        
        // Create claim tracker to prevent double-minting
        let claim_tracker = &mut ctx.accounts.claim_tracker;
        claim_tracker.bump = ctx.bumps.claim_tracker;
        claim_tracker.note_commitment = intent.note_commitment;
        claim_tracker.deposit_id = intent.deposit_id;
        claim_tracker.claimed_at = Clock::get()?.unix_timestamp;
        
        // Mint sZEC to user
        let mint_amount = intent.amount;
        let seeds = &[b"mint-authority".as_ref(), &[ctx.bumps.mint_authority]];
        let signer_seeds = &[&seeds[..]];
        
        token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.szec_mint.to_account_info(),
                    to: ctx.accounts.user_token_account.to_account_info(),
                    authority: ctx.accounts.mint_authority.to_account_info(),
                },
                signer_seeds,
            ),
            mint_amount,
        )?;
        
        // Update state
        intent.status = DepositStatus::Minted as u8;
        intent.updated_at = Clock::get()?.unix_timestamp;
        config.total_minted += mint_amount;
        
        emit!(DepositMinted {
            deposit_id: intent.deposit_id,
            user: intent.user,
            amount: mint_amount,
        });
        
        Ok(())
    }

    // ========================================================================
    // WITHDRAWAL FLOW
    // ========================================================================

    /// Step 1: User burns sZEC and creates encrypted burn intent
    pub fn burn_for_withdrawal(
        ctx: Context<BurnForWithdrawal>,
        computation_offset: u64,
        amount: u64,
        encrypted_burn_input: Vec<[u8; 32]>, // Contains encrypted zcash_address
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        let config = &mut ctx.accounts.bridge_config;
        let burn_intent = &mut ctx.accounts.burn_intent;
        
        // Assign burn_id
        let burn_id = config.burn_nonce;
        config.burn_nonce += 1;
        
        burn_intent.bump = ctx.bumps.burn_intent;
        burn_intent.burn_id = burn_id;
        burn_intent.user = ctx.accounts.user.key();
        burn_intent.amount = amount;
        burn_intent.status = BurnStatus::Pending as u8;
        burn_intent.encrypted_data = [0; 512]; // Will be filled by callback
        burn_intent.solana_burn_txid = [0; 64];
        burn_intent.created_at = Clock::get()?.unix_timestamp;
        
        // Burn sZEC from user
        token::burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.szec_mint.to_account_info(),
                    from: ctx.accounts.user_token_account.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )?;
        
        config.total_burned += amount;
        
        // Queue Arcium create_burn_intent
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        
        let mut args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::PlaintextU64(burn_id), // Pass burn_id to Arcium
        ];
        for ciphertext in encrypted_burn_input.iter() {
            args.push(Argument::EncryptedU8(*ciphertext));
        }
        
        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![CreateBurnIntentCallback::callback_ix(&[])],
            1,
        )?;
        
        emit!(BurnInitiated {
            burn_id,
            user: ctx.accounts.user.key(),
            amount,
        });
        
        Ok(())
    }

    /// Callback: Store encrypted burn intent data
    #[arcium_callback(encrypted_ix = "create_burn_intent")]
    pub fn create_burn_intent_callback(
        ctx: Context<CreateBurnIntentCallback>,
        output: ComputationOutputs<CreateBurnIntentOutput>,
    ) -> Result<()> {
        let burn_result = match output {
            ComputationOutputs::Success(CreateBurnIntentOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::ComputationFailed.into()),
        };
        
        let burn_intent = &mut ctx.accounts.burn_intent;
        
        // Store encrypted data (MPC nodes will read this)
        let mut offset = 0;
        for ct in burn_result.ciphertexts.iter() {
            if offset + 32 <= burn_intent.encrypted_data.len() {
                burn_intent.encrypted_data[offset..offset + 32].copy_from_slice(ct);
                offset += 32;
            }
        }
        
        burn_intent.status = BurnStatus::Processing as u8;
        burn_intent.updated_at = Clock::get()?.unix_timestamp;
        
        emit!(BurnIntentCreated {
            burn_id: burn_intent.burn_id,
            user: burn_intent.user,
        });
        
        Ok(())
    }

    /// Step 2: MPC finalizes after Zcash TX is mined
    pub fn finalize_withdrawal(
        ctx: Context<FinalizeWithdrawal>,
        computation_offset: u64,
        encrypted_update: Vec<[u8; 32]>, // Contains zcash_txid and new_status
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        // Only MPC authority can finalize
        require!(
            ctx.accounts.authority.key() == ctx.accounts.bridge_config.mpc_authority,
            BridgeError::Unauthorized
        );
        
        let burn_intent = &ctx.accounts.burn_intent;
        require!(
            burn_intent.status == BurnStatus::Processing as u8,
            BridgeError::InvalidStatus
        );
        
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        
        let mut args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
        ];
        for ciphertext in encrypted_update.iter() {
            args.push(Argument::EncryptedU8(*ciphertext));
        }
        
        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![UpdateBurnIntentCallback::callback_ix(&[])],
            1,
        )?;
        
        Ok(())
    }

    /// Callback: Update burn intent with Zcash TXID
    #[arcium_callback(encrypted_ix = "update_burn_intent")]
    pub fn update_burn_intent_callback(
        ctx: Context<UpdateBurnIntentCallback>,
        output: ComputationOutputs<UpdateBurnIntentOutput>,
    ) -> Result<()> {
        let update_result = match output {
            ComputationOutputs::Success(UpdateBurnIntentOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::ComputationFailed.into()),
        };
        
        let burn_intent = &mut ctx.accounts.burn_intent;
        
        // Update encrypted data with new state (includes zcash_txid)
        let mut offset = 0;
        for ct in update_result.ciphertexts.iter() {
            if offset + 32 <= burn_intent.encrypted_data.len() {
                burn_intent.encrypted_data[offset..offset + 32].copy_from_slice(ct);
                offset += 32;
            }
        }
        
        burn_intent.status = BurnStatus::Completed as u8;
        burn_intent.updated_at = Clock::get()?.unix_timestamp;
        
        emit!(WithdrawalFinalized {
            burn_id: burn_intent.burn_id,
        });
        
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
    pub enclave_authority: Pubkey,  // Can set UAs
    pub mpc_authority: Pubkey,      // Can finalize withdrawals
    pub szec_mint: Pubkey,
    pub deposit_nonce: u64,
    pub burn_nonce: u64,
    pub total_minted: u64,
    pub total_burned: u64,
}

#[account]
pub struct DepositIntent {
    pub bump: u8,
    pub deposit_id: u64,
    pub user: Pubkey,
    pub status: u8,
    pub amount: u64,
    pub note_commitment: [u8; 32],
    pub unified_address: [u8; 256],
    pub ua_length: u16,
    pub created_at: i64,
    pub updated_at: i64,
}

#[account]
pub struct BurnIntent {
    pub bump: u8,
    pub burn_id: u64,
    pub user: Pubkey,
    pub amount: u64,
    pub status: u8,
    pub encrypted_data: [u8; 512], // Arcium-encrypted burn intent
    pub solana_burn_txid: [u8; 64],
    pub created_at: i64,
    pub updated_at: i64,
}

#[account]
pub struct ClaimTracker {
    pub bump: u8,
    pub note_commitment: [u8; 32],
    pub deposit_id: u64,
    pub claimed_at: i64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum DepositStatus {
    Pending = 0,
    AddressGenerated = 1,
    Detected = 2,
    Minted = 3,
    Failed = 4,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum BurnStatus {
    Pending = 0,
    Processing = 1,
    Completed = 2,
    Failed = 3,
}

// ============================================================================
// EVENTS
// ============================================================================

#[event]
pub struct DepositIntentCreated { pub deposit_id: u64, pub user: Pubkey }
#[event]
pub struct UnifiedAddressSet { pub deposit_id: u64, pub ua_length: u16 }
#[event]
pub struct DepositMinted { pub deposit_id: u64, pub user: Pubkey, pub amount: u64 }
#[event]
pub struct BurnInitiated { pub burn_id: u64, pub user: Pubkey, pub amount: u64 }
#[event]
pub struct BurnIntentCreated { pub burn_id: u64, pub user: Pubkey }
#[event]
pub struct WithdrawalFinalized { pub burn_id: u64 }

#[error_code]
pub enum BridgeError {
    #[msg("Unauthorized")] Unauthorized,
    #[msg("Invalid status for this operation")] InvalidStatus,
    #[msg("Invalid address")] InvalidAddress,
    #[msg("Attestation verification failed")] AttestationFailed,
    #[msg("Computation failed")] ComputationFailed,
    #[msg("Note already claimed")] NoteAlreadyClaimed,
}

// ============================================================================
// SIZE IMPLEMENTATIONS
// ============================================================================

impl BridgeConfig {
    pub const SIZE: usize = 8 + 1 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 8;
}

impl DepositIntent {
    pub const SIZE: usize = 8 + 1 + 8 + 32 + 1 + 8 + 32 + 256 + 2 + 8 + 8;
}

impl BurnIntent {
    pub const SIZE: usize = 8 + 1 + 8 + 32 + 8 + 1 + 512 + 64 + 8 + 8;
}

impl ClaimTracker {
    pub const SIZE: usize = 8 + 1 + 32 + 8 + 8;
}

// ============================================================================
// INITIALIZATION CONTEXTS
// ============================================================================

#[derive(Accounts)]
pub struct InitBridge<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        init,
        payer = admin,
        space = BridgeConfig::SIZE,
        seeds = [b"bridge-config"],
        bump
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,
    #[account(
        init,
        payer = admin,
        mint::decimals = 8,
        mint::authority = mint_authority,
        seeds = [b"szec-mint"],
        bump
    )]
    pub szec_mint: Box<Account<'info, Mint>>,
    /// CHECK: PDA for mint authority
    #[account(seeds = [b"mint-authority"], bump)]
    pub mint_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[init_computation_definition_accounts("verify_attestation", payer)]
#[derive(Accounts)]
pub struct InitVerifyAttestationCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by arcium
    #[account(mut)]
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("create_burn_intent", payer)]
#[derive(Accounts)]
pub struct InitCreateBurnIntentCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by arcium
    #[account(mut)]
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("update_burn_intent", payer)]
#[derive(Accounts)]
pub struct InitUpdateBurnIntentCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by arcium
    #[account(mut)]
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

// ============================================================================
// DEPOSIT FLOW CONTEXTS
// ============================================================================

#[derive(Accounts)]
pub struct InitDepositIntent<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        mut,
        seeds = [b"bridge-config"],
        bump = bridge_config.bump
    )]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,
    #[account(
        init,
        payer = user,
        space = DepositIntent::SIZE,
        seeds = [b"deposit-intent", user.key().as_ref(), &bridge_config.deposit_nonce.to_le_bytes()],
        bump
    )]
    pub deposit_intent: Box<Account<'info, DepositIntent>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetUnifiedAddress<'info> {
    pub authority: Signer<'info>,
    #[account(seeds = [b"bridge-config"], bump = bridge_config.bump)]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,
    #[account(
        mut,
        seeds = [b"deposit-intent", deposit_intent.user.as_ref(), &deposit_intent.deposit_id.to_le_bytes()],
        bump = deposit_intent.bump
    )]
    pub deposit_intent: Box<Account<'info, DepositIntent>>,
}

#[queue_computation_accounts("verify_attestation", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct MintWithAttestation<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(seeds = [b"bridge-config"], bump = bridge_config.bump)]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,
    #[account(
        mut,
        seeds = [b"deposit-intent", deposit_intent.user.as_ref(), &deposit_intent.deposit_id.to_le_bytes()],
        bump = deposit_intent.bump
    )]
    pub deposit_intent: Box<Account<'info, DepositIntent>>,
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init_if_needed, space = 9, payer = payer, seeds = [&SIGN_PDA_SEED], bump, address = derive_sign_pda!())]
    pub sign_pda_account: Box<Account<'info, SignerAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by arcium
    #[account(mut, address = derive_mempool_pda!())]
    pub mempool_account: UncheckedAccount<'info>,
    /// CHECK: checked by arcium
    #[account(mut, address = derive_execpool_pda!())]
    pub executing_pool: UncheckedAccount<'info>,
    /// CHECK: checked by arcium
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_VERIFY_ATTESTATION))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, BridgeError::ComputationFailed))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("verify_attestation")]
#[derive(Accounts)]
pub struct VerifyAttestationCallback<'info> {
    #[account(
        mut,
        seeds = [b"deposit-intent", deposit_intent.user.as_ref(), &deposit_intent.deposit_id.to_le_bytes()],
        bump = deposit_intent.bump
    )]
    pub deposit_intent: Box<Account<'info, DepositIntent>>,
    #[account(mut, seeds = [b"bridge-config"], bump = bridge_config.bump)]
    pub bridge_config: Box<Account<'info, BridgeConfig>>,
    #[account(
        init,
        payer = payer,
        space = ClaimTracker::SIZE,
        seeds = [b"claim-tracker", deposit_intent.note_commitment.as_ref()],
        bump
    )]
    pub claim_tracker: Box<Account<'info, ClaimTracker>>,
    #[account(mut, seeds = [b"szec-mint"], bump)]
    pub szec_mint: Box<Account<'info, Mint>>,
    /// CHECK: mint authority PDA
    #[account(seeds = [b"mint-authority"], bump)]
    pub mint_authority: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = szec_mint,
        associated_token::authority = deposit_intent.user,
    )]
    pub user_token_account: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, anchor_spl::associated_token::AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    