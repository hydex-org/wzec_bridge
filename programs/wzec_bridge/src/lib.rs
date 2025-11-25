use anchor_lang::prelude::*;
use anchor_spl::{
    token::{self, Burn, Mint, MintTo, Token, TokenAccount},
};
use arcium_anchor::prelude::*;

// Computation definition offsets
const COMP_DEF_OFFSET_VERIFY_ATTESTATION: u32 = comp_def_offset("verify_attestation");
const COMP_DEF_OFFSET_CREATE_BURN: u32 = comp_def_offset("create_burn_intent");
const COMP_DEF_OFFSET_UPDATE_BURN: u32 = comp_def_offset("update_burn_intent");

declare_id!("HefTNtytDcQgSQmBpPuwjGipbVcJTMRHnppU9poWRXhD");

#[arcium_program]
pub mod wzec_bridge {
    use super::*;

    // ========================================================================
    // INITIALIZATION INSTRUCTIONS
    // ========================================================================

    /// Initialize the bridge configuration with enclave and MPC setup
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
        bridge_config.wzec_mint = ctx.accounts.wzec_mint.key();
        bridge_config.mint_authority_bump = ctx.bumps.mint_authority;
        bridge_config.withdrawal_nonce = 0;
        bridge_config.deposit_nonce = 0;
        bridge_config.mpc_quorum_pubkeys = mpc_quorum_pubkeys;
        bridge_config.bridge_ufvk = bridge_ufvk;

        msg!("Bridge initialized");
        msg!("wZEC Mint: {}", ctx.accounts.wzec_mint.key());
        msg!("Admin: {}", admin);
        msg!("Enclave Authority: {}", enclave_authority);

        Ok(())
    }

    /// Initialize computation definitions (one-time setup)
    pub fn init_verify_attestation_comp_def(ctx: Context<InitVerifyAttestationCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, 0, None, None)?;
        Ok(())
    }

    pub fn init_create_burn_comp_def(ctx: Context<InitCreateBurnCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, 0, None, None)?;
        Ok(())
    }

    pub fn init_update_burn_comp_def(ctx: Context<InitUpdateBurnCompDef>) -> Result<()> {
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

    /// Step 2.5: Set deposit details after enclave detection (called by enclave authority)
    pub fn set_deposit_details(
        ctx: Context<SetDepositDetails>,
        deposit_id: u64,
        amount: u64,
        note_commitment: [u8; 32],
    ) -> Result<()> {
        require!(
            ctx.accounts.enclave_authority.key() == ctx.accounts.bridge_config.enclave_authority
                || ctx.accounts.enclave_authority.key() == ctx.accounts.bridge_config.admin,
            BridgeError::Unauthorized
        );

        let deposit_intent = &mut ctx.accounts.deposit_intent;
        require!(
            deposit_intent.deposit_id == deposit_id,
            BridgeError::InvalidDepositId
        );
        require!(
            deposit_intent.status == DepositStatus::AddressGenerated as u8,
            BridgeError::InvalidDepositStatus
        );
        require!(amount > 0, BridgeError::InvalidAmount);

        // Prevent double-setting (security check)
        require!(
            deposit_intent.amount == 0,
            BridgeError::NoteAlreadyClaimed
        );

        deposit_intent.amount = amount;
        deposit_intent.note_commitment = note_commitment;
        deposit_intent.status = DepositStatus::Detected as u8;

        emit!(DepositDetected {
            deposit_id,
            amount,
            note_commitment,
        });

        msg!("Deposit {} detected: {} zatoshis", deposit_id, amount);

        Ok(())
    }

    /// Step 3: Mint wZEC after enclave attestation (encrypted verification)
    pub fn mint_with_attestation(
        ctx: Context<MintWithAttestation>,
        computation_offset: u64,
        deposit_id: u64,
        encrypted_attestation: [u8; 32],  // Encrypted attestation from enclave
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        let deposit_intent = &mut ctx.accounts.deposit_intent;

        require!(
            deposit_intent.deposit_id == deposit_id,
            BridgeError::InvalidDepositId
        );
        // Require that deposit details have been set (amount and note_commitment)
        require!(
            deposit_intent.status == DepositStatus::Detected as u8,
            BridgeError::InvalidDepositStatus
        );
        require!(
            deposit_intent.amount > 0,
            BridgeError::InvalidAmount
        );

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        // Queue confidential computation to verify attestation
        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::EncryptedU8(encrypted_attestation),
            Argument::PlaintextU64(deposit_id),
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![VerifyAttestationCallback::callback_ix(&[])],
            1,
        )?;

        msg!("Attestation verification queued for deposit {}", deposit_id);

        Ok(())
    }

    /// Callback after attestation is verified - actually mint the tokens
    #[arcium_callback(encrypted_ix = "verify_attestation")]
    pub fn verify_attestation_callback(
        ctx: Context<VerifyAttestationCallback>,
        output: ComputationOutputs<VerifyAttestationOutput>,
    ) -> Result<()> {
        let attestation_result = match output {
            ComputationOutputs::Success(VerifyAttestationOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::AttestationFailed.into()),
        };

        // Extract attestation data from encrypted output
        // The Arcium computation returns an AttestationResult with:
        // - amount: u64
        // - note_commitment: [u8; 32]
        // - recipient: [u8; 32]
        // - is_valid: bool

        // For now, we need to deserialize from the ciphertexts
        // In a production setup, you'd have proper deserialization logic here
        // This is a placeholder that shows the intended structure

        let deposit_intent = &mut ctx.accounts.deposit_intent;
        let bridge_config = &ctx.accounts.bridge_config;
        let claim_tracker = &mut ctx.accounts.claim_tracker;

        // TODO: Properly deserialize attestation_result to extract:
        // - amount
        // - note_commitment
        // - recipient
        // - is_valid flag

        // For now, ensure amount was set by a previous step or extract from attestation
        require!(
            deposit_intent.amount > 0,
            BridgeError::InvalidAmount
        );

        // Prevent double-mint: amount should only be set once
        // This check would be redundant once we extract from attestation,
        // but serves as a safety check

        // Mark note as claimed to prevent double-spend
        claim_tracker.bump = ctx.bumps.claim_tracker;
        claim_tracker.note_commitment = deposit_intent.note_commitment;
        claim_tracker.claimed_at = Clock::get()?.unix_timestamp;
        claim_tracker.deposit_id = deposit_intent.deposit_id;

        // Mint wZEC tokens using the amount from deposit_intent
        let seeds = &[
            b"mint-authority".as_ref(),
            &[bridge_config.mint_authority_bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.wzec_mint.to_account_info(),
                to: ctx.accounts.user_token_account.to_account_info(),
                authority: ctx.accounts.mint_authority.to_account_info(),
            },
            signer,
        );

        let amount = deposit_intent.amount;
        token::mint_to(cpi_ctx, amount)?;

        // Update deposit status
        deposit_intent.status = DepositStatus::Minted as u8;

        emit!(TokensMinted {
            deposit_id: deposit_intent.deposit_id,
            user: deposit_intent.user,
            amount,
            encrypted_attestation: attestation_result.ciphertexts[0],
        });

        msg!("Minted {} wZEC for deposit {}", amount, deposit_intent.deposit_id);

        Ok(())
    }

    // ========================================================================
    // DEMO MINT (Admin only, for testing)
    // ========================================================================

    pub fn demo_mint(ctx: Context<DemoMint>, amount: u64) -> Result<()> {
        require!(
            ctx.accounts.admin.key() == ctx.accounts.bridge_config.admin,
            BridgeError::Unauthorized
        );
        require!(amount > 0, BridgeError::InvalidAmount);

        let seeds = &[
            b"mint-authority".as_ref(),
            &[ctx.accounts.bridge_config.mint_authority_bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.wzec_mint.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.mint_authority.to_account_info(),
            },
            signer,
        );

        token::mint_to(cpi_ctx, amount)?;

        msg!("Demo minted {} wZEC", amount);

        Ok(())
    }

    // ========================================================================
    // REDEMPTION FLOW (wZEC → ZEC)
    // ========================================================================

    /// Burn wZEC and create encrypted withdrawal intent
    pub fn burn_for_withdrawal(
        ctx: Context<BurnForWithdrawal>,
        computation_offset: u64,
        amount: u64,
        zcash_address: Vec<u8>,
        encrypted_data: [u8; 32],
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        require!(amount > 0, BridgeError::InvalidAmount);
        require!(
            zcash_address.len() > 0 && zcash_address.len() <= 256,
            BridgeError::InvalidAddress
        );

        // Validate Zcash UA format
        require!(
            zcash_address.starts_with(b"u1") || zcash_address.starts_with(b"utest1"),
            BridgeError::InvalidAddress
        );

        // Burn tokens
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Burn {
                mint: ctx.accounts.wzec_mint.to_account_info(),
                from: ctx.accounts.user_token_account.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        );
        token::burn(cpi_ctx, amount)?;

        // Get burn ID and increment
        let bridge_config = &mut ctx.accounts.bridge_config;
        let burn_id = bridge_config.withdrawal_nonce;
        bridge_config.withdrawal_nonce += 1;

        // Queue confidential burn intent creation
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        
        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::EncryptedU8(encrypted_data),
            Argument::PlaintextU64(burn_id),
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![CreateBurnIntentCallback::callback_ix(&[])],
            1,
        )?;

        msg!("Burn queued: ID {} for {} wZEC", burn_id, amount);

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "create_burn_intent")]
    pub fn create_burn_intent_callback(
        ctx: Context<CreateBurnIntentCallback>,
        output: ComputationOutputs<CreateBurnIntentOutput>,
    ) -> Result<()> {
        let burn_output = match output {
            ComputationOutputs::Success(CreateBurnIntentOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::ComputationFailed.into()),
        };

        emit!(BurnIntentCreated {
            burn_id: 0, // Encrypted in burn_output
            encrypted_burn_data: burn_output.ciphertexts[0],
            nonce: burn_output.nonce.to_le_bytes(),
        });

        msg!("Burn intent created (encrypted)");

        Ok(())
    }

    /// MPC nodes call this after broadcasting Zcash TX
    pub fn finalize_withdrawal(
        ctx: Context<FinalizeWithdrawal>,
        computation_offset: u64,
        burn_id: u64,
        encrypted_txid: [u8; 32],
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::EncryptedU8(encrypted_txid),
            Argument::PlaintextU64(burn_id),
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![UpdateBurnIntentCallback::callback_ix(&[])],
            1,
        )?;

        msg!("Withdrawal finalization queued for burn {}", burn_id);

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "update_burn_intent")]
    pub fn update_burn_intent_callback(
        ctx: Context<UpdateBurnIntentCallback>,
        output: ComputationOutputs<UpdateBurnIntentOutput>,
    ) -> Result<()> {
        let update_output = match output {
            ComputationOutputs::Success(UpdateBurnIntentOutput { field_0 }) => field_0,
            _ => return Err(BridgeError::ComputationFailed.into()),
        };

        emit!(WithdrawalFinalized {
            burn_id: 0, // Encrypted in update_output
            encrypted_txid: update_output.ciphertexts[0],
            nonce: update_output.nonce.to_le_bytes(),
        });

        msg!("Withdrawal finalized (encrypted)");

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
    pub wzec_mint: Pubkey,
    pub mint_authority_bump: u8,
    pub withdrawal_nonce: u64,
    pub deposit_nonce: u64,
    pub mpc_quorum_pubkeys: Vec<[u8; 32]>,
    pub bridge_ufvk: Vec<u8>,  // Full Viewing Key
}

impl BridgeConfig {
    pub const MAX_SIZE: usize = 8 + 1 + 32 + 32 + 32 + 1 + 8 + 8 + (4 + 32 * 10) + (4 + 512);
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
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(
        init,
        payer = payer,
        mint::decimals = 8,
        mint::authority = mint_authority,
    )]
    pub wzec_mint: Account<'info, Mint>,

    /// CHECK: PDA mint authority
    #[account(
        seeds = [b"mint-authority"],
        bump
    )]
    pub mint_authority: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
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

#[derive(Accounts)]
#[instruction(deposit_id: u64, amount: u64, note_commitment: [u8; 32])]
pub struct SetDepositDetails<'info> {
    pub enclave_authority: Signer<'info>,

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

#[queue_computation_accounts("verify_attestation", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, deposit_id: u64)]
pub struct MintWithAttestation<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

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
    pub sign_pda_account: Account<'info, SignerAccount>,
    
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    
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
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    
    #[account(mut, address = derive_cluster_pda!(mxe_account, BridgeError::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("verify_attestation")]
#[derive(Accounts)]
pub struct VerifyAttestationCallback<'info> {
    #[account(mut)]
    pub deposit_intent: Account<'info, DepositIntent>,

    #[account(
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(
        init,
        payer = payer,
        space = ClaimTracker::SIZE,
        seeds = [
            b"claim-tracker",
            deposit_intent.key().as_ref()
        ],
        bump
    )]
    pub claim_tracker: Account<'info, ClaimTracker>,

    /// CHECK: PDA mint authority
    #[account(
        seeds = [b"mint-authority"],
        bump = bridge_config.mint_authority_bump,
    )]
    pub mint_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        address = bridge_config.wzec_mint,
    )]
    pub wzec_mint: Account<'info, Mint>,

    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_VERIFY_ATTESTATION))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DemoMint<'info> {
    pub admin: Signer<'info>,

    #[account(
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    /// CHECK: PDA mint authority
    #[account(
        seeds = [b"mint-authority"],
        bump = bridge_config.mint_authority_bump,
    )]
    pub mint_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        address = bridge_config.wzec_mint,
    )]
    pub wzec_mint: Account<'info, Mint>,

    #[account(mut)]
    pub recipient_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[queue_computation_accounts("create_burn_intent", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct BurnForWithdrawal<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(
        mut,
        associated_token::mint = wzec_mint,
        associated_token::authority = user,
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        address = bridge_config.wzec_mint,
    )]
    pub wzec_mint: Account<'info, Mint>,

    pub token_program: Program<'info, Token>,

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
    pub sign_pda_account: Account<'info, SignerAccount>,
    
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    
    #[account(mut, address = derive_mempool_pda!())]
    /// CHECK: checked by arcium
    pub mempool_account: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_execpool_pda!())]
    /// CHECK: checked by arcium
    pub executing_pool: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    /// CHECK: checked by arcium
    pub computation_account: UncheckedAccount<'info>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CREATE_BURN))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    
    #[account(mut, address = derive_cluster_pda!(mxe_account, BridgeError::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("create_burn_intent")]
#[derive(Accounts)]
pub struct CreateBurnIntentCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CREATE_BURN))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

#[queue_computation_accounts("update_burn_intent", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct FinalizeWithdrawal<'info> {
    #[account(mut)]
    pub mpc_node: Signer<'info>,

    #[account(
        seeds = [b"bridge-config"],
        bump = bridge_config.bump,
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

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
    pub sign_pda_account: Account<'info, SignerAccount>,
    
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    
    #[account(mut, address = derive_mempool_pda!())]
    /// CHECK: checked by arcium
    pub mempool_account: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_execpool_pda!())]
    /// CHECK: checked by arcium
    pub executing_pool: UncheckedAccount<'info>,
    
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    /// CHECK: checked by arcium
    pub computation_account: UncheckedAccount<'info>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_UPDATE_BURN))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    
    #[account(mut, address = derive_cluster_pda!(mxe_account, BridgeError::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("update_burn_intent")]
#[derive(Accounts)]
pub struct UpdateBurnIntentCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_UPDATE_BURN))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

// Computation definition initialization contexts
#[init_computation_definition_accounts("verify_attestation", payer)]
#[derive(Accounts)]
pub struct InitVerifyAttestationCompDef<'info> {
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

#[init_computation_definition_accounts("create_burn_intent", payer)]
#[derive(Accounts)]
pub struct InitCreateBurnCompDef<'info> {
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

#[init_computation_definition_accounts("update_burn_intent", payer)]
#[derive(Accounts)]
pub struct InitUpdateBurnCompDef<'info> {
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
pub struct DepositDetected {
    pub deposit_id: u64,
    pub amount: u64,
    pub note_commitment: [u8; 32],
}

#[event]
pub struct TokensMinted {
    pub deposit_id: u64,
    pub user: Pubkey,
    pub amount: u64,
    pub encrypted_attestation: [u8; 32],
}

#[event]
pub struct BurnIntentCreated {
    pub burn_id: u64,
    pub encrypted_burn_data: [u8; 32],
    pub nonce: [u8; 16],
}

#[event]
pub struct WithdrawalFinalized {
    pub burn_id: u64,
    pub encrypted_txid: [u8; 32],
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
}