use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, MintTo};
use anchor_spl::associated_token::AssociatedToken;
declare_id!("B12pxSGTH8bt8LtVcdbEXf2CPpf2sFJuj7SctsFuvcQc");

#[program]
pub mod wzec_bridge {
    use super::*;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

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
        Ok(())
    }

    // ========================================================================
    // DEPOSIT FLOW
    // ========================================================================

    /// User creates their own deposit intent
    pub fn init_deposit_intent(ctx: Context<InitDepositIntent>) -> Result<()> {
        let config = &mut ctx.accounts.bridge_config;
        let intent = &mut ctx.accounts.deposit_intent;
        
        let deposit_id = config.deposit_nonce;
        config.deposit_nonce += 1;
        
        intent.bump = ctx.bumps.deposit_intent;
        intent.deposit_id = deposit_id;
        intent.user = ctx.accounts.user.key();
        intent.status = 0; // Pending
        intent.amount = 0;
        intent.note_commitment = [0; 32];
        intent.ua_hash = [0; 32];
        intent.created_at = Clock::get()?.unix_timestamp;
        
        emit!(DepositIntentCreated { deposit_id, user: intent.user });
        Ok(())
    }

    /// Enclave creates deposit intent for a user AND sets the unified address in one TX
    /// This is the main entry point for the deposit flow
    pub fn create_deposit_for_user(
        ctx: Context<CreateDepositForUser>,
        recipient: Pubkey,
        ua_hash: [u8; 32],
    ) -> Result<()> {
        let config = &ctx.accounts.bridge_config;
        
        // Only enclave authority can create deposits for users
        require!(
            ctx.accounts.authority.key() == config.enclave_authority ||
            ctx.accounts.authority.key() == config.mpc_authority,
            BridgeError::Unauthorized
        );
        
        let deposit_id = ctx.accounts.bridge_config.deposit_nonce;
        
        // Initialize deposit intent
        let intent = &mut ctx.accounts.deposit_intent;
        intent.bump = ctx.bumps.deposit_intent;
        intent.deposit_id = deposit_id;
        intent.user = recipient;
        intent.status = 1; // AddressGenerated (skipping Pending since we set UA immediately)
        intent.amount = 0; // Will be set on mint
        intent.note_commitment = [0; 32]; // Will be set on mint
        intent.ua_hash = ua_hash;
        intent.created_at = Clock::get()?.unix_timestamp;
        
        // Update config
        let config = &mut ctx.accounts.bridge_config;
        config.deposit_nonce += 1;
        
        emit!(DepositIntentCreated { deposit_id, user: recipient });
        emit!(UnifiedAddressSet { deposit_id });
        
        msg!("Created deposit #{} for user {} with UA hash", deposit_id, recipient);
        
        Ok(())
    }

    pub fn set_unified_address(
        ctx: Context<SetUnifiedAddress>,
        ua_hash: [u8; 32],
        amount: u64,
        note_commitment: [u8; 32],
    ) -> Result<()> {
        require!(
            ctx.accounts.authority.key() == ctx.accounts.bridge_config.enclave_authority,
            BridgeError::Unauthorized
        );
        
        let intent = &mut ctx.accounts.deposit_intent;
        require!(intent.status == 0, BridgeError::InvalidStatus);
        
        intent.ua_hash = ua_hash;
        intent.amount = amount;
        intent.note_commitment = note_commitment;
        intent.status = 1; // AddressGenerated
        
        emit!(UnifiedAddressSet { deposit_id: intent.deposit_id });
        Ok(())
    }

    /// Simplified mint function for devnet testing
    /// Just requires MPC authority to sign - no Arcium
    pub fn mint_simple(
        ctx: Context<MintSimple>,
        note_commitment: [u8; 32],
        amount: u64,
        _block_height: u64,
    ) -> Result<()> {
        let intent = &ctx.accounts.deposit_intent;
        let config = &ctx.accounts.bridge_config;
        
        // Verify caller is authorized (enclave or MPC authority)
        require!(
            ctx.accounts.authority.key() == config.enclave_authority ||
            ctx.accounts.authority.key() == config.mpc_authority,
            BridgeError::Unauthorized
        );
        
        // Verify deposit is in correct state (must be AddressGenerated = 1)
        require!(intent.status == 1, BridgeError::InvalidStatus);
        
        // Initialize claim tracker (prevents double-mint)
        let claim_tracker = &mut ctx.accounts.claim_tracker;
        claim_tracker.bump = ctx.bumps.claim_tracker;
        claim_tracker.note_commitment = note_commitment;
        claim_tracker.deposit_id = intent.deposit_id;
        claim_tracker.claimed_at = Clock::get()?.unix_timestamp;
        
        // Update deposit intent
        let intent = &mut ctx.accounts.deposit_intent;
        intent.status = 3; // Minted
        intent.amount = amount;
        intent.note_commitment = note_commitment;
        
        // Update bridge config
        let config = &mut ctx.accounts.bridge_config;
        config.total_minted += amount;
        
        // Mint tokens
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
            amount,
        )?;
        
        emit!(DepositMinted { 
            deposit_id: intent.deposit_id, 
            user: intent.user, 
            amount 
        });
        
        Ok(())
    }

    /// Direct mint without requiring pre-existing deposit intent
    /// Creates deposit intent inline and mints in one transaction
    /// For devnet testing - MPC authority only
    pub fn mint_direct(
        ctx: Context<MintDirect>,
        recipient: Pubkey,
        note_commitment: [u8; 32],
        amount: u64,
        block_height: u64,
    ) -> Result<()> {
        let config = &ctx.accounts.bridge_config;
        
        // Verify caller is MPC authority
        require!(
            ctx.accounts.authority.key() == config.mpc_authority,
            BridgeError::Unauthorized
        );
        
        // Get deposit ID and increment nonce
        let deposit_id = ctx.accounts.bridge_config.deposit_nonce;
        
        // Initialize deposit intent inline
        let intent = &mut ctx.accounts.deposit_intent;
        intent.bump = ctx.bumps.deposit_intent;
        intent.deposit_id = deposit_id;
        intent.user = recipient;
        intent.status = 3; // Minted directly
        intent.amount = amount;
        intent.note_commitment = note_commitment;
        intent.ua_hash = [0; 32]; // No UA for direct mint
        intent.created_at = Clock::get()?.unix_timestamp;
        
        // Initialize claim tracker (prevents double-mint)
        let claim_tracker = &mut ctx.accounts.claim_tracker;
        claim_tracker.bump = ctx.bumps.claim_tracker;
        claim_tracker.note_commitment = note_commitment;
        claim_tracker.deposit_id = deposit_id;
        claim_tracker.claimed_at = Clock::get()?.unix_timestamp;
        
        // Update bridge config
        let config = &mut ctx.accounts.bridge_config;
        config.deposit_nonce += 1;
        config.total_minted += amount;
        
        // Mint tokens
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
            amount,
        )?;
        
        emit!(DepositIntentCreated { deposit_id, user: recipient });
        emit!(DepositMinted { 
            deposit_id, 
            user: recipient, 
            amount 
        });
        
        msg!("Direct mint: {} zatoshi to {} (block {})", amount, recipient, block_height);
        
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
    pub mpc_authority: Pubkey,
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
    pub ua_hash: [u8; 32],
    pub created_at: i64,
}

#[account]
pub struct BurnIntent {
    pub bump: u8,
    pub burn_id: u64,
    pub user: Pubkey,
    pub amount: u64,
    pub status: u8,
    pub encrypted_data_hash: [u8; 32],
    pub zcash_txid: [u8; 32],
    pub created_at: i64,
}

#[account]
pub struct ClaimTracker {
    pub bump: u8,
    pub note_commitment: [u8; 32],
    pub deposit_id: u64,
    pub claimed_at: i64,
}

// ============================================================================
// EVENTS
// ============================================================================

#[event]
pub struct DepositIntentCreated { pub deposit_id: u64, pub user: Pubkey }
#[event]
pub struct UnifiedAddressSet { pub deposit_id: u64 }
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
    #[msg("Invalid status")] InvalidStatus,
    #[msg("Invalid address")] InvalidAddress,
    #[msg("Attestation failed")] AttestationFailed,
    #[msg("Computation failed")] ComputationFailed,
}

// ============================================================================
// SIZE IMPLEMENTATIONS
// ============================================================================

impl BridgeConfig {
    pub const SIZE: usize = 8 + 1 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 8;
}

impl DepositIntent {
    pub const SIZE: usize = 8 + 1 + 8 + 32 + 1 + 8 + 32 + 32 + 8;
}

impl BurnIntent {
    pub const SIZE: usize = 8 + 1 + 8 + 32 + 8 + 1 + 32 + 32 + 8;
}

impl ClaimTracker {
    pub const SIZE: usize = 8 + 1 + 32 + 8 + 8;
}

// ============================================================================
// ACCOUNT CONTEXTS
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
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(
        init,
        payer = admin,
        mint::decimals = 8,
        mint::authority = mint_authority,
        seeds = [b"szec-mint"],
        bump
    )]
    pub szec_mint: Account<'info, Mint>,
    /// CHECK: PDA for mint authority
    #[account(seeds = [b"mint-authority"], bump)]
    pub mint_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct InitDepositIntent<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"bridge-config"], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(
        init,
        payer = user,
        space = DepositIntent::SIZE,
        seeds = [b"deposit-intent", user.key().as_ref(), &bridge_config.deposit_nonce.to_le_bytes()],
        bump
    )]
    pub deposit_intent: Account<'info, DepositIntent>,
    pub system_program: Program<'info, System>,
}

/// Enclave creates deposit intent for any user
#[derive(Accounts)]
#[instruction(recipient: Pubkey)]
pub struct CreateDepositForUser<'info> {
    /// Enclave or MPC authority
    pub authority: Signer<'info>,
    
    /// Payer for account creation
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(mut, seeds = [b"bridge-config"], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    
    /// Deposit intent for the recipient user
    #[account(
        init,
        payer = payer,
        space = DepositIntent::SIZE,
        seeds = [b"deposit-intent", recipient.as_ref(), &bridge_config.deposit_nonce.to_le_bytes()],
        bump
    )]
    pub deposit_intent: Account<'info, DepositIntent>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetUnifiedAddress<'info> {
    pub authority: Signer<'info>,
    #[account(seeds = [b"bridge-config"], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(
        mut,
        seeds = [b"deposit-intent", deposit_intent.user.as_ref(), &deposit_intent.deposit_id.to_le_bytes()],
        bump = deposit_intent.bump
    )]
    pub deposit_intent: Account<'info, DepositIntent>,
}

/// Simplified mint without Arcium MPC (for devnet)
#[derive(Accounts)]
#[instruction(note_commitment: [u8; 32])]
pub struct MintSimple<'info> {
    /// Authority (enclave or MPC) - must be signer
    pub authority: Signer<'info>,
    
    /// Payer for the claim tracker account
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(mut, seeds = [b"bridge-config"], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    
    #[account(
        mut,
        seeds = [b"deposit-intent", deposit_intent.user.as_ref(), &deposit_intent.deposit_id.to_le_bytes()],
        bump = deposit_intent.bump
    )]
    pub deposit_intent: Account<'info, DepositIntent>,
    
    /// Claim tracker prevents double-mint of the same note
    #[account(
        init,
        payer = payer,
        space = ClaimTracker::SIZE,
        seeds = [b"claim-tracker", note_commitment.as_ref()],
        bump
    )]
    pub claim_tracker: Account<'info, ClaimTracker>,
    
    #[account(mut, seeds = [b"szec-mint"], bump)]
    pub szec_mint: Account<'info, Mint>,
    
    /// CHECK: PDA for mint authority
    #[account(seeds = [b"mint-authority"], bump)]
    pub mint_authority: UncheckedAccount<'info>,
    
    /// CHECK: User wallet - must match deposit_intent.user
    #[account(constraint = user_wallet.key() == deposit_intent.user)]
    pub user_wallet: UncheckedAccount<'info>,
    
    /// User's token account to receive minted tokens
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = szec_mint,
        associated_token::authority = user_wallet,
    )]
    pub user_token_account: Account<'info, TokenAccount>,
    
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// Direct mint - creates deposit intent and mints in one TX
/// For devnet testing without pre-existing deposit intents
#[derive(Accounts)]
#[instruction(recipient: Pubkey, note_commitment: [u8; 32])]
pub struct MintDirect<'info> {
    /// MPC authority - must be signer
    pub authority: Signer<'info>,
    
    /// Payer for account creation
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(mut, seeds = [b"bridge-config"], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    
    /// Deposit intent - created inline
    #[account(
        init,
        payer = payer,
        space = DepositIntent::SIZE,
        seeds = [b"deposit-intent", recipient.as_ref(), &bridge_config.deposit_nonce.to_le_bytes()],
        bump
    )]
    pub deposit_intent: Account<'info, DepositIntent>,
    
    /// Claim tracker prevents double-mint
    #[account(
        init,
        payer = payer,
        space = ClaimTracker::SIZE,
        seeds = [b"claim-tracker", note_commitment.as_ref()],
        bump
    )]
    pub claim_tracker: Account<'info, ClaimTracker>,
    
    #[account(mut, seeds = [b"szec-mint"], bump)]
    pub szec_mint: Account<'info, Mint>,
    
    /// CHECK: PDA for mint authority
    #[account(seeds = [b"mint-authority"], bump)]
    pub mint_authority: UncheckedAccount<'info>,
    
    /// Recipient's token account
    #[account(
        mut,
        associated_token::mint = szec_mint,
        associated_token::authority = recipient,
    )]
    pub user_token_account: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}
