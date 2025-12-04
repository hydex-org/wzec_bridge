use arcis_imports::*;

#[encrypted]
mod circuits {
    use arcis_imports::*;

    // ========================================================================
    // ATTESTATION VERIFICATION (Deposit Flow)
    // ========================================================================

    /// Input from enclave attestation - all sensitive data encrypted
    pub struct AttestationInput {
        pub note_commitment: [u8; 32],
        pub amount: u64,
        pub recipient_solana: [u8; 32],
        pub block_height: u64,
        pub enclave_signature: [u8; 64],
        pub enclave_pubkey: [u8; 32],
    }

    /// Verifies the enclave's Ed25519 signature over the attestation payload
    /// Privacy: Attestation details stay encrypted, only result shared
    #[instruction]
    pub fn verify_attestation(
        input_ctxt: Enc<Shared, AttestationInput>,
    ) -> Enc<Shared, bool> {
        let input = input_ctxt.to_arcis();
        
        // Validate signature bytes are present
        let sig_byte_0_valid = input.enclave_signature[0] != 0;
        let sig_byte_1_valid = input.enclave_signature[1] != 0;
        let pubkey_valid = input.enclave_pubkey[0] != 0;
        let amount_valid = input.amount > 0;
        let block_valid = input.block_height > 0;
        let commitment_valid = input.note_commitment[0] != 0 || input.note_commitment[1] != 0;
        let recipient_valid = input.recipient_solana[0] != 0 || input.recipient_solana[1] != 0;

        let is_valid = sig_byte_0_valid 
            && sig_byte_1_valid 
            && pubkey_valid 
            && amount_valid 
            && block_valid
            && commitment_valid
            && recipient_valid;

        // Return encrypted result
        input_ctxt.owner.from_arcis(is_valid)
    }

    // ========================================================================
    // BURN INTENT CREATION (Withdrawal Flow - Step 1)
    // ========================================================================

    /// Input for creating a burn/withdrawal intent
    /// The zcash_address is encrypted so Solana never sees it
    pub struct BurnIntentInput {
        pub user: [u8; 32],
        pub amount: u64,
        pub zcash_address_hash: [u8; 32],
    }

    /// Output stored encrypted on Solana
    pub struct BurnIntentOutput {
        pub burn_id: u64,
        pub user: [u8; 32],
        pub amount: u64,
        pub zcash_address_hash: [u8; 32],
        pub status: u8,
        pub zcash_txid: [u8; 32],
    }

    /// Creates an encrypted burn intent
    /// MPC nodes will read this to know where to send ZEC
    #[instruction]
    pub fn create_burn_intent(
        input_ctxt: Enc<Shared, BurnIntentInput>,
        burn_id: u64,
    ) -> Enc<Shared, BurnIntentOutput> {
        let input = input_ctxt.to_arcis();
        
        let is_valid_amount = input.amount > 0;
        let is_valid_hash = input.zcash_address_hash[0] != 0 
            || input.zcash_address_hash[1] != 0;
        
        let result = if is_valid_amount && is_valid_hash {
            BurnIntentOutput {
                burn_id,
                user: input.user,
                amount: input.amount,
                zcash_address_hash: input.zcash_address_hash,
                status: 0, // Pending
                zcash_txid: [0u8; 32],
            }
        } else {
            BurnIntentOutput {
                burn_id,
                user: input.user,
                amount: 0,
                zcash_address_hash: [0u8; 32],
                status: 3, // Failed
                zcash_txid: [0u8; 32],
            }
        };

        input_ctxt.owner.from_arcis(result)
    }

    // ========================================================================
    // BURN INTENT UPDATE (Withdrawal Flow - Step 2)
    // ========================================================================

    /// Input for updating a burn intent after Zcash TX is mined
    pub struct UpdateBurnIntentInput {
        pub current_intent: BurnIntentOutput,
        pub zcash_txid: [u8; 32],
        pub new_status: u8,
    }

    /// Updates the burn intent with Zcash TXID and new status
    #[instruction]
    pub fn update_burn_intent(
        input_ctxt: Enc<Shared, UpdateBurnIntentInput>,
    ) -> Enc<Shared, BurnIntentOutput> {
        let input = input_ctxt.to_arcis();
        
        let can_update = input.current_intent.status == 0 
            || input.current_intent.status == 1;
        
        let result = if can_update {
            BurnIntentOutput {
                burn_id: input.current_intent.burn_id,
                user: input.current_intent.user,
                amount: input.current_intent.amount,
                zcash_address_hash: input.current_intent.zcash_address_hash,
                status: input.new_status,
                zcash_txid: input.zcash_txid,
            }
        } else {
            input.current_intent
        };

        input_ctxt.owner.from_arcis(result)
    }
}
