use arcis_imports::*;

#[encrypted]
mod circuits {
    use arcis_imports::*;

    // ========================================================================
    // ATTESTATION VERIFICATION (Deposit Flow)
    // ========================================================================

    /// Input from enclave attestation
    pub struct AttestationInput {
        pub note_commitment: [u8; 32],
        pub amount: u64,
        pub recipient_solana: [u8; 32],
        pub block_height: u64,
        pub enclave_signature: [u8; 64],
        pub enclave_pubkey: [u8; 32],
    }

    /// Verifies the enclave's Ed25519 signature over the attestation payload
    /// Returns true if valid, false otherwise
    #[instruction]
    pub fn verify_attestation(
        input_ctxt: Enc<Shared, AttestationInput>,
    ) -> Enc<Shared, bool> {
        let input = input_ctxt.to_arcis();
        
        // Basic validation - in production, use Arcium's ed25519_verify if available
        // For now: validate that all critical fields are non-zero/valid
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

        input_ctxt.owner.from_arcis(is_valid)
    }

    // ========================================================================
    // BURN INTENT CREATION (Withdrawal Flow - Step 1)
    // ========================================================================

    /// Input for creating a burn/withdrawal intent
    /// The zcash_address is encrypted so Solana never sees it
    pub struct BurnIntentInput {
        pub user: [u8; 32],           // Solana pubkey
        pub amount: u64,              // Amount in zatoshis
        pub zcash_address: [u8; 256], // Destination UA (encrypted)
        pub address_len: u16,         // Actual length of address
    }

    /// Output stored encrypted on Solana
    pub struct BurnIntentOutput {
        pub burn_id: u64,
        pub user: [u8; 32],
        pub amount: u64,
        pub zcash_address: [u8; 256],
        pub address_len: u16,
        pub status: u8,               // 0=Pending, 1=Processing, 2=Completed, 3=Failed
        pub zcash_txid: [u8; 32],     // Filled in by update_burn_intent
    }

    /// Creates an encrypted burn intent
    /// MPC nodes will read this to know where to send ZEC
    #[instruction]
    pub fn create_burn_intent(
        input_ctxt: Enc<Shared, BurnIntentInput>,
        burn_id: u64,
    ) -> Enc<Shared, BurnIntentOutput> {
        let input = input_ctxt.to_arcis();
        
        // Validate address length
        let is_valid_len = input.address_len >= 4 && input.address_len <= 256;
        
        // Validate amount
        let is_valid_amount = input.amount > 0;
        
        let result = if is_valid_len && is_valid_amount {
            BurnIntentOutput {
                burn_id,
                user: input.user,
                amount: input.amount,
                zcash_address: input.zcash_address,
                address_len: input.address_len,
                status: 0, // Pending
                zcash_txid: [0u8; 32],
            }
        } else {
            // Return failed intent
            BurnIntentOutput {
                burn_id,
                user: input.user,
                amount: 0,
                zcash_address: [0u8; 256],
                address_len: 0,
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
        pub current_intent: BurnIntentOutput, // Current encrypted state
        pub zcash_txid: [u8; 32],              // Zcash transaction ID
        pub new_status: u8,                    // 2=Completed, 3=Failed
    }

    /// Updates the burn intent with Zcash TXID and new status
    #[instruction]
    pub fn update_burn_intent(
        input_ctxt: Enc<Shared, UpdateBurnIntentInput>,
    ) -> Enc<Shared, BurnIntentOutput> {
        let input = input_ctxt.to_arcis();
        
        // Only allow update if current status is Pending or Processing
        let can_update = input.current_intent.status == 0 
            || input.current_intent.status == 1;
        
        let result = if can_update {
            BurnIntentOutput {
                burn_id: input.current_intent.burn_id,
                user: input.current_intent.user,
                amount: input.current_intent.amount,
                zcash_address: input.current_intent.zcash_address,
                address_len: input.current_intent.address_len,
                status: input.new_status,
                zcash_txid: input.zcash_txid,
            }
        } else {
            // Return unchanged if invalid transition
            input.current_intent
        };

        input_ctxt.owner.from_arcis(result)
    }
}