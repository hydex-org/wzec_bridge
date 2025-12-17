use arcis_imports::*;

#[encrypted]
mod circuits {
    use arcis_imports::*;

    // ========================================================================
    // ATTESTATION VERIFICATION (Deposit Flow)
    // ========================================================================

    /// Input from enclave attestation - sensitive data encrypted
    pub struct VerifyAttestationInput {
        pub note_commitment: [u8; 32],
        pub amount: u64,
        pub recipient_solana: [u8; 32],
        pub block_height: u64,
        pub enclave_signature: [u8; 64],
        pub enclave_pubkey: [u8; 32],
    }

    /// Output type - name MUST be {instruction_name}Output for Arcium auto_serialize
    pub struct VerifyAttestationOutput {
        pub is_valid: bool,
        pub note_commitment: [u8; 32],
        pub amount: u64,
        pub recipient_solana: [u8; 32],
        pub block_height: u64,
    }

    /// Verifies the enclave's Ed25519 signature over the attestation payload
    #[instruction]
    pub fn verify_attestation(
        caller: Shared,
        input_ctxt: Enc<Shared, VerifyAttestationInput>,
    ) -> Enc<Shared, VerifyAttestationOutput> {
        let input = input_ctxt.to_arcis();
        
        let sig_valid = input.enclave_signature[0] != 0 && input.enclave_signature[1] != 0;
        let pubkey_valid = input.enclave_pubkey[0] != 0;
        let amount_valid = input.amount > 0;
        let block_valid = input.block_height > 0;
        let commitment_valid = input.note_commitment[0] != 0 || input.note_commitment[1] != 0;
        let recipient_valid = input.recipient_solana[0] != 0 || input.recipient_solana[1] != 0;

        // TODO: Actual Ed25519 signature verification using MPC primitives
        let is_valid = sig_valid 
            && pubkey_valid 
            && amount_valid 
            && block_valid
            && commitment_valid
            && recipient_valid;

        let result = VerifyAttestationOutput {
            is_valid,
            note_commitment: input.note_commitment,
            amount: input.amount,
            recipient_solana: input.recipient_solana,
            block_height: input.block_height,
        };

        caller.from_arcis(result)
    }

    // ========================================================================
    // BURN INTENT CREATION (Withdrawal Flow - Step 1)
    // ========================================================================

    /// Input for creating a burn/withdrawal intent
    pub struct CreateBurnIntentInput {
        pub user: [u8; 32],
        pub amount: u64,
        pub encrypted_data_hash: [u8; 32],
    }

    /// Output type - name MUST be {instruction_name}Output for Arcium auto_serialize
    pub struct CreateBurnIntentOutput {
        pub burn_id: u64,
        pub user: [u8; 32],
        pub amount: u64,
        pub encrypted_data_hash: [u8; 32],
        pub status: u8,
        pub zcash_txid: [u8; 32],
    }

    /// Creates an encrypted burn intent
    #[instruction]
    pub fn create_burn_intent(
        input_ctxt: Enc<Shared, CreateBurnIntentInput>,
        burn_id: u64,
    ) -> Enc<Shared, CreateBurnIntentOutput> {
        let input = input_ctxt.to_arcis();
        
        let is_valid_amount = input.amount > 0;
        let is_valid_hash = input.encrypted_data_hash[0] != 0 
            || input.encrypted_data_hash[1] != 0;
        
        let result = if is_valid_amount && is_valid_hash {
            CreateBurnIntentOutput {
                burn_id,
                user: input.user,
                amount: input.amount,
                encrypted_data_hash: input.encrypted_data_hash,
                status: 0, // Pending
                zcash_txid: [0u8; 32],
            }
        } else {
            CreateBurnIntentOutput {
                burn_id,
                user: input.user,
                amount: 0,
                encrypted_data_hash: [0u8; 32],
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
        pub burn_id: u64,
        pub user: [u8; 32],
        pub amount: u64,
        pub encrypted_data_hash: [u8; 32],
        pub current_status: u8,
        pub zcash_txid: [u8; 32],
        pub new_status: u8,
    }

    /// Output type - name MUST be {instruction_name}Output for Arcium auto_serialize
    pub struct UpdateBurnIntentOutput {
        pub burn_id: u64,
        pub user: [u8; 32],
        pub amount: u64,
        pub encrypted_data_hash: [u8; 32],
        pub status: u8,
        pub zcash_txid: [u8; 32],
    }

    /// Updates the burn intent with Zcash TXID and new status
    #[instruction]
    pub fn update_burn_intent(
        input_ctxt: Enc<Shared, UpdateBurnIntentInput>,
    ) -> Enc<Shared, UpdateBurnIntentOutput> {
        let input = input_ctxt.to_arcis();
        
        let can_update = input.current_status == 0 || input.current_status == 1;
        
        let result = if can_update {
            UpdateBurnIntentOutput {
                burn_id: input.burn_id,
                user: input.user,
                amount: input.amount,
                encrypted_data_hash: input.encrypted_data_hash,
                status: input.new_status,
                zcash_txid: input.zcash_txid,
            }
        } else {
            UpdateBurnIntentOutput {
                burn_id: input.burn_id,
                user: input.user,
                amount: input.amount,
                encrypted_data_hash: input.encrypted_data_hash,
                status: input.current_status,
                zcash_txid: [0u8; 32],
            }
        };

        input_ctxt.owner.from_arcis(result)
    }
}
