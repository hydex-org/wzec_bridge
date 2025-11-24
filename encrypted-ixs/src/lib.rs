use arcis_imports::*;

#[encrypted]
mod circuits {
    use arcis_imports::*;

    // ========================================================================
    // DEPOSIT FLOW - Attestation Verification
    // ========================================================================

    /// Encrypted attestation from enclave
    pub struct AttestationInput {
        pub note_commitment: [u8; 32],
        pub amount: u64,
        pub recipient_solana: [u8; 32],
        pub block_height: u64,
        pub enclave_signature: [u8; 64],
        pub enclave_pubkey: [u8; 32],
    }

    /// Verify enclave attestation (confidential)
    #[instruction]
    pub fn verify_attestation(
        input_ctxt: Enc<Shared, AttestationInput>,
    ) -> Enc<Shared, bool> {
        let input = input_ctxt.to_arcis();
        
        // In production, verify:
        // 1. Enclave signature is valid
        // 2. Note commitment is unique
        // 3. Block height is recent enough
        // 4. Amount is reasonable
        
        // Simplified verification for now
        let is_valid = input.amount > 0 && input.block_height > 0;
        
        input_ctxt.owner.from_arcis(is_valid)
    }

    // ========================================================================
    // REDEMPTION FLOW - Burn Intent Creation
    // ========================================================================

    pub struct BurnIntentInput {
        pub user: [u8; 32],
        pub amount: u64,
        pub zcash_address: [u8; 256],
        pub address_len: u16,
    }

    pub struct BurnIntentOutput {
        pub burn_id: u64,
        pub user: [u8; 32],
        pub amount: u64,
        pub zcash_address: [u8; 256],
        pub address_len: u16,
        pub status: u8,
    }

    #[instruction]
    pub fn create_burn_intent(
        input_ctxt: Enc<Shared, BurnIntentInput>,
        burn_id: u64,
    ) -> Enc<Shared, BurnIntentOutput> {
        let input = input_ctxt.to_arcis();
        
        let output = BurnIntentOutput {
            burn_id,
            user: input.user,
            amount: input.amount,
            zcash_address: input.zcash_address,
            address_len: input.address_len,
            status: 0, // Pending
        };
        
        input_ctxt.owner.from_arcis(output)
    }

    // ========================================================================
    // FINALIZATION - Update Burn Intent with Zcash TXID
    // ========================================================================

    pub struct UpdateBurnIntentInput {
        pub burn_intent: BurnIntentOutput,
        pub zcash_txid: [u8; 32],
        pub new_status: u8,
    }

    #[instruction]
    pub fn update_burn_intent(
        input_ctxt: Enc<Shared, UpdateBurnIntentInput>,
    ) -> Enc<Shared, BurnIntentOutput> {
        let input = input_ctxt.to_arcis();
        
        let mut output = input.burn_intent;
        output.status = input.new_status;
        
        input_ctxt.owner.from_arcis(output)
    }
}
