# 4.1 Solana Program

### **4.1.1 Purpose**

- **wZEC Mint Management**

    The program owns an SPL mint representing wrapped ZEC with 8 decimals. All wZEC is minted through a Program Derived Address (PDA) mint authority and burned during withdrawals, ensuring the total supply always matches circulating wrapped ZEC. The mint uses SPL Token standard with PDA-based authority, eliminating any private key requirements.

    ```rust
    // Mint initialization with PDA authority
    #[account(
        init,
        payer = payer,
        mint::decimals = 8,
        mint::authority = mint_authority,
    )]
    pub wzec_mint: Account<'info, Mint>,

    #[account(
        seeds = [b"mint-authority"],
        bump
    )]
    pub mint_authority: UncheckedAccount<'info>,
    ```

- **Deposit Intent Registry**

    For each Zcash deposit, the program creates a deposit-intent record in a PDA. The deposit flow is a three-step process:
    1. User calls `init_intent` with a `diversifier_index` to create the intent
    2. Admin/MPC calls `set_unified_address` to populate the generated Unified Address (UA)
    3. User submits attestation via `mint_with_attestation` for verification and minting

    PDAs are deterministic program-owned addresses with no private key, storing user state including the Solana recipient, diversifier index, expected amount, note commitment, UA, status, and timestamps.

    ```rust
    pub struct DepositIntent {
        pub bump: u8,
        pub deposit_id: u64,              // Unique sequential ID
        pub user: Pubkey,                  // Solana recipient
        pub diversifier_index: u32,        // Used to generate unique UA
        pub status: u8,                    // Pending, AddressGenerated, Detected, Minted, Failed
        pub amount: u64,                   // Amount to mint (set during attestation)
        pub note_commitment: [u8; 32],     // Zcash note commitment for uniqueness
        pub unified_address: [u8; 256],    // Generated UA for Zcash deposit
        pub ua_length: u16,                // Actual UA length (up to 256 bytes)
        pub created_at: i64,               // Unix timestamp
    }
    ```

- **Confidential Burn Intent via Arcium**

    Unlike traditional burn logs stored in PDAs, this program leverages **Arcium confidential computing** for privacy-preserving withdrawals. When users burn wZEC, the program:
    1. Immediately burns tokens using SPL `burn` (reducing supply)
    2. Queues an encrypted computation to create a confidential burn intent
    3. Emits events containing encrypted withdrawal data (amount, recipient, burn ID)
    4. MPC nodes decrypt and process withdrawals off-chain, then finalize on-chain

    This approach keeps withdrawal details confidential while maintaining verifiable on-chain state transitions.

    ```rust
    // Burn event with encrypted data
    #[event]
    pub struct BurnIntentCreated {
        pub burn_id: u64,
        pub encrypted_burn_data: [u8; 32],  // Encrypted amount, address, user
        pub nonce: [u8; 16],
    }
    ```

- **Attestation Verification & Note Uniqueness via Arcium**

    The program uses **Arcium confidential computing** to verify enclave attestations privately. Attestations contain:
    - Note commitment (serves as nullifier)
    - Amount to mint
    - Recipient Solana address
    - Block height
    - Enclave signature

    Verification happens in a confidential computation environment where:
    1. Enclave signature is validated against the configured enclave authority
    2. Note commitment uniqueness is checked
    3. Block height and amount are validated
    4. On success, a callback instruction mints wZEC to the user

    A `ClaimTracker` PDA stores used note commitments to prevent double-minting. PDAs let the program manage these records without any private keys.

    ```rust
    pub struct ClaimTracker {
        pub bump: u8,
        pub note_commitment: [u8; 32],  // Prevents double-spending
        pub claimed_at: i64,
        pub deposit_id: u64,
    }
    ```

---

## **4.1.2 Accounts**

- **BridgeConfig PDA**

    Central configuration account storing critical bridge parameters. Seeds: `[b"bridge-config"]`

    ```rust
    pub struct BridgeConfig {
        pub bump: u8,
        pub admin: Pubkey,                      // Bridge administrator
        pub enclave_authority: Pubkey,          // Trusted enclave public key
        pub wzec_mint: Pubkey,                  // wZEC SPL mint address
        pub mint_authority_bump: u8,            // PDA bump for mint authority
        pub withdrawal_nonce: u64,              // Sequential burn/withdrawal ID
        pub deposit_nonce: u64,                 // Sequential deposit ID
        pub mpc_quorum_pubkeys: Vec<[u8; 32]>, // MPC node public keys (max 10)
        pub bridge_ufvk: Vec<u8>,              // Unified Full Viewing Key (max 512 bytes)
    }
    ```

- **Mint Account (wZEC SPL mint)**

    Standard SPL Token mint with 8 decimals. Stores total wZEC supply. Only the PDA mint authority may mint or burn.

    Program ID: `HefTNtytDcQgSQmBpPuwjGipbVcJTMRHnppU9poWRXhD`

- **DepositIntent PDA**

    Maps a user to their deposit intent with complete lifecycle tracking. Deterministic PDAs let clients derive the address without storing it.

    Seeds: `[b"deposit-intent", user_pubkey, deposit_id]`

    Status values: `0=Pending, 1=AddressGenerated, 2=Detected, 3=Minted, 4=Failed`

- **ClaimTracker PDA**

    Maps each Zcash note commitment to claimed status. Prevents re-minting from the same Zcash note.

    Seeds: `[b"claim-tracker", deposit_intent_pubkey]`

    Created during the `verify_attestation_callback` to mark a note commitment as used.

- **Mint Authority PDA**

    Program-controlled PDA with mint and burn authority. No private key exists.

    Seeds: `[b"mint-authority"]`

- **Enclave Authority Account**

    Public key stored in `BridgeConfig` used by Arcium confidential computations to verify attestation signatures. Set during `init_bridge`.

---

## **4.1.3 Instructions**

### **Initialization**

- **init_bridge**

    One-time initialization of bridge infrastructure. Must be called first.

    **Parameters:**
    - `admin: Pubkey` - Bridge administrator
    - `enclave_authority: Pubkey` - Trusted enclave public key for attestations
    - `mpc_quorum_pubkeys: Vec<[u8; 32]>` - MPC node public keys
    - `bridge_ufvk: Vec<u8>` - Bridge Unified Full Viewing Key

    **Actions:**
    - Creates BridgeConfig PDA
    - Initializes wZEC mint with 8 decimals
    - Sets up PDA mint authority
    - Stores MPC quorum and viewing key

    ```rust
    pub fn init_bridge(
        ctx: Context<InitBridge>,
        admin: Pubkey,
        enclave_authority: Pubkey,
        mpc_quorum_pubkeys: Vec<[u8; 32]>,
        bridge_ufvk: Vec<u8>,
    ) -> Result<()>
    ```

- **init_verify_attestation_comp_def / init_create_burn_comp_def / init_update_burn_comp_def**

    Initialize Arcium computation definitions for the three confidential operations:
    1. Attestation verification
    2. Burn intent creation
    3. Burn intent update/finalization

    Must be called once before the respective operations can be used.


### **Deposit Flow (ZEC → wZEC)**

- **init_intent**

    **Step 1:** User initiates deposit and receives a unique deposit ID. The diversifier index allows generating multiple unique UAs for the same user.

    **Parameters:**
    - `diversifier_index: u32` - Index for UA generation

    **Actions:**
    - Increments `bridge_config.deposit_nonce` to get unique deposit ID
    - Creates DepositIntent PDA with status `Pending`
    - Emits `DepositIntentCreated` event

    **Security:**
    - Each user+deposit_id combination creates a unique PDA
    - Prevents multiple simultaneous deposits to the same intent

    ```rust
    pub fn init_intent(
        ctx: Context<InitIntent>,
        diversifier_index: u32,
    ) -> Result<()>

    // Seeds: [b"deposit-intent", user.key(), deposit_nonce]
    ```

- **set_unified_address**

    **Step 2:** Admin or MPC API updates the deposit intent with the generated Unified Address.

    **Parameters:**
    - `deposit_id: u64` - The deposit intent to update
    - `unified_address: Vec<u8>` - Generated UA (max 256 bytes)

    **Actions:**
    - Validates caller is admin
    - Stores UA in DepositIntent
    - Updates status to `AddressGenerated`
    - Emits `UnifiedAddressSet` event

    **Security:**
    - Only admin can set UA
    - UA length validated (max 256 bytes)
    - Must be in `Pending` status

    ```rust
    pub fn set_unified_address(
        ctx: Context<SetUnifiedAddress>,
        deposit_id: u64,
        unified_address: Vec<u8>,
    ) -> Result<()>
    ```

- **mint_with_attestation**

    **Step 3:** User submits encrypted attestation from enclave. Queues confidential verification computation.

    **Parameters:**
    - `computation_offset: u64` - Arcium computation slot offset
    - `deposit_id: u64` - Deposit to mint for
    - `encrypted_attestation: [u8; 32]` - Encrypted attestation ciphertext
    - `pub_key: [u8; 32]` - Arcis public key for encryption
    - `nonce: u128` - Encryption nonce

    **Actions:**
    - Validates deposit intent status is `AddressGenerated`
    - Queues Arcium computation with encrypted attestation
    - Computation validates enclave signature, note commitment, amount
    - On success, `verify_attestation_callback` is automatically invoked

    **Security:**
    - Attestation verification happens in confidential computing environment
    - Cannot be front-run or manipulated
    - Must provide valid encrypted attestation matching the deposit intent

    ```rust
    pub fn mint_with_attestation(
        ctx: Context<MintWithAttestation>,
        computation_offset: u64,
        deposit_id: u64,
        encrypted_attestation: [u8; 32],
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()>

    // Queues confidential computation
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        None,
        vec![VerifyAttestationCallback::callback_ix(&[])],
        1,
    )?;
    ```

- **verify_attestation_callback**

    **Automatic callback** invoked by Arcium after attestation verification completes.

    **Parameters:**
    - `output: ComputationOutputs<VerifyAttestationOutput>` - Result from confidential computation

    **Actions:**
    - Validates computation succeeded
    - Creates ClaimTracker PDA to mark note commitment as used
    - Mints wZEC to user's token account using PDA authority
    - Updates deposit intent status to `Minted`
    - Emits `TokensMinted` event with encrypted attestation data

    **Security:**
    - Only callable by Arcium program after successful computation
    - Automatically prevents double-minting via ClaimTracker
    - Uses PDA signer for secure minting

    ```rust
    #[arcium_callback(encrypted_ix = "verify_attestation")]
    pub fn verify_attestation_callback(
        ctx: Context<VerifyAttestationCallback>,
        output: ComputationOutputs<VerifyAttestationOutput>,
    ) -> Result<()>

    // Minting with PDA authority
    let seeds = &[
        b"mint-authority".as_ref(),
        &[bridge_config.mint_authority_bump],
    ];
    let signer = &[&seeds[..]];

    token::mint_to(cpi_ctx, deposit_intent.amount)?;
    ```

### **Withdrawal Flow (wZEC → ZEC)**

- **burn_for_withdrawal**

    Burns wZEC and creates encrypted withdrawal intent via Arcium confidential computation.

    **Parameters:**
    - `computation_offset: u64` - Arcium computation slot offset
    - `amount: u64` - Amount of wZEC to burn (in zatoshis, 10^-8 ZEC)
    - `zcash_address: Vec<u8>` - Target Zcash Unified Address
    - `encrypted_data: [u8; 32]` - Encrypted withdrawal details
    - `pub_key: [u8; 32]` - Arcis public key
    - `nonce: u128` - Encryption nonce

    **Actions:**
    - Validates amount > 0 and address format (must start with `u1` or `utest1`)
    - Burns tokens immediately using SPL `burn` (reduces supply instantly)
    - Increments `bridge_config.withdrawal_nonce` to get burn ID
    - Queues confidential computation to create encrypted burn intent
    - Callback emits `BurnIntentCreated` event with encrypted data

    **Security:**
    - Tokens burned before computation (fail-safe design)
    - Address format validated
    - Withdrawal details encrypted, visible only to MPC nodes
    - Burn ID prevents replay attacks

    ```rust
    pub fn burn_for_withdrawal(
        ctx: Context<BurnForWithdrawal>,
        computation_offset: u64,
        amount: u64,
        zcash_address: Vec<u8>,
        encrypted_data: [u8; 32],
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()>

    // Immediate burn
    token::burn(cpi_ctx, amount)?;

    // Queue confidential burn intent creation
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        None,
        vec![CreateBurnIntentCallback::callback_ix(&[])],
        1,
    )?;
    ```

- **create_burn_intent_callback**

    Automatic callback after confidential burn intent computation completes.

    **Actions:**
    - Emits `BurnIntentCreated` event with encrypted burn data
    - Encrypted data includes: burn_id, user, amount, zcash_address, status
    - MPC nodes listen to this event and process withdrawal

    ```rust
    #[arcium_callback(encrypted_ix = "create_burn_intent")]
    pub fn create_burn_intent_callback(
        ctx: Context<CreateBurnIntentCallback>,
        output: ComputationOutputs<CreateBurnIntentOutput>,
    ) -> Result<()>
    ```

- **finalize_withdrawal**

    Called by MPC nodes after broadcasting the Zcash withdrawal transaction.

    **Parameters:**
    - `computation_offset: u64` - Arcium computation slot
    - `burn_id: u64` - Burn to finalize
    - `encrypted_txid: [u8; 32]` - Encrypted Zcash transaction ID
    - `pub_key: [u8; 32]` - Arcis public key
    - `nonce: u128` - Encryption nonce

    **Actions:**
    - Queues confidential computation to update burn intent status
    - Callback emits `WithdrawalFinalized` event with encrypted TXID

    **Security:**
    - Only MPC nodes can finalize (validated via signature)
    - Encrypted TXID provides verifiable proof
    - Prevents replay via burn_id tracking

    ```rust
    pub fn finalize_withdrawal(
        ctx: Context<FinalizeWithdrawal>,
        computation_offset: u64,
        burn_id: u64,
        encrypted_txid: [u8; 32],
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()>
    ```

### **Administrative**

- **demo_mint**

    **Admin-only** instruction for testing. Mints arbitrary wZEC without attestation.

    **Security:** Only callable by configured admin. Should be disabled in production.


---

## **4.1.4 Confidential Computing with Arcium**

This bridge leverages **Arcium** for privacy-preserving operations. Arcium provides a confidential computing layer where sensitive computations execute off-chain in a trusted execution environment, with results verified on-chain.

### **Encrypted Instructions**

The bridge defines three confidential computations in `encrypted-ixs/src/lib.rs`:

1. **verify_attestation** - Validates enclave attestations

    ```rust
    pub struct AttestationInput {
        pub note_commitment: [u8; 32],
        pub amount: u64,
        pub recipient_solana: [u8; 32],
        pub block_height: u64,
        pub enclave_signature: [u8; 64],
        pub enclave_pubkey: [u8; 32],
    }

    #[instruction]
    pub fn verify_attestation(
        input_ctxt: Enc<Shared, AttestationInput>,
    ) -> Enc<Shared, bool>
    ```

2. **create_burn_intent** - Creates encrypted withdrawal record

    ```rust
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
        pub status: u8,  // 0=Pending, 1=Processing, 2=Completed
    }

    #[instruction]
    pub fn create_burn_intent(
        input_ctxt: Enc<Shared, BurnIntentInput>,
        burn_id: u64,
    ) -> Enc<Shared, BurnIntentOutput>
    ```

3. **update_burn_intent** - Finalizes withdrawal with TXID

    ```rust
    pub struct UpdateBurnIntentInput {
        pub burn_intent: BurnIntentOutput,
        pub zcash_txid: [u8; 32],
        pub new_status: u8,
    }

    #[instruction]
    pub fn update_burn_intent(
        input_ctxt: Enc<Shared, UpdateBurnIntentInput>,
    ) -> Enc<Shared, BurnIntentOutput>
    ```

### **Computation Flow**

1. **Queue:** On-chain instruction queues computation with encrypted inputs
2. **Execute:** Arcium network executes computation in confidential environment
3. **Callback:** Result triggers automatic callback instruction with outputs
4. **State Update:** Callback updates on-chain state or emits events

### **Privacy Guarantees**

- Attestation details (note commitment, amount) remain encrypted during verification
- Withdrawal addresses and amounts encrypted, only visible to authorized MPC nodes
- On-chain events contain only encrypted ciphertexts
- Arcium nodes cannot collude to decrypt without proper authorization
