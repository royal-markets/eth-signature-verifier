use {
    alloy_primitives::{eip191_hash_message, keccak256, Address, Bytes, Uint, B256, U256},
    alloy_provider::Provider,
    alloy_rpc_types::{BlockId, TransactionInput, TransactionRequest},
    alloy_sol_types::{sol, SolConstructor, SolValue},
    alloy_transport::{Transport, TransportErrorKind},
    k256::{
        ecdsa::{RecoveryId, Signature, VerifyingKey},
        elliptic_curve::sec1::ToEncodedPoint,
    },
    log::{debug, error},
    thiserror::*,
};

/// The expected result for a successful signature verification.
const SUCCESS_RESULT: u8 = 0x01;

/// The magic bytes used to detect ERC-6492 signatures.
const ERC6492_DETECTION_SUFFIX: [u8; 32] = [
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
];

sol! {
  contract ValidateSigOffchain {
    constructor (address _signer, bytes32 _hash, bytes memory _signature);
  }
}

sol! {
    struct ERC6492SignatureData {
        address create2_factory;
        bytes factory_calldata;
        bytes signature;
    }

    contract Create2 {
        function computeAddress(bytes32 salt, bytes32 bytecodeHash) external view returns (address) {}
    }
}
const VALIDATE_SIG_OFFCHAIN_BYTECODE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/../../../../.foundry/forge/out/Erc6492.sol/ValidateSigOffchain.bytecode"
));

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    Valid,
    Invalid,
}

impl Verification {
    pub fn is_valid(self) -> bool {
        matches!(self, Verification::Valid)
    }
}

/// Represents errors that can occur during signature operations.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Ecrecover error")]
    EcrecoverError,
    #[error("Provider error: {0}")]
    ProviderError(#[from] RpcError),
    #[error("Decode error")]
    DecodeError,
}
pub type RpcError = alloy_json_rpc::RpcError<TransportErrorKind>;
fn compute_address_call(salt: B256, bytecode_hash: B256) -> Bytes {
    let selector = keccak256("computeAddress(bytes32,bytes32)")[..4].to_vec();
    let mut call_data = selector;
    call_data.extend_from_slice(&salt.0);
    call_data.extend_from_slice(&bytecode_hash.0);
    call_data.into()
}

fn bytes_to_usize(bytes: &[u8]) -> usize {
    let mut padded = [0u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(bytes);
    u64::from_be_bytes(padded) as usize
}

/// Extracts the signer's address from a signature.
///
/// This function supports EOA, ERC-1271, and ERC-6492 signatures.
///
/// # Arguments
///
/// * `signature` - The signature to extract the address from.
/// * `message` - The original message that was signed.
///
/// # Returns
///
/// The extracted address or an error if the extraction fails.
pub async fn extract_address<S, M, P, T>(
    signature: S,
    message: M,
    provider: P,
) -> Result<Address, SignatureError>
where
    S: Into<Bytes>,
    M: AsRef<[u8]>,
    P: Provider<T>,
    T: Transport + Clone,
{
    let signature: Bytes = signature.into();
    let message_hash = eip191_hash_message(message);

    println!("Full signature: {:?}", signature);

    if signature.len() >= 32 && signature[signature.len() - 32..] == ERC6492_DETECTION_SUFFIX {
        // ERC-6492 signature
        let sig_data = &signature[..signature.len() - 32];

        println!("ERC-6492 signature data length: {}", sig_data.len());

        if sig_data.len() < 20 + 32 + 32 {
            return Err(SignatureError::InvalidSignature);
        }

        let create2_factory = Address::from_slice(&sig_data[12..32]);
        println!("CREATE2 factory address: {:?}", create2_factory);

        let factory_calldata_offset = bytes_to_usize(&sig_data[60..64]);
        let signature_offset = bytes_to_usize(&sig_data[92..96]);

        println!("Factory calldata offset: {}", factory_calldata_offset);
        println!("Signature offset: {}", signature_offset);

        if factory_calldata_offset + 32 > sig_data.len() || signature_offset + 32 > sig_data.len() {
            return Err(SignatureError::InvalidSignature);
        }

        let factory_calldata_len =
            bytes_to_usize(&sig_data[factory_calldata_offset..factory_calldata_offset + 32]);
        println!("Factory calldata length: {}", factory_calldata_len);

        if factory_calldata_offset + 32 + factory_calldata_len > sig_data.len() {
            return Err(SignatureError::InvalidSignature);
        }

        let factory_calldata = &sig_data
            [factory_calldata_offset + 32..factory_calldata_offset + 32 + factory_calldata_len];
        println!("Factory calldata: {:?}", factory_calldata);

        if factory_calldata.len() < 68 {
            return Err(SignatureError::InvalidSignature);
        }

        let salt = B256::from_slice(&factory_calldata[4..36]);
        println!("Salt: {:?}", salt);

        println!("Bytecode offset bytes: {:?}", &factory_calldata[36..40]);
        let bytecode_offset = bytes_to_usize(&factory_calldata[36..40]);
        println!("Bytecode offset: {}", bytecode_offset);

        if bytecode_offset + 4 > factory_calldata.len() {
            return Err(SignatureError::InvalidSignature);
        }

        println!(
            "Bytecode length bytes: {:?}",
            &factory_calldata[bytecode_offset..bytecode_offset + 4]
        );
        let bytecode_len = bytes_to_usize(&factory_calldata[bytecode_offset..bytecode_offset + 4]);
        println!("Bytecode length: {}", bytecode_len);

        if bytecode_offset + 4 + bytecode_len > factory_calldata.len() {
            return Err(SignatureError::InvalidSignature);
        }

        let bytecode = &factory_calldata[bytecode_offset + 4..bytecode_offset + 4 + bytecode_len];
        let bytecode_hash = keccak256(bytecode);

        println!("Bytecode length: {}", bytecode.len());
        println!("Bytecode hash: {:?}", bytecode_hash);

        let call_data = compute_address_call(salt, bytecode_hash);
        let tx = TransactionRequest {
            to: Some(create2_factory),
            input: call_data.into(),
            ..Default::default()
        };

        let result = provider
            .call(&tx, BlockId::latest())
            .await
            .map_err(|e| SignatureError::ProviderError(e))?;

        println!("computeAddress result: {:?}", result);

        if result.len() < 32 {
            return Err(SignatureError::InvalidSignature);
        }
        let contract_address = Address::from_slice(&result[12..32]);

        println!("Computed contract address: {:?}", contract_address);

        Ok(contract_address)
    } else if signature.len() == 65 {
        // EOA signature
        let v = signature[64];
        let r = U256::from_be_bytes::<32>(signature[0..32].try_into().unwrap());
        let s = U256::from_be_bytes::<32>(signature[32..64].try_into().unwrap());
        ecrecover(message_hash, v, r, s)
    } else {
        // ERC-1271 signature
        // The format is typically: contract_address (20 bytes) + signature_data
        if signature.len() < 20 {
            return Err(SignatureError::InvalidSignature);
        }
        let contract_address = Address::from_slice(&signature[0..20]);
        Ok(contract_address)
    }
}

/// Verifies a signature automatically by extracting the signer's address.
///
/// This function first extracts the signer's address from the signature and then
/// verifies the signature using that address.
///
/// # Arguments
///
/// * `signature` - The signature to verify.
/// * `message` - The original message that was signed.
/// * `provider` - The provider used for making RPC calls.
///
/// # Returns
///
/// A `Verification` enum indicating whether the signature is valid or invalid.
pub async fn verify_signature_auto<S, M, P, T>(
    signature: S,
    message: M,
    provider: P,
) -> Result<Verification, RpcError>
where
    S: Into<Bytes> + Clone,
    M: AsRef<[u8]> + Clone,
    P: Provider<T>,
    T: Transport + Clone,
{
    let address = extract_address(signature.clone(), message.clone(), &provider)
        .await
        .unwrap();
    verify_signature(signature, address, message, provider).await
}

/// Recovers the signer's address from an ECDSA signature.
///
/// # Arguments
///
/// * `hash` - The 32-byte hash of the signed message.
/// * `v` - The recovery id.
/// * `r` - The r component of the signature.
/// * `s` - The s component of the signature.
///
/// # Returns
///
/// The recovered signer's address or an error if recovery fails.
fn ecrecover(hash: B256, v: u8, r: U256, s: U256) -> Result<Address, SignatureError> {
    let recovery_id =
        RecoveryId::from_byte(v.checked_sub(27).ok_or(SignatureError::InvalidSignature)?)
            .ok_or(SignatureError::InvalidSignature)?;
    let r_bytes: [u8; 32] = r.to_be_bytes();
    let s_bytes: [u8; 32] = s.to_be_bytes();

    let signature =
        Signature::from_scalars(r_bytes, s_bytes).map_err(|_| SignatureError::InvalidSignature)?;

    let verifying_key =
        VerifyingKey::recover_from_prehash(hash.as_slice(), &signature, recovery_id)
            .map_err(|_| SignatureError::EcrecoverError)?;

    let public_key = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key.as_bytes();

    let address = Address::from_slice(&keccak256(&public_key_bytes[1..])[12..]);
    Ok(address)
}

/// Verify a signature using ERC-6492.
///
/// This will return `Ok(Verification::Valid)` if the signature passes verification.
/// If the signature is invalid, it will return `Ok(Verification::Invalid)`.
///
/// If an error occurs while making the RPC call, it will return `Err(RpcError)`.
pub async fn verify_signature<S, M, P, T>(
    signature: S,
    address: Address,
    message: M,
    provider: P,
) -> Result<Verification, RpcError>
where
    S: Into<Bytes>,
    M: AsRef<[u8]>,
    P: Provider<T>,
    T: Transport + Clone,
{
    let call = ValidateSigOffchain::constructorCall {
        _signer: address,
        _hash: eip191_hash_message(message),
        _signature: signature.into(),
    };
    let bytes = VALIDATE_SIG_OFFCHAIN_BYTECODE
        .iter()
        .cloned()
        .chain(call.abi_encode())
        .collect::<Vec<u8>>();
    let transaction_request =
        TransactionRequest::default().input(TransactionInput::new(bytes.into()));

    let result = provider
        .call(&transaction_request, Default::default())
        .await;

    match result {
        Err(e) => {
            if let Some(error_response) = e.as_error_resp() {
                if error_response.message.starts_with("execution reverted") {
                    Ok(Verification::Invalid)
                } else {
                    Err(e)
                }
            } else {
                Err(e)
            }
        }
        Ok(result) => {
            if let Some(result) = result.first() {
                if result == &SUCCESS_RESULT {
                    Ok(Verification::Valid)
                } else {
                    Ok(Verification::Invalid)
                }
            } else {
                Ok(Verification::Invalid)
            }
        }
    }
}

#[cfg(test)]
mod test_helpers;

#[cfg(test)]
mod test {
    use {
        super::*,
        alloy_primitives::{address, b256, bytes, Uint, U256},
        alloy_provider::{network::Ethereum, ReqwestProvider},
        alloy_sol_types::{SolCall, SolValue},
        k256::ecdsa::SigningKey,
        test_helpers::{
            deploy_contract, sign_message, spawn_anvil, CREATE2_CONTRACT, ERC1271_MOCK_CONTRACT,
        },
    };

    // Manual test. Paste address, signature, message, and project ID to verify
    // function
    #[tokio::test]
    #[ignore]
    async fn manual() {
        let address = address!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let message = "xxx";
        let signature = bytes!("aaaa");

        let provider = ReqwestProvider::<Ethereum>::new_http(
            "https://rpc.walletconnect.com/v1?chainId=eip155:1&projectId=xxx"
                .parse()
                .unwrap(),
        );
        assert!(verify_signature(signature, address, message, provider)
            .await
            .unwrap()
            .is_valid());
    }

    #[tokio::test]
    async fn test_extract_address_eoa() {
        let (_anvil, _rpc_url, provider, private_key) = spawn_anvil();
        let message = "test message";
        let signature = sign_message(message, &private_key);
        let expected_address = Address::from_private_key(&private_key);
        let extracted_address = extract_address(signature.clone(), message, provider.clone())
            .await
            .unwrap();
        assert_eq!(extracted_address, expected_address);
    }

    #[tokio::test]
    async fn test_extract_address_erc1271() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let contract_address = deploy_contract(
            &rpc_url,
            &private_key,
            ERC1271_MOCK_CONTRACT,
            Some(&Address::from_private_key(&private_key).to_string()),
        )
        .await;
        let message = "test message";
        let signature = sign_message(message, &private_key);
        // Use the raw bytes of the Address
        let erc1271_signature = [contract_address.as_slice(), signature.as_ref()].concat();
        let extracted_address = extract_address(erc1271_signature, message, provider.clone())
            .await
            .unwrap();
        assert_eq!(extracted_address, contract_address);
    }

    #[tokio::test]
    async fn test_extract_address_erc6492() {
        env_logger::init();

        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;
        let message = "test message";
        let signature = sign_message(message, &private_key);
        let (predeploy_address, erc6492_signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        println!("ERC-6492 Signature length: {}", erc6492_signature.len());
        println!("Predeploy address: {:?}", predeploy_address);
        println!("CREATE2 factory address: {:?}", create2_factory_address);
        println!("ERC-6492 Signature: {:?}", erc6492_signature);

        println!("ERC-6492 Signature: {:?}", erc6492_signature);

        // Print the salt and bytecode used in predeploy_signature
        let sig_data = &erc6492_signature[..erc6492_signature.len() - 32];
        let factory_calldata_offset = bytes_to_usize(&sig_data[60..64]);
        println!("Test: Factory calldata offset: {}", factory_calldata_offset);
        let factory_calldata_len =
            bytes_to_usize(&sig_data[factory_calldata_offset..factory_calldata_offset + 32]);
        println!("Test: Factory calldata length: {}", factory_calldata_len);
        let factory_calldata = &sig_data
            [factory_calldata_offset + 32..factory_calldata_offset + 32 + factory_calldata_len];
        println!("Test: Factory calldata: {:?}", factory_calldata);
        let salt = B256::from_slice(&factory_calldata[4..36]);
        println!("Test: Salt: {:?}", salt);
        println!(
            "Test: Bytecode offset bytes: {:?}",
            &factory_calldata[36..40]
        );
        let bytecode_offset = bytes_to_usize(&factory_calldata[36..40]);
        println!("Test: Bytecode offset: {}", bytecode_offset);
        println!(
            "Test: Bytecode length bytes: {:?}",
            &factory_calldata[bytecode_offset..bytecode_offset + 4]
        );
        let bytecode_len = bytes_to_usize(&factory_calldata[bytecode_offset..bytecode_offset + 4]);
        println!("Test: Bytecode length: {}", bytecode_len);
        let bytecode = &factory_calldata[bytecode_offset + 4..bytecode_offset + 4 + bytecode_len];
        let bytecode_hash = keccak256(bytecode);
        println!("Test: Bytecode length: {}", bytecode.len());
        println!("Test: Bytecode hash: {:?}", bytecode_hash);

        let extracted_address = extract_address(erc6492_signature, message, provider)
            .await
            .unwrap();
        assert_eq!(extracted_address, predeploy_address);
    }
    #[tokio::test]
    async fn eoa_pass() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();

        let private_key = SigningKey::random(&mut rand::thread_rng());
        let message = "xxx";
        let signature = sign_message(message, &private_key);
        let address = Address::from_private_key(&private_key);
        assert!(verify_signature(signature, address, message, provider)
            .await
            .unwrap()
            .is_valid());
    }

    #[tokio::test]
    async fn eoa_wrong_signature() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();

        let private_key = SigningKey::random(&mut rand::thread_rng());
        let message = "xxx";
        let mut signature = sign_message(message, &private_key);
        *signature.first_mut().unwrap() = signature.first().unwrap().wrapping_add(1);
        let address = Address::from_private_key(&private_key);
        assert!(!verify_signature(signature, address, message, provider)
            .await
            .unwrap()
            .is_valid());
    }

    #[tokio::test]
    async fn eoa_wrong_address() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();

        let private_key = SigningKey::random(&mut rand::thread_rng());
        let message = "xxx";
        let signature = sign_message(message, &private_key);
        let mut address = Address::from_private_key(&private_key);
        *address.0.first_mut().unwrap() = address.0.first().unwrap().wrapping_add(1);
        assert!(!verify_signature(signature, address, message, provider)
            .await
            .unwrap()
            .is_valid());
    }

    #[tokio::test]
    async fn eoa_wrong_message() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();

        let private_key = SigningKey::random(&mut rand::thread_rng());
        let message = "xxx";
        let signature = sign_message(message, &private_key);
        let address = Address::from_private_key(&private_key);
        let message2 = "yyy";
        assert!(!verify_signature(signature, address, message2, provider)
            .await
            .unwrap()
            .is_valid());
    }

    #[tokio::test]
    async fn erc1271_pass() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let contract_address = deploy_contract(
            &rpc_url,
            &private_key,
            ERC1271_MOCK_CONTRACT,
            Some(&Address::from_private_key(&private_key).to_string()),
        )
        .await;

        let message = "xxx";
        let signature = sign_message(message, &private_key);

        assert!(
            verify_signature(signature, contract_address, message, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn erc1271_wrong_signature() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let contract_address = deploy_contract(
            &rpc_url,
            &private_key,
            ERC1271_MOCK_CONTRACT,
            Some(&Address::from_private_key(&private_key).to_string()),
        )
        .await;

        let message = "xxx";
        let mut signature = sign_message(message, &private_key);
        *signature.first_mut().unwrap() = signature.first().unwrap().wrapping_add(1);

        assert!(
            !verify_signature(signature, contract_address, message, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    async fn erc1271_wrong_signer() {
        let (anvil, rpc_url, provider, private_key) = spawn_anvil();
        let contract_address = deploy_contract(
            &rpc_url,
            &private_key,
            ERC1271_MOCK_CONTRACT,
            Some(&Address::from_private_key(&private_key).to_string()),
        )
        .await;

        let message = "xxx";
        let signature = sign_message(
            message,
            &SigningKey::from_bytes(&anvil.keys().get(1).unwrap().to_bytes()).unwrap(),
        );

        assert!(
            !verify_signature(signature, contract_address, message, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn erc1271_wrong_contract_address() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let mut contract_address = deploy_contract(
            &rpc_url,
            &private_key,
            ERC1271_MOCK_CONTRACT,
            Some(&Address::from_private_key(&private_key).to_string()),
        )
        .await;

        *contract_address.0.first_mut().unwrap() =
            contract_address.0.first().unwrap().wrapping_add(1);

        let message = "xxx";
        let signature = sign_message(message, &private_key);

        assert!(
            !verify_signature(signature, contract_address, message, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn erc1271_wrong_message() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let contract_address = deploy_contract(
            &rpc_url,
            &private_key,
            ERC1271_MOCK_CONTRACT,
            Some(&Address::from_private_key(&private_key).to_string()),
        )
        .await;

        let message = "xxx";
        let signature = sign_message(message, &private_key);

        let message2 = "yyy";
        assert!(
            !verify_signature(signature, contract_address, message2, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    const ERC1271_MOCK_BYTECODE: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/../../../../.foundry/forge/out/Erc1271Mock.sol/Erc1271Mock.bytecode"
    ));
    const ERC6492_MAGIC_BYTES: [u16; 16] = [
        0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492,
        0x6492, 0x6492, 0x6492, 0x6492, 0x6492,
    ];
    sol! {
        contract Erc1271Mock {
            address owner_eoa;

            constructor(address owner_eoa) {
                owner_eoa = owner_eoa;
            }
        }
    }

    sol! {
        contract Create2 {
            function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) external payable returns (address addr);
        }
    }

    fn predeploy_signature(
        owner_eoa: Address,
        create2_factory_address: Address,
        signature: Vec<u8>,
    ) -> (Address, Vec<u8>) {
        let salt = b256!("7c5ea36004851c764c44143b1dcb59679b11c9a68e5f41497f6cf3d480715331");
        let contract_bytecode = ERC1271_MOCK_BYTECODE;
        let contract_constructor = Erc1271Mock::constructorCall { owner_eoa };

        let bytecode = contract_bytecode
            .iter()
            .cloned()
            .chain(contract_constructor.abi_encode())
            .collect::<Vec<u8>>();
        let predeploy_address = create2_factory_address.create2_from_code(salt, bytecode.clone());
        let signature = (
            create2_factory_address,
            Create2::deployCall {
                amount: Uint::ZERO,
                salt,
                bytecode: bytecode.into(),
            }
            .abi_encode(),
            signature,
        )
            .abi_encode_sequence()
            .into_iter()
            .chain(
                ERC6492_MAGIC_BYTES
                    .iter()
                    .flat_map(|&x| x.to_be_bytes().into_iter()),
            )
            .collect::<Vec<u8>>();
        (predeploy_address, signature)
    }

    #[tokio::test]
    async fn erc6492_pass() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let signature = sign_message(message, &private_key);
        let (predeploy_address, signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        assert!(
            verify_signature(signature, predeploy_address, message, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn erc6492_wrong_signature() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let mut signature = sign_message(message, &private_key);
        *signature.first_mut().unwrap() = signature.first().unwrap().wrapping_add(1);
        let (predeploy_address, signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        assert!(
            !verify_signature(signature, predeploy_address, message, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    async fn erc6492_wrong_signer() {
        let (anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let signature = sign_message(
            message,
            &SigningKey::from_bytes(&anvil.keys().get(1).unwrap().to_bytes()).unwrap(),
        );
        let (predeploy_address, signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        assert!(
            !verify_signature(signature, predeploy_address, message, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    async fn erc6492_wrong_contract_address() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let signature = sign_message(message, &private_key);
        let (mut predeploy_address, signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        *predeploy_address.0.first_mut().unwrap() =
            predeploy_address.0.first().unwrap().wrapping_add(1);

        assert!(
            !verify_signature(signature, predeploy_address, message, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    async fn erc6492_wrong_message() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let signature = sign_message(message, &private_key);
        let (predeploy_address, signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        let message2 = "yyy";
        assert!(
            !verify_signature(signature, predeploy_address, message2, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }
}
