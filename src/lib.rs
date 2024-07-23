use {
    alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256, U256},
    alloy_provider::Provider,
    alloy_rpc_types::{BlockId, TransactionInput, TransactionRequest},
    alloy_sol_types::{sol, SolConstructor},
    alloy_transport::{Transport, TransportErrorKind},
    k256::ecdsa::{RecoveryId, Signature, VerifyingKey},
    log::error,
};

/// The expected result for a successful signature verification.
const SUCCESS_RESULT: u8 = 0x01;

/// The magic bytes used to detect ERC-6942 signatures.
const ERC6942_DETECTION_SUFFIX: [u8; 32] = [
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
];

const VALIDATE_SIG_OFFCHAIN_BYTECODE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/../../../../.foundry/forge/out/Erc6942.sol/ValidateSigOffchain.bytecode"
));

sol! {
  contract ValidateSigOffchain {
    constructor (address _signer, bytes32 _hash, bytes memory _signature);
    function isValidSig(address _signer, bytes32 _hash, bytes memory _signature) external view returns (bool);
  }
}

sol! {
    struct ERC6942SignatureData {
        address create2_factory;
        bytes factory_calldata;
        bytes signature;
    }

    contract Create2 {
        function computeAddress(bytes32 salt, bytes32 bytecodeHash) external view returns (address) {}
    }
}

sol! {
    struct ERC6942Signature {
        address create2_factory;
        bytes factory_calldata;
        bytes signature;
    }
}

/// Represents the result of a signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Verification {
    Valid,
    Invalid,
}

impl Verification {
    /// Returns true if the verification is valid.
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

// Parses an ERC-6942 signature into its components.
//
// # Arguments
//
// * `sig_data` - The ERC-6942 signature data to parse.
//
// # Returns
//
// A tuple containing the CREATE2 factory address, factory calldata, and the original signature.
fn parse_erc6942_signature(sig_data: &[u8]) -> Result<(Address, Vec<u8>, Vec<u8>), SignatureError> {
    if sig_data.len() < 96 {
        return Err(SignatureError::InvalidSignature);
    }

    let create2_factory = Address::from_slice(&sig_data[12..32]);
    let factory_calldata_offset = bytes_to_usize(&sig_data[32..64]);
    let signature_offset = bytes_to_usize(&sig_data[64..96]);

    if factory_calldata_offset >= sig_data.len() || signature_offset >= sig_data.len() {
        return Err(SignatureError::InvalidSignature);
    }

    let factory_calldata_len =
        bytes_to_usize(&sig_data[factory_calldata_offset..factory_calldata_offset + 32]);
    if factory_calldata_offset + 32 + factory_calldata_len > sig_data.len() {
        return Err(SignatureError::InvalidSignature);
    }
    let factory_calldata = sig_data
        [factory_calldata_offset + 32..factory_calldata_offset + 32 + factory_calldata_len]
        .to_vec();

    let signature_len = bytes_to_usize(&sig_data[signature_offset..signature_offset + 32]);
    if signature_offset + 32 + signature_len > sig_data.len() {
        return Err(SignatureError::InvalidSignature);
    }
    let signature = sig_data[signature_offset + 32..signature_offset + 32 + signature_len].to_vec();

    Ok((create2_factory, factory_calldata, signature))
}
// Converts a byte slice to a usize.
fn bytes_to_usize(bytes: &[u8]) -> usize {
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    let value = U256::from_be_bytes(padded);
    value.as_limbs()[0].try_into().unwrap()
}

/// Extracts the signer's address from a signature.
///
/// This function supports EOA, ERC-1271, and ERC-6942 signatures.
///
/// # Arguments
///
/// * `signature` - The signature to extract the address from.
/// * `message` - The original message that was signed.
/// * `provider` - The provider used for making RPC calls.
///
/// # Returns
///
/// The extracted address or an error if the extraction fails.
pub async fn extract_address<S, P, T>(
    signature: S,
    message: FixedBytes<32>,
    provider: P,
) -> Result<Address, SignatureError>
where
    S: Into<Bytes>,
    P: Provider<T>,
    T: Transport + Clone,
{
    let signature: Bytes = signature.into();

    if signature.len() >= 32 && signature[signature.len() - 32..] == ERC6942_DETECTION_SUFFIX {
        let sig_data = &signature[..signature.len() - 32];
        let (create2_factory, factory_calldata, original_signature) =
            parse_erc6942_signature(sig_data)?;

        let tx = TransactionRequest {
            to: Some(create2_factory),
            input: factory_calldata.into(),
            ..Default::default()
        };

        let result = provider
            .call(&tx, BlockId::latest())
            .await
            .map_err(SignatureError::ProviderError)?;

        if result.len() < 20 {
            // If the contract is already deployed, we should fall back to standard signature verification
            return ecrecover_address(message, &original_signature);
        }

        Ok(Address::from_slice(&result[result.len() - 20..]))
    } else if signature.len() == 65 {
        ecrecover_address(message, &signature)
    } else {
        if signature.len() < 20 {
            return Err(SignatureError::InvalidSignature);
        }
        Ok(Address::from_slice(&signature[0..20]))
    }
}

fn ecrecover_address(message: FixedBytes<32>, signature: &[u8]) -> Result<Address, SignatureError> {
    if signature.len() != 65 {
        return Err(SignatureError::InvalidSignature);
    }

    let v = signature[64];
    let r = U256::from_be_bytes::<32>(signature[0..32].try_into().unwrap());
    let s = U256::from_be_bytes::<32>(signature[32..64].try_into().unwrap());

    ecrecover(B256::from(message), v, r, s)
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
    message: FixedBytes<32>,
    provider: P,
) -> Result<Verification, RpcError>
where
    S: Into<Bytes> + Clone,
    // M: AsRef<[u8]> + Clone,
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

    Ok(Address::from_slice(
        &keccak256(&public_key_bytes[1..])[12..],
    ))
}

/// Verifies a signature using ERC-6942.
///
/// # Arguments
///
/// * `signature` - The signature to verify.
/// * `address` - The address to verify against.
/// * `message` - The original message that was signed.
/// * `provider` - The provider used for making RPC calls.
///
/// # Returns
///
/// A `Verification` enum indicating whether the signature is valid or invalid.
/// If an error occurs while making the RPC call, it will return `Err(RpcError)`.
pub async fn verify_signature<S, P, T>(
    signature: S,
    address: Address,
    message: FixedBytes<32>,
    provider: P,
) -> Result<Verification, RpcError>
where
    S: Into<Bytes>,
    P: Provider<T>,
    T: Transport + Clone,
{
    let call = ValidateSigOffchain::constructorCall {
        _signer: address,
        _hash: message,
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
        alloy_dyn_abi::eip712::TypedData,
        alloy_primitives::{address, b256, bytes, keccak256, Address, Uint, B256, I256, U256},
        alloy_provider::{network::Ethereum, ReqwestProvider},
        alloy_signer::{Signer, SignerSync},
        alloy_signer_local::PrivateKeySigner,
        alloy_sol_types::{eip712_domain, sol, SolCall, SolValue},
        k256::ecdsa::SigningKey,
        serde::Serialize,
        serial_test::serial,
        test_helpers::{
            deploy_contract, message_str_to_bytes, sign_message_eip191, spawn_anvil,
            CREATE2_CONTRACT, ERC1271_MOCK_CONTRACT,
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
        let message_bytes = message_str_to_bytes(message);
        assert!(
            verify_signature(signature, address, message_bytes, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_extract_address_eoa() {
        let (_anvil, _rpc_url, provider, private_key) = spawn_anvil();
        let message = "test message";
        let message_bytes = alloy_primitives::eip191_hash_message(message.as_bytes());
        let signature = sign_message_eip191(message, &private_key);
        let expected_address = Address::from_private_key(&private_key);
        let extracted_address = extract_address(signature.clone(), message_bytes, provider.clone())
            .await
            .unwrap();
        assert_eq!(extracted_address, expected_address);
    }

    #[tokio::test]
    #[serial]
    async fn test_extract_address_eip721() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();
        sol! {
            #[derive(Debug, Serialize)]
            struct FooBar {
                int256 foo;
                uint256 bar;
                bytes fizz;
                bytes32 buzz;
                string far;
                address out;
            }
        }

        let signer = PrivateKeySigner::random();

        let chain_id = provider.get_chain_id().await.unwrap();
        let signer = signer.with_chain_id(Some(chain_id));

        let domain = eip712_domain! {
            name: "Eip712Test",
            version: "1",
            chain_id: chain_id,
            verifying_contract: signer.address(),
            salt: keccak256("eip712-test-75F0CCte"),
        };
        let foo_bar = FooBar {
            foo: I256::try_from(10u64).unwrap(),
            bar: U256::from(20u64),
            fizz: b"fizz".to_vec().into(),
            buzz: keccak256("buzz"),
            far: "space".into(),
            out: Address::ZERO,
        };

        let foo_bar_dynamic = TypedData::from_struct(&foo_bar, Some(domain.clone()));
        let dynamic_hash = foo_bar_dynamic.eip712_signing_hash().unwrap();
        let sig_dynamic = signer.sign_hash_sync(&dynamic_hash).unwrap();
        let signature: Bytes = sig_dynamic.as_bytes().to_vec().into();

        let extracted_address = extract_address(signature, dynamic_hash, provider)
            .await
            .unwrap();

        assert_eq!(extracted_address, signer.address());
    }

    #[tokio::test]
    #[serial]
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
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(message, &private_key);
        // Use the raw bytes of the Address
        let erc1271_signature = [contract_address.as_slice(), signature.as_ref()].concat();
        let extracted_address = extract_address(erc1271_signature, message_bytes, provider.clone())
            .await
            .unwrap();
        assert_eq!(extracted_address, contract_address);
    }

    #[tokio::test]
    #[ignore]
    async fn test_extract_address_erc6942() {
        env_logger::init();

        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;
        let message = "test message";
        let message_bytes = alloy_primitives::eip191_hash_message(message.as_bytes());
        let signature = sign_message_eip191(message, &private_key);
        let (predeploy_address, erc6942_signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        // Print the salt and bytecode used in predeploy_signature
        let sig_data = &erc6942_signature[..erc6942_signature.len() - 32];
        let factory_calldata_offset = bytes_to_usize(&sig_data[64..96]);
        if factory_calldata_offset < sig_data.len() {
            let factory_calldata = &sig_data[factory_calldata_offset..];
            if factory_calldata.len() >= 36 {
                let _salt = B256::from_slice(&factory_calldata[4..36]);
                if factory_calldata.len() >= 68 {
                    let bytecode_offset = bytes_to_usize(&factory_calldata[36..68]);
                    if bytecode_offset + 32 <= factory_calldata.len() {
                        let bytecode_len = bytes_to_usize(
                            &factory_calldata[bytecode_offset..bytecode_offset + 32],
                        );
                        if bytecode_offset + 32 + bytecode_len <= factory_calldata.len() {
                            let bytecode = &factory_calldata
                                [bytecode_offset + 32..bytecode_offset + 32 + bytecode_len];
                            let _bytecode_hash = keccak256(bytecode);
                        } else {
                            println!("Test: Bytecode length exceeds factory calldata length");
                        }
                    } else {
                        println!("Test: Bytecode offset + 32 exceeds factory calldata length");
                    }
                } else {
                    println!("Test: Factory calldata length < 68");
                }
            } else {
                println!("Test: Factory calldata length < 36");
            }
        } else {
            println!("Test: Factory calldata offset exceeds signature data length");
        }

        let extracted_address = extract_address(erc6942_signature, message_bytes, provider)
            .await
            .unwrap();

        assert_eq!(extracted_address, predeploy_address);
    }
    #[tokio::test]
    #[serial]
    async fn eoa_pass() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();

        let private_key = SigningKey::random(&mut rand::thread_rng());
        let message = "xxx";
        let eip191_message = alloy_primitives::eip191_hash_message(message);
        let signature = sign_message_eip191(&message, &private_key);
        let signature_bytes = Bytes::from(signature.to_vec());
        // let signature_2 = sign_message_digest(message_bytes, &mut private_key);
        let address = Address::from_private_key(&private_key);

        assert!(
            verify_signature(signature_bytes, address, eip191_message, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    #[serial]
    async fn eoa_wrong_signature() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();

        let private_key = SigningKey::random(&mut rand::thread_rng());
        let message = "xxx";
        let mut signature = sign_message_eip191(message, &private_key);
        *signature.first_mut().unwrap() = signature.first().unwrap().wrapping_add(1);
        let address = Address::from_private_key(&private_key);
        let message_bytes = message_str_to_bytes(message);
        assert!(
            !verify_signature(signature, address, message_bytes, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    #[serial]
    async fn typed_data() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();

        sol! {
            #[derive(Debug, Serialize)]
            struct FooBar {
                int256 foo;
                uint256 bar;
                bytes fizz;
                bytes32 buzz;
                string far;
                address out;
            }
        }

        let signer = PrivateKeySigner::random();

        let chain_id = provider.get_chain_id().await.unwrap();
        let signer = signer.with_chain_id(Some(chain_id));

        let domain = eip712_domain! {
            name: "Eip712Test",
            version: "1",
            chain_id: chain_id,
            verifying_contract: signer.address(),
            salt: keccak256("eip712-test-75F0CCte"),
        };
        let foo_bar = FooBar {
            foo: I256::try_from(10u64).unwrap(),
            bar: U256::from(20u64),
            fizz: b"fizz".to_vec().into(),
            buzz: keccak256("buzz"),
            far: "space".into(),
            out: Address::ZERO,
        };

        let foo_bar_dynamic = TypedData::from_struct(&foo_bar, Some(domain.clone()));
        let dynamic_hash = foo_bar_dynamic.eip712_signing_hash().unwrap();
        let sig_dynamic = signer.sign_hash_sync(&dynamic_hash).unwrap();
        assert_eq!(
            sig_dynamic
                .recover_address_from_prehash(&dynamic_hash)
                .unwrap(),
            signer.address()
        );
        let sig_dynamic = signer.sign_hash_sync(&dynamic_hash).unwrap();
        assert_eq!(
            sig_dynamic
                .recover_address_from_prehash(&dynamic_hash)
                .unwrap(),
            signer.address()
        );
        assert_eq!(signer.sign_hash_sync(&dynamic_hash).unwrap(), sig_dynamic);

        let signature: Bytes = sig_dynamic.as_bytes().to_vec().into();

        let signer_address = signer.address();
        let is_valid = verify_signature(signature, signer_address, dynamic_hash, provider);

        let is_valid = is_valid.await;
        println!("Is valid: {:?}", is_valid);
        assert!(is_valid.unwrap().is_valid());
    }

    #[tokio::test]
    #[serial]
    async fn eoa_wrong_address() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();

        let private_key = SigningKey::random(&mut rand::thread_rng());
        let message = "xxx";
        let signature = sign_message_eip191(message, &private_key);
        let mut address = Address::from_private_key(&private_key);
        *address.0.first_mut().unwrap() = address.0.first().unwrap().wrapping_add(1);
        let message_bytes = message_str_to_bytes(message);
        assert!(
            !verify_signature(signature, address, message_bytes, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    #[serial]
    async fn eoa_wrong_message() {
        let (_anvil, _rpc_url, provider, _private_key) = spawn_anvil();

        let private_key = SigningKey::random(&mut rand::thread_rng());
        let message = "xxx";
        let signature = sign_message_eip191(message, &private_key);
        let address = Address::from_private_key(&private_key);
        let message2 = "yyy";
        let message2_bytes = message_str_to_bytes(message2);
        assert!(
            !verify_signature(signature, address, message2_bytes, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    #[serial]
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
        let eip191_message = alloy_primitives::eip191_hash_message(message);
        let signature = sign_message_eip191(&message, &private_key);
        let signature_bytes = Bytes::from(signature.to_vec());

        assert!(
            verify_signature(signature_bytes, contract_address, eip191_message, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    #[serial]
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
        let message_bytes = message_str_to_bytes(message);
        let mut signature = sign_message_eip191(message, &private_key);
        let signature_bytes = Bytes::from(signature.to_vec());
        *signature.first_mut().unwrap() = signature.first().unwrap().wrapping_add(1);

        assert!(
            !verify_signature(signature_bytes, contract_address, message_bytes, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    #[serial]
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
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(
            message,
            &SigningKey::from_bytes(&anvil.keys().get(1).unwrap().to_bytes()).unwrap(),
        );

        assert!(
            !verify_signature(signature, contract_address, message_bytes, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    #[serial]
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
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(message, &private_key);

        assert!(
            !verify_signature(signature, contract_address, message_bytes, provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    #[serial]
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
        let signature = sign_message_eip191(message, &private_key);

        let message2 = "yyy";
        let message2_bytes = message_str_to_bytes(message2);
        assert!(
            !verify_signature(signature, contract_address, message2_bytes, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    const ERC1271_MOCK_BYTECODE: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/../../../../.foundry/forge/out/Erc1271Mock.sol/Erc1271Mock.bytecode"
    ));
    const ERC6942_MAGIC_BYTES: [u16; 16] = [
        0x6942, 0x6942, 0x6942, 0x6942, 0x6942, 0x6942, 0x6942, 0x6942, 0x6942, 0x6942, 0x6942,
        0x6942, 0x6942, 0x6942, 0x6942, 0x6942,
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
                ERC6942_MAGIC_BYTES
                    .iter()
                    .flat_map(|&x| x.to_be_bytes().into_iter()),
            )
            .collect::<Vec<u8>>();
        (predeploy_address, signature)
    }

    #[tokio::test]
    #[serial]
    async fn erc6942_pass() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let signature = sign_message_eip191(message, &private_key);
        let eoa_owner_address = Address::from_private_key(&private_key);
        let (predeploy_address, signature) =
            predeploy_signature(eoa_owner_address, create2_factory_address, signature);

        let signature_bytes = Bytes::from(signature.to_vec());

        let message_bytes = alloy_primitives::eip191_hash_message(message);

        let result =
            verify_signature(signature_bytes, predeploy_address, message_bytes, provider).await;

        assert!(result.unwrap().is_valid());
    }

    #[tokio::test]
    #[serial]
    async fn erc6942_wrong_signature() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let message_bytes = message_str_to_bytes(message);
        let mut signature = sign_message_eip191(message, &private_key);
        *signature.first_mut().unwrap() = signature.first().unwrap().wrapping_add(1);
        let (predeploy_address, signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        assert!(
            !verify_signature(signature, predeploy_address, message_bytes, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    #[serial]
    async fn erc6942_wrong_signer() {
        let (anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(
            message,
            &SigningKey::from_bytes(&anvil.keys().get(1).unwrap().to_bytes()).unwrap(),
        );
        let (predeploy_address, signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        assert!(
            !verify_signature(signature, predeploy_address, message_bytes, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    #[serial]
    async fn erc6942_wrong_contract_address() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(message, &private_key);
        let (mut predeploy_address, signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        *predeploy_address.0.first_mut().unwrap() =
            predeploy_address.0.first().unwrap().wrapping_add(1);

        assert!(
            !verify_signature(signature, predeploy_address, message_bytes, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    #[serial]
    async fn erc6942_wrong_message() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let signature = sign_message_eip191(message, &private_key);
        let (predeploy_address, signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        let message2 = "yyy";
        let message2_bytes = message_str_to_bytes(message2);
        assert!(
            !verify_signature(signature, predeploy_address, message2_bytes, provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }
    #[tokio::test]
    #[ignore]
    async fn test_erc6942_signature_with_invalid_factory() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;
        let message = "test message";
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(message, &private_key);

        let invalid_factory = address!("0000000000000000000000000000000000000001");
        let (_predeploy_address, mut erc6942_signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        // Modify the factory address in the signature to be invalid
        erc6942_signature[12..32].copy_from_slice(invalid_factory.as_slice());

        let result = extract_address(erc6942_signature, message_bytes, provider).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn test_erc6942_signature_with_empty_factory_calldata() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;
        let message = "test message";
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(message, &private_key);

        let (_predeploy_address, mut erc6942_signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        // Set factory calldata length to 0
        let factory_calldata_offset = bytes_to_usize(&erc6942_signature[32..64]);
        erc6942_signature[factory_calldata_offset..factory_calldata_offset + 32].fill(0);

        let result = extract_address(erc6942_signature, message_bytes, provider).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn test_erc6942_signature_with_mismatched_lengths() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;
        let message = "test message";
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(message, &private_key);

        let (_predeploy_address, mut erc6942_signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        // Modify the length of the factory calldata to be incorrect
        let factory_calldata_offset = bytes_to_usize(&erc6942_signature[32..64]);
        let incorrect_length: [u8; 32] = U256::from(1000).to_be_bytes();
        erc6942_signature[factory_calldata_offset..factory_calldata_offset + 32]
            .copy_from_slice(&incorrect_length);

        let result = extract_address(erc6942_signature, message_bytes, provider).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn test_erc6942_signature_with_invalid_magic_bytes() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;
        let message = "test message";
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(message, &private_key);

        let (predeploy_address, mut erc6942_signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        // Modify the magic bytes
        let signature_len = erc6942_signature.len();
        erc6942_signature[signature_len - 32..].fill(0);

        // Create an immutable reference for extract_address
        let modified_signature = erc6942_signature;

        let result = extract_address(modified_signature, message_bytes, provider).await;
        assert!(matches!(result, Ok(addr) if addr != predeploy_address));
    }

    #[tokio::test]
    #[ignore]
    async fn test_erc6942_signature_with_deployed_contract() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;
        let message = "test message";
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(message, &private_key);
        let address = Address::from_private_key(&private_key);

        // First, deploy the contract
        let (_predeploy_address, erc6942_signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature.clone(),
        );

        let _ = extract_address(erc6942_signature.clone(), message_bytes, provider.clone())
            .await
            .unwrap();

        // Now try to extract the address again
        let result = extract_address(erc6942_signature, message_bytes, provider).await;
        assert_eq!(result.unwrap(), address);
    }
    #[tokio::test]
    #[ignore]
    async fn test_erc6942_signature_with_different_message() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();

        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;

        let original_message = "test message";
        let original_message_bytes =
            alloy_primitives::eip191_hash_message(original_message.as_bytes());

        let signature = sign_message_eip191(original_message, &private_key);

        let signer_address = Address::from_private_key(&private_key);

        let (predeploy_address, erc6942_signature) =
            predeploy_signature(signer_address, create2_factory_address, signature.to_vec());

        // First, extract address with the correct message
        let result1 = extract_address(
            erc6942_signature.clone().to_vec(),
            original_message_bytes,
            provider.clone(),
        )
        .await;

        match &result1 {
            Ok(addr) => println!("Extracted address with original message: {:?}", addr),
            Err(e) => println!("Error extracting address with original message: {:?}", e),
        }
        assert!(
            result1.is_ok(),
            "Failed to extract address with original message"
        );
        assert_eq!(
            result1.unwrap(),
            signer_address,
            "Extracted address doesn't match predeploy address"
        );

        // Now try with a different message
        let different_message = "different message";
        let different_message_bytes = message_str_to_bytes(different_message);

        let result2 = extract_address(
            erc6942_signature.clone(),
            different_message_bytes,
            provider.clone(),
        )
        .await;
        match &result2 {
            Ok(addr) => println!("Extracted address with different message: {:?}", addr),
            Err(e) => println!("Error extracting address with different message: {:?}", e),
        }

        // The extracted address should be the same for both messages
        assert!(
            result2.is_ok(),
            "Failed to extract address with different message"
        );
        assert_eq!(
            result2.unwrap(),
            predeploy_address,
            "Extracted address should match predeploy address even with different message"
        );

        // Now verify the signature with both messages
        let verification1 = verify_signature(
            erc6942_signature.clone(),
            predeploy_address,
            original_message_bytes,
            provider.clone(),
        )
        .await;
        assert!(
            verification1.unwrap().is_valid(),
            "Signature should be valid for the original message"
        );

        let verification2 = verify_signature(
            erc6942_signature,
            predeploy_address,
            different_message_bytes,
            provider,
        )
        .await;
        assert!(
            !verification2.unwrap().is_valid(),
            "Signature should be invalid for the different message"
        );

        println!("Test completed successfully");
    }

    #[tokio::test]
    #[ignore]
    async fn test_erc6942_signature_with_large_factory_calldata() {
        let (_anvil, rpc_url, provider, private_key) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &private_key, CREATE2_CONTRACT, None).await;
        let message = "test message";
        let message_bytes = message_str_to_bytes(message);
        let signature = sign_message_eip191(message, &private_key);

        let (_predeploy_address, erc6942_signature) = predeploy_signature(
            Address::from_private_key(&private_key),
            create2_factory_address,
            signature,
        );

        // Increase the size of factory calldata
        let factory_calldata_offset = bytes_to_usize(&erc6942_signature[32..64]);
        let large_calldata = vec![0; 1_000_000]; // 1MB of data
        let mut new_signature = erc6942_signature[..factory_calldata_offset + 32].to_vec();
        new_signature.extend_from_slice(&U256::from(large_calldata.len()).to_be_bytes::<32>());
        new_signature.extend_from_slice(&large_calldata);
        new_signature.extend_from_slice(&erc6942_signature[factory_calldata_offset + 32..]);

        let result = extract_address(new_signature, message_bytes, provider).await;
        assert!(result.is_err());
    }
}
