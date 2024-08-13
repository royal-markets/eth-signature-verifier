use {
    alloy::{hex::encode, primitives::FixedBytes}, serde::{Deserialize, Serialize}, std::io::Read, tiny_keccak::{Hasher, Keccak}
};

#[derive(Debug, Serialize, Deserialize)]
pub struct TypedDataDomain {
    name: String,
    version: String,
    verifying_contract: String,
    chain_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HashMessageParameters {
    message: String,
    verifier_domain: TypedDataDomain,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureWrapper {
    owner_index: u8,
    signature_data: Vec<u8>,
}


fn to_prefixed_message(message: &str) -> Vec<u8> {
    format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes().to_vec()
}

fn keccak256(input: &[u8]) -> FixedBytes<32> {
    let mut keccak = Keccak::v256();
    keccak.update(input);
    let mut res = [0u8; 32];
    keccak.finalize(&mut res);
    let fixed_bytes:FixedBytes<32> = FixedBytes::from(res);
    fixed_bytes
}

fn encode_domain(domain: TypedDataDomain) -> Vec<u8> {
    let name = keccak256(domain.name.as_bytes());
    let version = keccak256(domain.version.as_bytes());
    let verifying_contract = keccak256(domain.verifying_contract.as_bytes());
    let chain_id: [u8; 8] = domain.chain_id.to_be_bytes();

    let mut encoded = Vec::new();
    encoded.extend_from_slice(&name.to_vec());
    encoded.extend_from_slice(&version.to_vec());
    encoded.extend_from_slice(&verifying_contract.to_vec());
    encoded.extend_from_slice(&chain_id);

    encoded
}

fn hash_typed_data(domain: TypedDataDomain, message: String) -> FixedBytes<32> {
    let domain_separator = encode_domain(domain);
    let message_hash = keccak256(&to_prefixed_message(&message));

    keccak256(&[
        domain_separator.as_slice(),
        message_hash.as_slice(),
    ].concat())
}

pub fn hash_message(parameters: HashMessageParameters) -> FixedBytes<32> {
    hash_typed_data(parameters.verifier_domain, parameters.message)
}

// Function to verify the signature (simplified)
fn verify_signature(message_hash: FixedBytes<32>, signature: SignatureWrapper, public_key: &[u8]) -> bool {
    // Implement signature verification logic here
    true // Placeholder, replace with actual verification logic
}

fn main() {
    let parameters = HashMessageParameters {
        message: String::from("hello world"),
        verifier_domain: TypedDataDomain {
            name: String::from("Smart Account"),
            version: String::from("1"),
            verifying_contract: String::from("0x1234567890abcdef1234567890abcdef12345678"),
            chain_id: 1,
`        },
`    };

    let hash = hash_message(parameters);
    println!("Hash: 0x{}", encode(hash.as_slice()));
}
