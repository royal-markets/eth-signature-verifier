# Universal Etheruem signature verification with ERC-6492

This crate verifies any Ethereum signature including:

- EOAs
- Smart contract wallets with [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271)
- Predeploy contract wallets with [ERC-6492](https://eips.ethereum.org/EIPS/eip-6492)

## Usage

This crate uses [Alloy](https://github.com/alloy-rs) and requires an RPC provider in order to verify all signature types.

```rust
use alloy_primitives::{address, bytes, eip191_hash_message};
use alloy_provider::{network::Ethereum, ReqwestProvider};
use sig_verifier::verify_signature;

#[tokio::main]
async fn main() {
    let address = address!("0xc0ffee254729296a45a3885639AC7E10F9d54979");
    let message = "coffee";
    let signature = bytes!("0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658");
    let provider = ReqwestProvider::<Ethereum>::new_http("https://rpc.example.com");

    let verification = verify_signature(signature, address, message, provider).await.unwrap();
    if verification.is_valid() {
        // signature valid
    }
}
```

This crate also allows for the extracting of an address from a signature, as shown below:

```rust
use sig_verifier::extract_address;

#[tokio::main]
async fn main() {
    let signature = bytes!("0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
    let address = extract_address(signature).await.unwrap(); // works for EOA, ERC1271, ERC6942
    dbg!(address);
}
```

See test cases in `src/lib.rs` for more examples.
