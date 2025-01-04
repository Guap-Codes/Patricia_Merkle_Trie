# Patricia Merkle Trie

A Rust implementation of a Patricia Merkle Trie, which combines the space efficiency of a Patricia Trie with the cryptographic verification properties of a Merkle Tree.

## Features

- Path compression for space efficiency
- Cryptographic verification of contents
- Generic key and value types
- Full CRUD operations (Create, Read, Update, Delete)


## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
patricia_merkle_trie = { git = "https://github.com/guap-codes/patricia_merkle_trie.git" }
```

## Modules

### `trie`

The main module implementing the Patricia Merkle Trie.

### `node`

Defines the core node structure used in the trie, including leaf nodes for storing values and branch nodes for maintaining the tree structure.

### `hash`

Provides hash functions for different node types in the trie, ensuring each type has a unique prefix to prevent collisions between different node types with the same content.

### `proof`

Implements Merkle proof generation and verification.

### `utils`

Utility functions for trie operations.

### `error`

Defines the various error conditions that can occur during trie operations, providing specific error types for different failure scenarios.

## Example

```rust
use patricia_merkle_trie::{PatriciaMerkleTrie, Result};

fn example() -> Result<()> {
    let mut trie = PatriciaMerkleTrie::new();
    
    // Insert a key-value pair
    trie.insert(b"hello".to_vec(), b"world".to_vec())?;
    
    // Retrieve the value
    let value = trie.get(&b"hello".to_vec())?;
    assert_eq!(value.unwrap(), b"world");
    
    // Get the root hash
    let root_hash = trie.root_hash()?;
    
    Ok(())
}
```

## Examples

### DNS Resolver

An example of using the Patricia Merkle Trie as a DNS resolver.

```rust
use patricia_merkle_trie::{PatriciaMerkleTrie, Result};

fn main() -> Result<()> {
    // Create a new Patricia Merkle Trie
    let mut dns_trie = PatriciaMerkleTrie::new();

    // Insert domain names and their corresponding IP addresses
    dns_trie.insert(b"example.com".to_vec(), b"93.184.216.34".to_vec())?;
    dns_trie.insert(b"rust-lang.org".to_vec(), b"13.227.75.110".to_vec())?;
    dns_trie.insert(b"github.com".to_vec(), b"140.82.114.4".to_vec())?;

    // Resolve domain names
    let ip = dns_trie.get(&b"example.com".to_vec())?;
    println!("example.com -> {:?}", ip.unwrap());

    let ip = dns_trie.get(&b"rust-lang.org".to_vec())?;
    println!("rust-lang.org -> {:?}", ip.unwrap());

    let ip = dns_trie.get(&b"github.com".to_vec())?;
    println!("github.com -> {:?}", ip.unwrap());

    // Attempt to resolve a non-existent domain
    let ip = dns_trie.get(&b"nonexistent.com".to_vec())?;
    println!("nonexistent.com -> {:?}", ip);

    Ok(())
}
```

### Merkle Proof

An example of generating and verifying Merkle proofs using the Patricia Merkle Trie.

```rust
use patricia_merkle_trie::proof::{MerkleProof, MerkleProofTrait};
use patricia_merkle_trie::{PatriciaMerkleTrie, Result};
use std::env;
use std::process;

fn insert_key_value_pairs(
    trie: &mut PatriciaMerkleTrie<Vec<u8>, Vec<u8>>,
    pairs: Vec<(&str, &str)>,
) -> Result<()> {
    for (key, value) in pairs {
        trie.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec())?;
    }
    Ok(())
    }

fn generate_and_print_proof(
    trie: &PatriciaMerkleTrie<Vec<u8>, Vec<u8>>,
    key: &str,
) -> Result<MerkleProof> {
    let proof: MerkleProof = trie.generate_proof(&key.as_bytes().to_vec())?;
    let root_hash = trie.root_hash()?;

    println!("Merkle Proof for key '{}': {:?}", key, proof);
    println!("Root Hash: {:?}", root_hash);

    Ok(proof)
    }

fn verify_proof(root_hash: Vec<u8>, proof: MerkleProof) -> Result<()> {
    let is_valid = PatriciaMerkleTrie::<Vec<u8>, Vec<u8>>::verify_proof(root_hash, proof)?;
    println!("Proof is valid: {}", is_valid);
    Ok(())
}

fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <key1> <value1> [<key2> <value2> ...]", args[0]);
        process::exit(1);
    }

    // Create a new Patricia Merkle Trie
    let mut trie = PatriciaMerkleTrie::new();

    // Insert key-value pairs into the trie
    let mut pairs = Vec::new();
    for i in (1..args.len()).step_by(2) {
        if i + 1 < args.len() {
            pairs.push((args[i].as_str(), args[i + 1].as_str()));
        }
    }
    insert_key_value_pairs(&mut trie, pairs)?;

    // Generate and print a Merkle proof for the first key
    let proof = generate_and_print_proof(&trie, &args[1])?;

    // Verify the Merkle proof against the root hash
    let root_hash = trie.root_hash()?;
    verify_proof(root_hash, proof)?;

    Ok(())
}
```

### Implementation Details

#### Branch Node Value Handling

Branch nodes in the trie can store values in addition to having children. The value in a branch node is set only when:
1. The remaining nibbles are empty (exact match with branch prefix)
2. There is exactly one nibble remaining (value belongs at this branch)

This ensures that values are stored at the correct level in the trie and prevents duplicate or incorrect storage.

### Error Handling

The trie provides detailed error types for different failure scenarios:

- `InvalidKey`: Key contains invalid characters or is empty
- `InvalidValue`: Value is invalid or cannot be encoded
- `HashError`: Error computing cryptographic hashes
- `ProofError`: Error generating or verifying Merkle proofs
- `StorageError`: Error accessing the node store

Each error type includes:
- Detailed error message
- Source error (if any)
- Context about where the error occurred

Example error handling:

```rust
match trie.insert(key, value) {
    Ok(_) => println!("Successfully inserted"),
    Err(e) => {
        println!("Error: {}", e);
        if let Some(source) = e.source() {
            println!("Caused by: {}", source);
        }
    }
}
```

> ⚠️ **Disclaimer**: This project is experimental and currently a work in progress. The API and implementation details may change significantly as development continues. While the core functionality is implemented, some features might be incomplete or require further testing. Use in production environments is not recommended at this stage.


## License

This project is licensed under the MIT License.
