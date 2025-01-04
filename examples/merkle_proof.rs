//! Example demonstrating Merkle proof generation and verification
//! This example shows how to:
//! 1. Create a trie with some key-value pairs
//! 2. Generate a Merkle proof for a specific key
//! 3. Verify the proof against the trie's root hash
//! 4. Handle various error cases and edge conditions

use patricia_merkle_trie::proof::MerkleProofTrait;
use patricia_merkle_trie::TrieError;
use patricia_merkle_trie::{PatriciaMerkleTrie, Result};

fn main() -> Result<()> {
    // Create a new Patricia Merkle Trie
    let mut trie = PatriciaMerkleTrie::new();

    // Insert key-value pairs with simple keys
    println!("Inserting key-value pairs...");
    let key1 = b"a".to_vec();
    let val1 = b"1".to_vec();
    let key2 = b"b".to_vec();
    let val2 = b"2".to_vec();
    let key3 = b"c".to_vec();
    let val3 = b"3".to_vec();

    println!("Inserting: key={:?}, value={:?}", key1, val1);
    trie.insert(key1.clone(), val1.clone())?;
    println!("Inserting: key={:?}, value={:?}", key2, val2);
    trie.insert(key2.clone(), val2.clone())?;
    println!("Inserting: key={:?}, value={:?}", key3, val3);
    trie.insert(key3.clone(), val3.clone())?;

    // Get the root hash
    let root_hash = trie.root_hash()?;
    println!("Root hash: {:?}\n", root_hash);

    // Generate and verify proof for each key
    let keys = [key1, key2, key3];
    let values = [val1, val2, val3];

    for (key, expected_value) in keys.iter().zip(values.iter()) {
        println!("\nTesting key: {:?}", key);
        match trie.generate_proof(key) {
            Ok(proof) => {
                println!("Generated proof:");
                println!("  Key: {:?}", proof.key);
                println!(
                    "  Value: {:?} (expected: {:?})",
                    proof.value, expected_value
                );
                println!("  Proof steps:");
                for (i, (nibble, hash)) in proof.proof.iter().enumerate() {
                    println!("    {}: nibble={}, hash={:?}", i, nibble, hash);

                    // Show what this hash represents
                    if *nibble == 0 {
                        println!("       (branch node hash)");
                    } else {
                        println!("       (leaf node hash)");
                    }
                }

                // Verify the proof
                match PatriciaMerkleTrie::<Vec<u8>, Vec<u8>>::verify_proof(root_hash.clone(), proof)
                {
                    Ok(is_valid) => {
                        if is_valid {
                            println!("Proof verification: success");
                        } else {
                            println!("Proof verification: failed");
                        }
                    }
                    Err(e) => println!("Error verifying proof: {:?}", e),
                }
            }
            Err(e) => println!("Error generating proof: {:?}", e),
        }
    }

    // Test error cases
    println!("\n=== Testing Error Cases ===");

    // 1. Try a non-existent key
    let missing_key = b"d".to_vec();
    println!("\nTesting non-existent key: {:?}", missing_key);
    match trie.generate_proof(&missing_key) {
        Ok(_) => println!("Unexpected: proof generated for missing key"),
        Err(e) => {
            println!("Expected error for missing key: {:?}", e);
            assert!(matches!(e, TrieError::NodeNotFound));
        }
    }

    // 2. Try an empty key
    let empty_key = Vec::new();
    println!("\nTesting empty key");
    match trie.generate_proof(&empty_key) {
        Ok(_) => println!("Unexpected: proof generated for empty key"),
        Err(e) => {
            println!("Expected error for empty key: {:?}", e);
            assert!(matches!(e, TrieError::InvalidKey));
        }
    }

    // 3. Try verifying an invalid proof
    println!("\nTesting invalid proof verification");
    let valid_proof = trie.generate_proof(&keys[0])?;
    let mut invalid_proof = valid_proof.clone();
    if let Some((_, hash)) = invalid_proof.proof.first_mut() {
        // Modify the hash to make it invalid
        if !hash.is_empty() {
            hash[0] = !hash[0];
        }
    }

    match PatriciaMerkleTrie::<Vec<u8>, Vec<u8>>::verify_proof(root_hash, invalid_proof) {
        Ok(is_valid) => {
            println!("Proof verification result: {}", is_valid);
            assert!(!is_valid, "Modified proof should not verify as valid");
        }
        Err(e) => println!("Error verifying modified proof: {:?}", e),
    }

    Ok(())
}
