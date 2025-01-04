//! Cryptographic hashing functionality for the Patricia Merkle Trie.
//!
//! This module provides hash functions for different node types in the trie,
//! ensuring each type has a unique prefix to prevent collisions between
//! different node types with the same content.

use crate::error::{Result, TrieError};
use sha2::{Digest, Sha256};

/// Computes a SHA-256 hash of arbitrary data
///
/// # Arguments
/// * `data` - Byte slice to hash
///
/// # Returns
/// A vector containing the 32-byte hash
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Computes a SHA-256 hash of a leaf node
///
/// Prepends a 0x00 byte to distinguish leaf node hashes from other types.
///
/// # Arguments
/// * `key` - Key stored in the leaf (in nibbles)
/// * `value` - Value stored in the leaf
///
/// # Returns
/// * `Ok(Vec<u8>)` - 32-byte hash of the leaf node
/// * `Err(TrieError)` - If key is empty
pub fn hash_leaf(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    println!("Hashing leaf - key: {:?}, value: {:?}", key, value);
    if key.is_empty() {
        return Err(TrieError::InvalidKey);
    }
    let mut hasher = Sha256::new();
    // Add a prefix byte to distinguish leaf node hashes
    hasher.update([0x00]);
    // Add key length and key bytes
    hasher.update(&[key.len() as u8]);
    hasher.update(key);
    // Add value length and value bytes
    hasher.update(&[value.len() as u8]);
    hasher.update(value);
    let hash = hasher.finalize().to_vec();
    println!("Leaf hash result: {:?}", hash);
    Ok(hash)
}

/// Computes a SHA-256 hash of a branch node
///
/// Prepends a 0x01 byte to distinguish branch node hashes from other types.
/// Sorts children by key before hashing to ensure consistent hashes.
///
/// # Arguments
/// * `prefix` - Common prefix of the branch (in nibbles)
/// * `children_data` - Vector of (key, hash) pairs for each child
/// * `value` - Optional value stored at the branch
///
/// # Returns
/// * `Ok(Vec<u8>)` - 32-byte hash of the branch node
/// * `Err(TrieError)` - If children_data is empty
pub fn hash_branch(
    prefix: &[u8],
    children_data: &[(u8, Vec<u8>)],
    value: &[u8],
) -> Result<Vec<u8>> {
    println!("Hashing branch - prefix: {:?}, children: {:?}, value: {:?}", prefix, children_data, value);
    if children_data.is_empty() {
        return Err(TrieError::InvalidBranch);
    }
    let mut hasher = Sha256::new();
    // Add a prefix byte to distinguish branch node hashes
    hasher.update([0x01]);
    // Add prefix length and prefix bytes
    hasher.update(&[prefix.len() as u8]);
    hasher.update(prefix);
    // Sort children by key for consistent hashing
    let mut sorted_children: Vec<_> = children_data.to_vec();
    sorted_children.sort_by_key(|&(k, _)| k);
    // Add number of children
    hasher.update(&[sorted_children.len() as u8]);
    for (key, child_hash) in sorted_children {
        println!("Processing child - key: {:?}, hash: {:?}", key, child_hash);
        hasher.update([key]);
        hasher.update(&[child_hash.len() as u8]);
        hasher.update(&child_hash);
    }
    // Add the branch value to the hash
    hasher.update(&[value.len() as u8]);
    hasher.update(value);
    let hash = hasher.finalize().to_vec();
    println!("Branch hash result: {:?}", hash);
    Ok(hash)
}

/// Computes a SHA-256 hash of an empty node
///
/// Prepends a 0x02 byte to distinguish empty node hashes from other types.
///
/// # Returns
/// A vector containing the 32-byte hash
pub fn hash_empty() -> Vec<u8> {
    hash_data(&[0x02]) // Special prefix for empty nodes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_leaf() {
        assert!(hash_leaf(&[], &[1]).is_err());

        let hash1 = hash_leaf(&[1], &[2]).unwrap();
        let hash2 = hash_leaf(&[1], &[2]).unwrap();
        let hash3 = hash_leaf(&[2], &[2]).unwrap();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_branch() {
        assert!(hash_branch(&[1], &[], &[1]).is_err());

        let children1 = vec![(1, vec![1]), (2, vec![2])];
        let children2 = vec![(2, vec![2]), (1, vec![1])];

        let hash1 = hash_branch(&[1], &children1, &[1]).unwrap();
        let hash2 = hash_branch(&[1], &children2, &[1]).unwrap();

        // Same content in different order should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_uniqueness() {
        let empty = hash_empty();
        let leaf = hash_leaf(&[1], &[2]).unwrap();
        let branch = hash_branch(&[1], &[(1, vec![2])], &[]).unwrap();

        assert_ne!(empty, leaf);
        assert_ne!(empty, branch);
        assert_ne!(leaf, branch);

        // Test that different branch values produce different hashes
        let branch2 = hash_branch(&[1], &[(1, vec![2])], &[3]).unwrap();
        assert_ne!(branch, branch2);
    }
}
