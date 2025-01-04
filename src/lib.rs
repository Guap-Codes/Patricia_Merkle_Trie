//! A Rust implementation of a Patricia Merkle Trie.
//!
//! This crate provides an implementation of a Patricia Merkle Trie, which combines
//! the space efficiency of a Patricia Trie with the cryptographic verification
//! properties of a Merkle Tree.
//!
//! # Features
//! - Path compression for space efficiency
//! - Cryptographic verification of contents
//! - Generic key and value types
//! - Full CRUD operations (Create, Read, Update, Delete)
//!
//! # Example
//! ```rust
//! use patricia_merkle_trie::{PatriciaMerkleTrie, Result};
//!
//! fn example() -> Result<()> {
//!     let mut trie = PatriciaMerkleTrie::new();
//!     
//!     // Insert a key-value pair
//!     trie.insert(b"hello".to_vec(), b"world".to_vec())?;
//!     
//!     // Retrieve the value
//!     let value = trie.get(&b"hello".to_vec())?;
//!     assert_eq!(value.unwrap(), b"world");
//!     
//!     // Get the root hash
//!     let root_hash = trie.root_hash()?;
//!     
//!     Ok(())
//! }
//! ```

/// Error types and Result type alias
mod error;
/// Cryptographic hashing functionality
mod hash;
/// Core node types and implementations
mod node;
/// Merkle proof generation and verification
pub mod proof;
/// Main trie implementation
mod trie;
/// Utility functions for trie operations
mod utils;

pub use error::{Result, TrieError};
pub use trie::PatriciaMerkleTrie;
