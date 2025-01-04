//! Error types for the Patricia Merkle Trie implementation.
//!
//! This module defines the various error conditions that can occur
//! during trie operations, providing specific error types for different
//! failure scenarios.

use thiserror::Error;

/// Errors that can occur during Patricia Merkle Trie operations
///
/// Each variant represents a specific error condition that can occur
/// during trie operations such as insertion, deletion, or traversal.
#[derive(Error, Debug)]
pub enum TrieError {
    /// Indicates that a key has an invalid format or is empty
    #[error("Invalid key format")]
    InvalidKey,

    /// Indicates that a node was not found during traversal
    #[error("Node not found")]
    NodeNotFound,

    /// Indicates that a node has an unexpected type during operation
    #[error("Invalid node type")]
    InvalidNodeType,

    /// Indicates that a key is shorter than the minimum required length
    #[error("Key too short")]
    KeyTooShort,

    /// Indicates that a key is longer than the maximum allowed length
    #[error("Key too long")]
    KeyTooLong,

    /// Indicates that a branch node has an invalid structure
    #[error("Invalid branch structure")]
    InvalidBranch,

    /// Indicates that a branch prefix is invalid or inconsistent
    #[error("Invalid prefix")]
    InvalidPrefix,

    /// Indicates that a branch node's internal structure is corrupted
    #[error("Corrupted branch structure")]
    CorruptedBranch,

    /// Indicates that a proof is invalid
    #[error("Invalid proof")]
    InvalidProof,
}

/// Type alias for Result with TrieError as the error type
///
/// This alias simplifies the use of Results throughout the codebase
/// by providing a consistent error type for all trie operations.
pub type Result<T> = std::result::Result<T, TrieError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(TrieError::InvalidKey.to_string(), "Invalid key format");
        assert_eq!(
            TrieError::InvalidBranch.to_string(),
            "Invalid branch structure"
        );
    }
}
