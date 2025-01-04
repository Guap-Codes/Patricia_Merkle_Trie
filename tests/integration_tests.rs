use patricia_merkle_trie::{PatriciaMerkleTrie, Result, TrieError};

mod basic_operations {
    use super::*;

    #[test]
    fn test_insert_and_get() -> Result<()> {
        let mut trie = PatriciaMerkleTrie::new();

        // Basic insert and get
        trie.insert(b"hello".to_vec(), b"world".to_vec())?;
        assert_eq!(trie.get(&b"hello".to_vec())?.unwrap(), b"world".as_slice());

        // Update existing key
        trie.insert(b"hello".to_vec(), b"updated".to_vec())?;
        assert_eq!(
            trie.get(&b"hello".to_vec())?.unwrap(),
            b"updated".as_slice()
        );

        Ok(())
    }

    #[test]
    fn test_delete() -> Result<()> {
        let mut trie = PatriciaMerkleTrie::new();

        // Insert multiple and delete one
        trie.insert(b"key1".to_vec(), b"value1".to_vec())?;
        trie.insert(b"key2".to_vec(), b"value2".to_vec())?;

        let deleted = trie.delete(&b"key1".to_vec())?;
        assert!(deleted.is_some());
        assert!(trie.get(&b"key1".to_vec())?.is_none());
        assert!(trie.get(&b"key2".to_vec())?.is_some());

        Ok(())
    }
}

mod error_handling {
    use super::*;

    #[test]
    fn test_invalid_keys() {
        let mut trie = PatriciaMerkleTrie::new();

        // Empty key
        assert!(matches!(
            trie.insert(vec![], b"value".to_vec()),
            Err(TrieError::InvalidKey)
        ));

        // Key too long
        let long_key = vec![0u8; 33];
        assert!(matches!(
            trie.insert(long_key, b"value".to_vec()),
            Err(TrieError::KeyTooLong)
        ));
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(TrieError::InvalidKey.to_string(), "Invalid key format");
        assert_eq!(
            TrieError::InvalidBranch.to_string(),
            "Invalid branch structure"
        );
    }
}

mod cryptographic_verification {
    use super::*;

    #[test]
    fn test_root_hash() -> Result<()> {
        let mut trie1 = PatriciaMerkleTrie::new();
        let mut trie2 = PatriciaMerkleTrie::new();

        // Same content should produce same hash
        trie1.insert(b"key".to_vec(), b"value".to_vec())?;
        trie2.insert(b"key".to_vec(), b"value".to_vec())?;
        assert_eq!(trie1.root_hash()?, trie2.root_hash()?);

        // Different content should produce different hash
        trie2.insert(b"key2".to_vec(), b"value2".to_vec())?;
        assert_ne!(trie1.root_hash()?, trie2.root_hash()?);

        Ok(())
    }
}
