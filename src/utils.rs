use crate::error::{Result, TrieError};

/// Finds the length of the common prefix between two byte slices
///
/// # Arguments
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
/// Length of the common prefix
pub fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

/// Convert a byte slice to a vector of nibbles (4-bit values)
pub fn to_nibbles(bytes: &[u8]) -> Result<Vec<u8>> {
    println!("Converting bytes to nibbles: {:?}", bytes);
    // Return empty vector for empty input
    if bytes.is_empty() {
        println!("Empty input, returning empty vector");
        return Ok(Vec::new());
    }

    // For prefix bytes, they are already in nibble form
    // Just convert them directly to a vector
    let result = bytes.to_vec();
    println!("Converted to nibbles: {:?}", result);
    Ok(result)
}

/// Verifies if a key is valid for use in the trie
///
/// # Arguments
/// * `key` - Byte slice to verify
///
/// # Returns
/// Result indicating if the key is valid
pub fn verify_key(key: &[u8]) -> Result<()> {
    println!("Verifying key: {:?}", key); // Debug print
    if key.is_empty() {
        println!("Key is empty"); // Debug print
        return Err(TrieError::InvalidKey);
    }
    if key.len() > 32 {
        println!("Key is too long: length = {}", key.len()); // Debug print
        return Err(TrieError::KeyTooLong); // Corrected error type
    }
    println!("Key is valid: {:?}", key); // Debug print
    Ok(())
}

/// Helper function to format nibbles for debugging
//pub(crate) fn format_nibbles(nibbles: &[u8]) -> String {
//    nibbles
//        .iter()
//        .map(|n| format!("{:x}", n))
//        .collect::<Vec<_>>()
//        .join("")
//}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_prefix() {
        assert_eq!(common_prefix(&[], &[]), 0);
        assert_eq!(common_prefix(&[1, 2, 3], &[1, 2, 4]), 2);
        assert_eq!(common_prefix(&[1, 2], &[1, 2]), 2);
        assert_eq!(common_prefix(&[1], &[2]), 0);
    }

    #[test]
    fn test_to_nibbles() {
        let nibbles = to_nibbles(&[]).unwrap();
        assert_eq!(nibbles, vec![]);

        let nibbles = to_nibbles(&[0x12, 0x34]).unwrap();
        assert_eq!(nibbles, vec![0x12, 0x34]);
    }

    #[test]
    fn test_verify_key() {
        assert!(verify_key(&[]).is_err());
        assert!(verify_key(&[0; 33]).is_err());
        assert!(verify_key(&[1, 2, 3]).is_ok());
    }

    #[test]
    fn test_simple_nibbles() -> Result<()> {
        let input = vec![0x1];
        let nibbles = to_nibbles(&input)?;
        assert_eq!(
            nibbles,
            vec![0x1],
            "Single byte 0x1 should give nibbles [0x1]"
        );

        let input = vec![0x2];
        let nibbles = to_nibbles(&input)?;
        assert_eq!(
            nibbles,
            vec![0x2],
            "Single byte 0x2 should give nibbles [0x2]"
        );

        Ok(())
    }
}
