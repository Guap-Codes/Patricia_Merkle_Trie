//! Implementation of a Patricia Merkle Trie data structure.
//!
//! A Patricia Merkle Trie is a modified radix trie that includes:
//! - Path compression (Patricia)
//! - Cryptographic verification (Merkle)
//! - Efficient storage and retrieval of key-value pairs
use crate::{
    error::{Result, TrieError},
    hash::{hash_branch, hash_empty, hash_leaf},
    node::Node,
    utils::{common_prefix, to_nibbles, verify_key},
};
use std::collections::HashMap;

/// A Patricia Merkle Trie implementation that stores key-value pairs
/// with cryptographic verification capabilities.
///
/// # Type Parameters
/// - `K`: Key type that can be converted to and from byte slices
/// - `V`: Value type that can be converted to byte slices
///
/// # Examples
/// ```
/// # use patricia_merkle_trie::{PatriciaMerkleTrie, Result};
/// # fn main() -> Result<()> {
/// let mut trie = PatriciaMerkleTrie::new();
/// trie.insert(b"key".to_vec(), b"value".to_vec())?;
/// assert_eq!(trie.get(&b"key".to_vec())?.unwrap(), b"value");
/// # Ok(())
/// # }
/// ```
pub struct PatriciaMerkleTrie<K, V> {
    root: Node<K, Option<V>>,
    node_store: HashMap<Vec<u8>, Node<K, Option<V>>>,
}

impl<K, V> PatriciaMerkleTrie<K, V>
where
    K: AsRef<[u8]> + Clone + From<Vec<u8>> + std::fmt::Debug,
    V: Clone + AsRef<[u8]> + std::fmt::Debug,
{
    /// Creates a new empty Patricia Merkle Trie
    pub fn new() -> Self {
        PatriciaMerkleTrie {
            root: Node::Empty,
            node_store: HashMap::new(),
        }
    }

    /// Returns a reference to the root node
    pub fn root(&self) -> &Node<K, Option<V>> {
        &self.root
    }

    /// Inserts a key-value pair into the trie
    ///
    /// # Arguments
    /// * `key` - The key to insert
    /// * `value` - The value to associate with the key
    ///
    /// # Returns
    /// * `Ok(())` on successful insertion
    /// * `Err(TrieError)` if the key is invalid
    pub fn insert(&mut self, key: K, value: V) -> Result<()> {
        println!("Inserting key: {:?}, value: {:?}", key, value);
        verify_key(key.as_ref())?;
        let key_nibbles = to_nibbles(key.as_ref())?;
        println!("Key nibbles: {:?}", key_nibbles);
        self.root = self.insert_at(self.root.clone(), key.clone(), key_nibbles, Some(value))?;
        Ok(())
    }

    /// Internal method to recursively insert a key-value pair
    ///
    /// # Arguments
    /// * `node` - Current node being processed
    /// * `key` - Full key being inserted
    /// * `nibbles` - Remaining nibbles of the key to process
    /// * `value` - Value to insert
    #[allow(clippy::only_used_in_recursion)]
    fn insert_at(
        &mut self,
        node: Node<K, Option<V>>,
        key: K,
        nibbles: Vec<u8>,
        value: Option<V>,
    ) -> Result<Node<K, Option<V>>> {
        println!("Inserting at node: {:?}, nibbles: {:?}", node, nibbles);
        let new_node = match node {
            Node::Empty => {
                let leaf = Node::Leaf {
                    key: key.clone(),
                    value: value.clone(),
                };
                // Store the leaf node
                let hash = self.hash_node(&leaf)?;
                self.node_store.insert(hash, leaf.clone());
                leaf
            }
            Node::Leaf {
                key: existing_key,
                value: existing_value,
            } => {
                let existing_nibbles = to_nibbles(existing_key.as_ref())?;
                let prefix_len = common_prefix(&existing_nibbles, &nibbles);

                if prefix_len == existing_nibbles.len() && prefix_len == nibbles.len() {
                    // Same key, just update value
                    let leaf = Node::Leaf {
                        key: key.clone(),
                        value: value.clone(),
                    };
                    let hash = self.hash_node(&leaf)?;
                    self.node_store.insert(hash, leaf.clone());
                    leaf
                } else {
                    // Create a new branch
                    let mut children = HashMap::new();
                    let prefix = if prefix_len > 0 {
                        existing_key.as_ref()[..prefix_len].to_vec()
                    } else {
                        vec![]
                    };

                    // Add existing leaf if it has remaining nibbles
                    if prefix_len < existing_nibbles.len() {
                        let existing_branch_key = existing_nibbles[prefix_len];
                        let existing_leaf = Node::Leaf {
                            key: existing_key.clone(),
                            value: existing_value.clone(),
                        };
                        let existing_hash = self.hash_node(&existing_leaf)?;
                        self.node_store
                            .insert(existing_hash.clone(), existing_leaf.clone());
                        children.insert(existing_branch_key, Box::new(existing_leaf));
                    }

                    // Add new leaf if it has remaining nibbles
                    if prefix_len < nibbles.len() {
                        let new_branch_key = nibbles[prefix_len];
                        let new_leaf = Node::Leaf {
                            key: key.clone(),
                            value: value.clone(),
                        };
                        let new_hash = self.hash_node(&new_leaf)?;
                        self.node_store.insert(new_hash.clone(), new_leaf.clone());
                        children.insert(new_branch_key, Box::new(new_leaf));
                    }

                    // Create and store the branch node
                    let branch = Node::Branch {
                        prefix: prefix.into(),
                        children,
                        value: if prefix_len == nibbles.len() {
                            value
                        } else {
                            None
                        },
                    };
                    let branch_hash = self.hash_node(&branch)?;
                    self.node_store.insert(branch_hash, branch.clone());
                    branch
                }
            }
            Node::Branch {
                prefix,
                mut children,
                value,
            } => {
                let prefix_nibbles = to_nibbles(prefix.as_ref())?;
                let prefix_len = common_prefix(&prefix_nibbles, &nibbles);

                if prefix_len < prefix_nibbles.len() {
                    // Split the branch
                    let new_prefix = prefix.as_ref()[..prefix_len].to_vec();
                    let mut new_children = HashMap::new();

                    // Create sub-branch for existing children
                    let remaining_prefix = prefix.as_ref()[prefix_len..].to_vec();
                    let sub_branch = Node::Branch {
                        prefix: remaining_prefix.into(),
                        children,
                        value: value.clone(),
                    };
                    let sub_hash = self.hash_node(&sub_branch)?;
                    self.node_store.insert(sub_hash.clone(), sub_branch.clone());
                    new_children.insert(prefix_nibbles[prefix_len], Box::new(sub_branch));

                    // Add new leaf
                    let new_leaf = Node::Leaf {
                        key: key.clone(),
                        value: value.clone(),
                    };
                    let new_hash = self.hash_node(&new_leaf)?;
                    self.node_store.insert(new_hash.clone(), new_leaf.clone());
                    new_children.insert(nibbles[prefix_len], Box::new(new_leaf));

                    // Create and store new branch
                    let new_branch = Node::Branch {
                        prefix: new_prefix.into(),
                        children: new_children,
                        value: None,
                    };
                    let branch_hash = self.hash_node(&new_branch)?;
                    self.node_store.insert(branch_hash, new_branch.clone());
                    new_branch
                } else {
                    let remaining_nibbles = nibbles[prefix_len..].to_vec();
                    if remaining_nibbles.is_empty() {
                        // Update branch value
                        let branch = Node::Branch {
                            prefix,
                            children,
                            value: value.clone(),
                        };
                        let hash = self.hash_node(&branch)?;
                        self.node_store.insert(hash, branch.clone());
                        branch
                    } else {
                        let child_nibble = remaining_nibbles[0];
                        let child = children
                            .remove(&child_nibble)
                            .unwrap_or(Box::new(Node::Empty));

                        // Recursively insert into child
                        let new_child = self.insert_at(
                            *child,
                            key.clone(),
                            remaining_nibbles.clone(), // Pass all remaining nibbles
                            value.clone(),
                        )?;

                        // Store the new child
                        let child_hash = self.hash_node(&new_child)?;
                        self.node_store.insert(child_hash, new_child.clone());

                        // Update branch with new child
                        children.insert(child_nibble, Box::new(new_child));
                        let branch = Node::Branch {
                            prefix,
                            children,
                            value: if remaining_nibbles.len() == 1 {
                                value
                            } else {
                                None
                            },
                        };
                        let hash = self.hash_node(&branch)?;
                        self.node_store.insert(hash, branch.clone());
                        branch
                    }
                }
            }
        };

        Ok(new_node)
    }

    /// Retrieves a value by key from the trie
    ///
    /// # Arguments
    /// * `key` - The key to look up
    ///
    /// # Returns
    /// * `Ok(Some(&V))` if the key exists
    /// * `Ok(None)` if the key doesn't exist
    /// * `Err(TrieError)` if the key is invalid
    pub fn get<'a>(&'a self, key: &K) -> Result<Option<&'a V>> {
        verify_key(key.as_ref())?;
        let key_nibbles = to_nibbles(key.as_ref())?;
        println!("Getting key: {:?}, nibbles: {:?}", key, key_nibbles); // Debug print
        self.get_at(&self.root, key_nibbles, key.as_ref())
    }

    /// Internal method to recursively search for a key
    #[allow(clippy::only_used_in_recursion)]
    fn get_at<'a>(
        &'a self,
        node: &'a Node<K, Option<V>>,
        nibbles: Vec<u8>,
        original_key: &[u8],
    ) -> Result<Option<&'a V>> {
        println!("Getting at node: {:?}, nibbles: {:?}", node, nibbles); // Debug print
        if node.is_empty() {
            return Ok(None);
        }

        if node.is_leaf() {
            if let Node::Leaf { key, value } = node {
                let existing_nibbles = to_nibbles(key.as_ref())?;
                println!(
                    "Leaf node found. Key: {:?}, existing nibbles: {:?}",
                    key, existing_nibbles
                ); // Debug print
                if original_key == key.as_ref() {
                    return Ok(value.as_ref());
                } else {
                    return Ok(None);
                }
            }
        }

        if let Node::Branch {
            ref prefix,
            children,
            value,
        } = node
        {
            println!("\nHandling branch node");
            println!("Branch prefix bytes: {:?}", prefix.as_ref());
            let prefix_nibbles = match to_nibbles(prefix.as_ref()) {
                Ok(n) => {
                    println!("Successfully converted prefix to nibbles: {:?}", n);
                    n
                }
                Err(e) => {
                    println!("Error converting prefix to nibbles: {:?}", e);
                    return Err(e);
                }
            };

            println!("Input nibbles: {:?}", nibbles);
            let prefix_len = common_prefix(&nibbles, &prefix_nibbles);

            println!(
                "Branch node found. Prefix: {:?}, prefix nibbles: {:?}, prefix_len: {}",
                prefix, prefix_nibbles, prefix_len
            ); // Debug print

            // If we've matched the entire prefix
            if prefix_len == prefix_nibbles.len() {
                // If we've consumed all nibbles and this branch has a value, return it
                if nibbles.len() == prefix_len {
                    return Ok(value.as_ref());
                }

                // Only try to get child_key if we have more nibbles
                if nibbles.len() > prefix_len {
                    let child_nibble = nibbles[prefix_len];
                    if let Some(child) = children.get(&child_nibble) {
                        // Recursively search in the child node with the remaining nibbles
                        return self.get_at(
                            child,
                            nibbles[prefix_len + 1..].to_vec(),
                            original_key,
                        );
                    }
                }
            }
            return Ok(None);
        }

        Ok(None)
    }

    /// Deletes a key-value pair from the trie
    ///
    /// # Arguments
    /// * `key` - The key to delete
    ///
    /// # Returns
    /// * `Ok(Some(V))` if the key was found and deleted
    /// * `Ok(None)` if the key didn't exist
    /// * `Err(TrieError)` if the key is invalid
    pub fn delete(&mut self, key: &K) -> Result<Option<V>> {
        println!("Deleting key: {:?}", key); // Debug print
        verify_key(key.as_ref())?;
        let key_nibbles = to_nibbles(key.as_ref())?;
        println!("Key nibbles: {:?}", key_nibbles); // Debug print
        let (new_root, value) = self.delete_at(self.root.clone(), key_nibbles, key.as_ref())?;
        println!(
            "After delete_at, new_root: {:?}, value: {:?}",
            new_root, value
        );
        match new_root {
            Node::Empty => {
                println!("Setting root to empty");
                self.root = Node::Empty;
            }
            _ => {
                let root_hash = self.hash_node(&new_root)?;
                self.node_store.insert(root_hash, new_root.clone());
                self.root = new_root;
            }
        }
        println!("Final root after deletion: {:?}", self.root);
        Ok(value)
    }

    /// Internal method to recursively delete a key-value pair
    #[allow(clippy::only_used_in_recursion)]
    fn delete_at(
        &mut self,
        node: Node<K, Option<V>>,
        nibbles: Vec<u8>,
        original_key: &[u8],
    ) -> Result<(Node<K, Option<V>>, Option<V>)> {
        println!("Deleting at node: {:?}, nibbles: {:?}", node, nibbles); // Debug print
        match node {
            Node::Empty => Ok((Node::Empty, None)),
            Node::Leaf { key, value } => {
                let existing_nibbles = to_nibbles(key.as_ref())?;
                let original_nibbles = to_nibbles(original_key)?;
                println!(
                    "Comparing nibbles: existing={:?}, original={:?}",
                    existing_nibbles, original_nibbles
                );
                if existing_nibbles != original_nibbles {
                    println!("Nibbles don't match, keeping leaf");
                    return Ok((Node::Leaf { key, value }, None));
                }
                println!(
                    "Found leaf node to delete with key: {:?}, value: {:?}",
                    key, value
                );
                println!("Returning Empty node and value: {:?}", value);
                Ok((Node::Empty, value))
            }
            Node::Branch {
                prefix,
                mut children,
                value,
            } => {
                let prefix_nibbles = to_nibbles(prefix.as_ref())?;
                let common_len = common_prefix(&prefix_nibbles, &nibbles);

                if common_len < prefix_nibbles.len() {
                    // Key not in this branch
                    return Ok((
                        Node::Branch {
                            prefix,
                            children,
                            value,
                        },
                        None,
                    ));
                }

                let remaining_nibbles = nibbles[common_len..].to_vec();
                if remaining_nibbles.is_empty() {
                    // This is the target branch, remove its value
                    if children.is_empty() {
                        Ok((Node::Empty, value))
                    } else {
                        let branch = Node::Branch {
                            prefix,
                            children,
                            value: None,
                        };
                        let hash = self.hash_node(&branch)?;
                        self.node_store.insert(hash, branch.clone());
                        Ok((branch, value))
                    }
                } else {
                    let child_nibble = remaining_nibbles[0];
                    println!("Looking for child with nibble: {:?}", child_nibble);
                    println!("Children before removal: {:?}", children);
                    if let Some(child) = children.remove(&child_nibble) {
                        println!("Found child to delete: {:?}", child);
                        let (new_child, deleted_value) =
                            self.delete_at(*child, remaining_nibbles[1..].to_vec(), original_key)?;
                        println!(
                            "After recursive delete, new_child: {:?}, deleted_value: {:?}",
                            new_child, deleted_value
                        );

                        match new_child {
                            Node::Empty => {
                                println!("Child was deleted, children map now: {:?}", children);
                                // Child was deleted, don't put it back
                                if children.is_empty() && value.is_none() {
                                    println!("No more children and no value, converting to empty");
                                    // No more children and no value, convert to empty node
                                    Ok((Node::Empty, deleted_value))
                                } else if children.len() == 1 && value.is_none() {
                                    println!("Only one child left, collapsing branch");
                                    // Only one child left and no value, collapse the branch
                                    let (remaining_nibble, remaining_child) =
                                        children.into_iter().next().unwrap();
                                    let child = *remaining_child;
                                    match child {
                                        Node::Leaf { key, value } => {
                                            // Create a new leaf with the combined prefix
                                            let mut new_key = prefix.as_ref().to_vec();
                                            new_key.push(remaining_nibble);
                                            let leaf = Node::Leaf {
                                                key: new_key.into(),
                                                value,
                                            };
                                            let hash = self.hash_node(&leaf)?;
                                            self.node_store.insert(hash, leaf.clone());
                                            println!("Collapsed to leaf: {:?}", leaf);
                                            Ok((leaf, deleted_value))
                                        }
                                        Node::Branch {
                                            prefix: child_prefix,
                                            children: child_children,
                                            value: child_value,
                                        } => {
                                            // Create a new branch with the combined prefix
                                            let mut new_prefix = prefix.as_ref().to_vec();
                                            new_prefix.push(remaining_nibble);
                                            new_prefix.extend_from_slice(child_prefix.as_ref());
                                            let branch = Node::Branch {
                                                prefix: new_prefix.into(),
                                                children: child_children,
                                                value: child_value,
                                            };
                                            let hash = self.hash_node(&branch)?;
                                            self.node_store.insert(hash, branch.clone());
                                            println!("Collapsed to branch: {:?}", branch);
                                            Ok((branch, deleted_value))
                                        }
                                        Node::Empty => Ok((Node::Empty, deleted_value)),
                                    }
                                } else {
                                    println!(
                                        "Multiple children remain or has value, keeping branch"
                                    );
                                    // Multiple children remain or has value, keep the branch
                                    let branch = Node::Branch {
                                        prefix,
                                        children,
                                        value,
                                    };
                                    let hash = self.hash_node(&branch)?;
                                    self.node_store.insert(hash, branch.clone());
                                    println!("Kept branch: {:?}", branch);
                                    Ok((branch, deleted_value))
                                }
                            }
                            _ => {
                                println!("Child was not deleted, putting it back");
                                // Child was not deleted or was modified, put it back
                                children.insert(child_nibble, Box::new(new_child));
                                let branch = Node::Branch {
                                    prefix,
                                    children,
                                    value,
                                };
                                let hash = self.hash_node(&branch)?;
                                self.node_store.insert(hash, branch.clone());
                                println!("Updated branch: {:?}", branch);
                                Ok((branch, deleted_value))
                            }
                        }
                    } else {
                        Ok((
                            Node::Branch {
                                prefix,
                                children,
                                value,
                            },
                            None,
                        ))
                    }
                }
            }
        }
    }

    /// Computes the cryptographic hash of the entire trie
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` containing the root hash
    /// * `Err(TrieError)` if hashing fails
    pub fn root_hash(&self) -> Result<Vec<u8>> {
        self.hash_node(&self.root)
    }

    /// Internal method to recursively compute node hashes
    #[allow(clippy::only_used_in_recursion)]
    pub fn hash_node(&self, node: &Node<K, Option<V>>) -> Result<Vec<u8>> {
        println!("Hashing node: {:?}", node);
        match node {
            Node::Empty => Ok(hash_empty()),
            Node::Leaf { key, value } => {
                let key_nibbles = to_nibbles(key.as_ref())?;
                println!(
                    "Leaf node - key: {:?}, nibbles: {:?}, value: {:?}",
                    key, key_nibbles, value
                );
                hash_leaf(
                    &key_nibbles,
                    value.as_ref().map(|v| v.as_ref()).unwrap_or(&[]),
                )
            }
            Node::Branch {
                prefix,
                children,
                value,
            } => {
                let prefix_nibbles = to_nibbles(prefix.as_ref())?;
                println!(
                    "Branch node - prefix: {:?}, nibbles: {:?}, children: {:?}, value: {:?}",
                    prefix, prefix_nibbles, children, value
                );
                let child_hashes = children
                    .iter()
                    .map(|(k, child)| {
                        println!("Processing child with key: {:?}", k);
                        Ok((*k, self.hash_node(child)?))
                    })
                    .collect::<Result<Vec<_>>>()?;

                hash_branch(
                    &prefix_nibbles,
                    &child_hashes,
                    value.as_ref().map(|v| v.as_ref()).unwrap_or(&[]),
                )
            }
        }
    }
}

// Add Default implementation for PatriciaMerkleTrie
impl<K, V> Default for PatriciaMerkleTrie<K, V>
where
    K: AsRef<[u8]> + Clone + From<Vec<u8>> + std::fmt::Debug,
    V: Clone + AsRef<[u8]> + std::fmt::Debug,
{
    fn default() -> Self {
        Self::new()
    }
}

//-----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_trie() {
        let trie: PatriciaMerkleTrie<Vec<u8>, Vec<u8>> = PatriciaMerkleTrie::new();
        assert!(matches!(trie.root, Node::Empty));
    }

    #[test]
    fn test_insert_at_empty() -> Result<()> {
        let mut trie = PatriciaMerkleTrie::new();
        let result = trie.insert_at(Node::Empty, vec![1], vec![1], Some(vec![2]))?;
        assert!(matches!(result, Node::Leaf { .. }));
        Ok(())
    }

    #[test]
    fn test_branch_creation() -> Result<()> {
        let mut trie = PatriciaMerkleTrie::new();
        let leaf1 = trie.insert_at(Node::Empty, vec![1, 2], vec![1, 2], Some(vec![3]))?;
        let result = trie.insert_at(leaf1, vec![1, 3], vec![1, 3], Some(vec![4]))?;

        assert!(matches!(result, Node::Branch { .. }));
        if let Node::Branch { children, .. } = result {
            assert_eq!(children.len(), 2);
        }
        Ok(())
    }

    #[test]
    fn test_branch_collapse() -> Result<()> {
        let mut trie = PatriciaMerkleTrie::new();

        // Insert two leaves
        trie.insert(vec![1, 2], vec![1])?;
        trie.insert(vec![1, 3], vec![2])?;

        // Verify both leaves are present
        assert_eq!(trie.get(&vec![1, 2])?.map(|v| v.to_vec()), Some(vec![1]));
        assert_eq!(trie.get(&vec![1, 3])?.map(|v| v.to_vec()), Some(vec![2]));

        // Delete one leaf
        let deleted_value = trie.delete(&vec![1, 2])?;
        assert_eq!(deleted_value.map(|v| v.to_vec()), Some(vec![1]));

        // Verify deleted leaf is gone and other leaf remains
        assert_eq!(trie.get(&vec![1, 2])?, None);
        assert_eq!(trie.get(&vec![1, 3])?.map(|v| v.to_vec()), Some(vec![2]));

        Ok(())
    }

    #[test]
    fn test_branch_collapse_corrected() -> Result<()> {
        let mut trie = PatriciaMerkleTrie::new();

        // Insert two leaves
        trie.insert(vec![1, 2], vec![1])?;
        trie.insert(vec![1, 3], vec![2])?;

        // Delete one leaf
        let deleted_value = trie.delete(&vec![1, 2])?;
        assert_eq!(deleted_value.map(|v| v.to_vec()), Some(vec![1]));

        // Verify deleted leaf is gone and other leaf remains
        assert_eq!(trie.get(&vec![1, 2])?, None);
        assert_eq!(trie.get(&vec![1, 3])?.map(|v| v.to_vec()), Some(vec![2]));

        Ok(())
    }

    #[test]
    fn test_invalid_operations() {
        let mut trie = PatriciaMerkleTrie::new();

        // Test empty key
        assert!(matches!(
            trie.insert(vec![], vec![1]),
            Err(TrieError::InvalidKey)
        ));

        // Test long key
        assert!(matches!(
            trie.insert(vec![0; 33], vec![1]),
            Err(TrieError::KeyTooLong) // Corrected error type
        ));
    }

    #[test]
    fn test_hash_consistency() -> Result<()> {
        let trie = PatriciaMerkleTrie::new(); // Removed mut since we don't modify the trie

        // Same content should produce same hash
        let hash1 = trie.hash_node(&Node::Leaf {
            key: vec![1],
            value: Some(vec![2]),
        })?;

        let hash2 = trie.hash_node(&Node::Leaf {
            key: vec![1],
            value: Some(vec![2]),
        })?;

        assert_eq!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_hash_consistency_corrected() -> Result<()> {
        let trie = PatriciaMerkleTrie::new();

        // Same content should produce same hash
        let hash1 = trie.hash_node(&Node::Leaf {
            key: vec![1],
            value: Some(vec![2]),
        })?;

        let hash2 = trie.hash_node(&Node::Leaf {
            key: vec![1],
            value: Some(vec![2]),
        })?;

        assert_eq!(hash1, hash2);
        Ok(())
    }
}
