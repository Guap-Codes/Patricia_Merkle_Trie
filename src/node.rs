//! Node types and implementations for the Patricia Merkle Trie.
//!
//! This module defines the core node structure used in the trie,
//! including leaf nodes for storing values and branch nodes for
//! maintaining the tree structure.

use std::collections::HashMap;

/// Represents a node in the Patricia Merkle Trie
///
/// # Type Parameters
/// - `K`: Key type that can be converted to and from byte slices
/// - `V`: Value type that can be converted to byte slices
///
/// # Variants
/// - `Leaf`: Stores a key-value pair
/// - `Branch`: Internal node with a prefix and child nodes
/// - `Empty`: Represents absence of a node
#[derive(Debug, Clone)]
pub enum Node<K, V> {
    /// Leaf node containing a key-value pair
    Leaf {
        /// The complete key for this leaf
        key: K,
        /// The value stored at this leaf
        value: V,
    },
    /// Branch node containing a common prefix and child nodes
    Branch {
        /// Common prefix shared by all children
        prefix: K,
        /// Map of nibble to child nodes
        children: HashMap<u8, Box<Node<K, V>>>,
        /// Value stored at this branch
        value: V,
    },
    /// Empty node representing absence of data
    Empty,
}

impl<K, V> Node<K, V>
where
    K: Clone + From<Vec<u8>>,
    V: Clone,
{
    /// Checks if the node is empty
    ///
    /// # Returns
    /// `true` if the node is the Empty variant
    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }

    /// Checks if the node is a leaf node
    ///
    /// # Returns
    /// `true` if the node is the Leaf variant
    pub fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf { .. })
    }

    /// Checks if the node is a branch node
    ///
    /// # Returns
    /// `true` if the node is the Branch variant
    pub fn is_branch(&self) -> bool {
        matches!(self, Node::Branch { .. })
    }

    /// Converts the node into a boxed node
    ///
    /// # Returns
    /// A Box containing the node
    pub fn into_boxed(self) -> Box<Self> {
        Box::new(self)
    }

    /// Gets the children of a branch node
    ///
    /// # Returns
    /// The children HashMap if this is a branch node, empty HashMap otherwise
    pub fn into_children(self) -> HashMap<u8, Box<Self>> {
        match self {
            Node::Branch { children, .. } => children,
            _ => HashMap::new(),
        }
    }
}

/// Default implementation creating an empty node
impl<K, V> Default for Node<K, V> {
    fn default() -> Self {
        Node::Empty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_type_checks() {
        let leaf: Node<Vec<u8>, Vec<u8>> = Node::Leaf {
            key: vec![1],
            value: vec![2],
        };
        let branch: Node<Vec<u8>, Vec<u8>> = Node::Branch {
            prefix: vec![1],
            children: HashMap::new(),
            value: vec![2],
        };
        let empty: Node<Vec<u8>, Vec<u8>> = Node::Empty;

        assert!(leaf.is_leaf());
        assert!(!leaf.is_branch());
        assert!(!leaf.is_empty());

        assert!(branch.is_branch());
        assert!(!branch.is_leaf());
        assert!(!branch.is_empty());

        assert!(empty.is_empty());
        assert!(!empty.is_leaf());
        assert!(!empty.is_branch());
    }

    #[test]
    fn test_into_boxed() {
        let node: Node<Vec<u8>, Vec<u8>> = Node::Empty;
        let boxed = node.into_boxed();
        assert!(matches!(*boxed, Node::Empty));
    }
}
