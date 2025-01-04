use crate::{
    hash::{hash_branch, hash_empty, hash_leaf},
    node::Node,
    utils::{common_prefix, to_nibbles},
    PatriciaMerkleTrie, Result, TrieError,
};

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Vec<(u8, Vec<u8>)>,
}

pub trait MerkleProofTrait<K, V> {
    fn generate_proof(&self, key: &K) -> Result<MerkleProof>;
    fn verify_proof(root_hash: Vec<u8>, proof: MerkleProof) -> Result<bool>;
    fn hash_node(&self, node: &Node<K, Option<V>>) -> Result<Vec<u8>>;
}

// Type aliases for complex types
type Proof = Vec<(u8, Vec<u8>)>;
type ProofResult = Result<(Vec<u8>, Proof)>;

impl<K, V> MerkleProofTrait<K, V> for PatriciaMerkleTrie<K, V>
where
    K: AsRef<[u8]> + Clone + From<Vec<u8>> + std::fmt::Debug,
    V: Clone + AsRef<[u8]> + std::fmt::Debug,
{
    fn generate_proof(&self, key: &K) -> Result<MerkleProof> {
        // Validate key
        if key.as_ref().is_empty() {
            return Err(TrieError::InvalidKey);
        }

        let key_nibbles = to_nibbles(key.as_ref())?;
        let (value, proof) = self.generate_proof_at(self.root(), key_nibbles, vec![])?;

        // Return error if proof is empty (key not found) or no value was found
        if proof.is_empty() || value.is_empty() {
            return Err(TrieError::NodeNotFound);
        }

        Ok(MerkleProof {
            key: key.as_ref().to_vec(),
            value,
            proof,
        })
    }

    fn verify_proof(root_hash: Vec<u8>, proof: MerkleProof) -> Result<bool> {
        // Validate inputs
        if proof.key.is_empty() {
            return Err(TrieError::InvalidKey);
        }
        if proof.proof.is_empty() {
            return Err(TrieError::InvalidProof);
        }

        // Start with the leaf hash
        let mut current_hash = hash_leaf(&proof.key, &proof.value)?;

        // Process proof elements from leaf to root
        let mut proof_iter = proof.proof.iter().peekable();

        while let Some((nibble, hash)) = proof_iter.next() {
            if hash.is_empty() {
                return Err(TrieError::InvalidProof);
            }

            // First verify that the current hash matches
            if current_hash != *hash {
                return Ok(false);
            }

            // If there's a next hash, prepare the current_hash for it
            if let Some((next_nibble, _)) = proof_iter.peek() {
                if *next_nibble == 0 {
                    // Next is a branch node, compute branch hash with current as child
                    let children = vec![(*nibble, current_hash)];
                    current_hash = hash_branch(&[], &children, &[])?;
                } else {
                    // Next is another child node, just take its hash
                    current_hash = hash.clone();
                }
            }
        }

        Ok(current_hash == root_hash)
    }

    fn hash_node(&self, node: &Node<K, Option<V>>) -> Result<Vec<u8>> {
        match node {
            Node::Empty => Ok(hash_empty()),
            Node::Leaf { key, value } => hash_leaf(
                key.as_ref(),
                value.as_ref().map(|v| v.as_ref()).unwrap_or(&[]),
            ),
            Node::Branch {
                prefix,
                children,
                value,
            } => {
                let child_hashes = children
                    .iter()
                    .map(|(k, child)| Ok((*k, self.hash_node(child)?)))
                    .collect::<Result<Vec<_>>>()?;

                hash_branch(
                    prefix.as_ref(),
                    &child_hashes,
                    value.as_ref().map(|v| v.as_ref()).unwrap_or(&[]),
                )
            }
        }
    }
}

impl<K, V> PatriciaMerkleTrie<K, V>
where
    K: AsRef<[u8]> + Clone + From<Vec<u8>> + std::fmt::Debug,
    V: Clone + AsRef<[u8]> + std::fmt::Debug,
{
    fn generate_proof_at(
        &self,
        node: &Node<K, Option<V>>,
        nibbles: Vec<u8>,
        mut proof: Proof,
    ) -> ProofResult {
        let node_hash = self.hash_node(node)?;

        match node {
            Node::Empty => Ok((vec![], proof)),
            Node::Leaf { key, value } => {
                let existing_nibbles = to_nibbles(key.as_ref())?;
                if nibbles != existing_nibbles {
                    return Ok((vec![], proof));
                }

                let value_bytes = value
                    .as_ref()
                    .map(|v| v.as_ref().to_vec())
                    .unwrap_or_default();

                // Add leaf hash to proof
                proof.push((existing_nibbles[0], node_hash));
                Ok((value_bytes, proof))
            }
            Node::Branch {
                prefix,
                children,
                value,
            } => {
                let prefix_nibbles = to_nibbles(prefix.as_ref())?;
                let common_len = common_prefix(&prefix_nibbles, &nibbles);

                // If we don't match the entire prefix, key is not in this branch
                if common_len < prefix_nibbles.len() {
                    return Ok((vec![], proof));
                }

                let remaining_nibbles = nibbles[common_len..].to_vec();

                // If no remaining nibbles, we're at the target branch
                if remaining_nibbles.is_empty() {
                    let value_bytes = value
                        .as_ref()
                        .map(|v| v.as_ref().to_vec())
                        .unwrap_or_default();

                    if !value_bytes.is_empty() {
                        // Add branch hash to proof
                        proof.push((0, node_hash));
                        return Ok((value_bytes, proof));
                    }
                    return Ok((vec![], proof));
                }

                // Otherwise, traverse down the appropriate child
                let child_nibble = remaining_nibbles[0];
                if let Some(child) = children.get(&child_nibble) {
                    let (value_bytes, child_proof) =
                        self.generate_proof_at(child, remaining_nibbles[1..].to_vec(), vec![])?;

                    // Only proceed if we found a value
                    if !value_bytes.is_empty() {
                        // Add branch hash to proof
                        proof.push((0, node_hash));

                        // Add child hash to proof
                        let child_hash = self.hash_node(child)?;
                        proof.push((child_nibble, child_hash));

                        // Add child proof
                        proof.extend(child_proof);
                        return Ok((value_bytes, proof));
                    }
                }
                Ok((vec![], proof))
            }
        }
    }
}
