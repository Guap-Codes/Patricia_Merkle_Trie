//! Example of using the Patricia Merkle Trie as a DNS resolver.
//!
//! This example demonstrates how to use the Patricia Merkle Trie to store and resolve
//! domain names to IP addresses. The trie provides efficient storage and retrieval
//! of key-value pairs, with cryptographic verification capabilities.

use patricia_merkle_trie::{PatriciaMerkleTrie, Result};
use std::error::Error;

/// Represents a simple DNS resolver using a Patricia Merkle Trie
struct DnsResolver {
    trie: PatriciaMerkleTrie<Vec<u8>, Vec<u8>>,
}

impl DnsResolver {
    /// Creates a new DNS resolver
    fn new() -> Self {
        Self {
            trie: PatriciaMerkleTrie::new(),
        }
    }

    /// Adds a domain name and its IP address to the resolver
    fn add_record(&mut self, domain: &str, ip: &str) -> Result<()> {
        println!("\nAttempting to add record:");
        println!("  Domain: {}", domain);
        println!("  IP: {}", ip);
        println!("  Domain bytes: {:?}", domain.as_bytes());
        println!("  IP bytes: {:?}", ip.as_bytes());

        match self
            .trie
            .insert(domain.as_bytes().to_vec(), ip.as_bytes().to_vec())
        {
            Ok(_) => {
                println!("Successfully added record for {}", domain);
                Ok(())
            }
            Err(e) => {
                println!("Error adding record for {}: {:?}", domain, e);
                println!("Error details: {}", e);
                if let Some(source) = e.source() {
                    println!("Caused by: {}", source);
                }
                Err(e)
            }
        }
    }

    /// Looks up the IP address for a given domain name
    fn lookup(&self, domain: &str) -> Result<Option<String>> {
        println!("\nLooking up domain: {}", domain);
        match self.trie.get(&domain.as_bytes().to_vec()) {
            Ok(result) => {
                match &result {
                    Some(bytes) => println!(
                        "Found IP for {}: {}",
                        domain,
                        String::from_utf8_lossy(bytes.as_ref())
                    ),
                    None => println!("No IP found for {}", domain),
                }
                Ok(result.map(|bytes| String::from_utf8_lossy(bytes.as_ref()).into_owned()))
            }
            Err(e) => {
                println!("Error looking up {}: {:?}", domain, e);
                Err(e)
            }
        }
    }

    /// Verifies the integrity of the DNS records using the root hash
    fn verify_records(&self) -> Result<Vec<u8>> {
        println!("\nVerifying DNS records...");
        match self.trie.root_hash() {
            Ok(hash) => {
                println!("Root hash computed successfully: {:?}", hash);
                Ok(hash)
            }
            Err(e) => {
                println!("Error computing root hash: {:?}", e);
                Err(e)
            }
        }
    }
}

fn main() -> Result<()> {
    // Create a new DNS resolver
    let mut resolver = DnsResolver::new();

    println!("\nAdding DNS records...");

    // Try adding records with detailed error handling
    let records = vec![
        ("example.com", "93.184.216.34"),
        ("rust-lang.org", "13.227.75.110"),
        ("github.com", "140.82.114.4"),
    ];

    // First add all records
    for (domain, ip) in &records {
        if let Err(e) = resolver.add_record(domain, ip) {
            println!("Failed to add record for {}: {:?}", domain, e);
            println!("Error details: {}", e);
            if let Some(source) = e.source() {
                println!("Caused by: {}", source);
            }
            return Err(e);
        }
    }

    // Then verify them
    println!("\nVerifying records were added correctly...");
    for (domain, _) in &records {
        if let Err(e) = resolver.lookup(domain) {
            println!("Failed to lookup {}: {:?}", domain, e);
            return Err(e);
        }
    }

    // Compute and display the root hash for verification
    let root_hash = resolver.verify_records()?;
    println!("\nFinal root hash: {:?}", root_hash);

    Ok(())
}
