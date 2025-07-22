use hypercube_signatures::xmss::{XMSSKeypair, XMSSParams};

fn main() {
    println!("Testing XMSS implementation...");

    // Test 1: Basic parameter creation
    let params = XMSSParams::new(4, 67, 16);
    assert_eq!(params.tree_height(), 4);
    assert_eq!(params.winternitz_parameter(), 67);
    println!("✓ Parameter creation test passed");

    // Test 2: Keypair generation
    let keypair = XMSSKeypair::generate(&params);
    assert_eq!(keypair.private_key().leaf_index(), 0);
    assert_eq!(keypair.public_key().root().len(), 32);
    assert_eq!(keypair.public_key().public_seed().len(), 32);
    println!("✓ Keypair generation test passed");

    // Test 3: Sign and verify
    let mut keypair = XMSSKeypair::generate(&params);
    let message = b"Hello, XMSS!";

    let signature = keypair.sign(message);
    assert_eq!(signature.leaf_index(), 0);
    assert_eq!(signature.randomness().len(), 32);
    println!("✓ Signature creation test passed");

    // Test 4: Verify signature
    let is_valid = keypair
        .public_key()
        .verify(message, &signature, keypair.params());
    if is_valid {
        println!("✓ Signature verification test passed");
    } else {
        println!("✗ Signature verification test failed");
        println!(
            "  Debug: PK root length = {}",
            keypair.public_key().root().len()
        );
        println!(
            "  Debug: Auth path has {} nodes",
            signature.auth_path().nodes().len()
        );
    }

    // Test 5: State increment
    assert_eq!(keypair.private_key().leaf_index(), 1);
    println!("✓ State increment test passed");

    println!("\nAll XMSS tests completed!");
}
