use hypercube_signatures::zk::circuit::batch_verify::BatchVerifyCircuit;
use hypercube_signatures::zk::circuit::hypercube::HypercubeGadget;
use hypercube_signatures::zk::circuit::poseidon2_wots::Poseidon2WotsGadget;
use hypercube_signatures::zk::{C, D, F};

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;

#[test]
fn test_hypercube_layer_verification() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    let w = 16;
    let v = 32;
    let expected_layer = 100;
    
    // Create targets for vertex components
    let mut vertex_targets = Vec::new();
    for _ in 0..v {
        vertex_targets.push(builder.add_virtual_target());
    }
    
    // Create target for expected layer
    let expected_layer_target = builder.add_virtual_target();
    
    // Verify layer
    let is_valid = HypercubeGadget::verify_layer(
        &mut builder,
        &vertex_targets,
        expected_layer_target,
        w,
        v,
    );
    
    // Assert the result is true
    builder.assert_one(is_valid.target);
    
    // Build circuit
    let data = builder.build::<C>();
    
    // Create witness with valid vertex in layer 100
    let mut pw = PartialWitness::new();
    
    // Set vertex components that sum to v*w - 100 = 512 - 100 = 412
    // For simplicity, set first 31 components to 13 and last one to 9
    // 31 * 13 + 9 = 403 + 9 = 412
    for i in 0..31 {
        pw.set_target(vertex_targets[i], F::from_canonical_usize(13));
    }
    pw.set_target(vertex_targets[31], F::from_canonical_usize(9));
    
    pw.set_target(expected_layer_target, F::from_canonical_usize(expected_layer));
    
    // Prove
    let proof = data.prove(pw).expect("Proof generation should succeed");
    
    // Verify
    assert!(data.verify(proof).is_ok(), "Proof should verify");
}

#[test]
fn test_tl1c_checksum_calculation() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Create layer target
    let layer_target = builder.add_virtual_target();
    
    // Calculate checksum
    let checksum = HypercubeGadget::calculate_tl1c_checksum(&mut builder, layer_target);
    
    // Create output target
    let output = builder.add_virtual_target();
    builder.connect(checksum, output);
    builder.register_public_input(output);
    
    // Build circuit
    let data = builder.build::<C>();
    
    // Test with layer = 42
    let mut pw = PartialWitness::new();
    pw.set_target(layer_target, F::from_canonical_usize(42));
    
    let proof = data.prove(pw).expect("Proof generation should succeed");
    
    // Verify checksum is 43 (layer + 1)
    assert_eq!(
        proof.public_inputs[0],
        F::from_canonical_usize(43),
        "Checksum should be layer + 1"
    );
}

#[test]
fn test_poseidon2_hash_chain_gadget() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Create input hash
    let input_hash = builder.add_virtual_hash();
    
    // Create iterations target (we'll use a constant for simplicity)
    let iterations = builder.constant(F::from_canonical_usize(3));
    
    // Compute hash chain
    let output = Poseidon2WotsGadget::hash_chain(
        &mut builder,
        input_hash,
        iterations,
        5, // max_iterations
    );
    
    // Register outputs
    for i in 0..4 {
        builder.register_public_input(output.elements[i]);
    }
    
    // Build circuit
    let data = builder.build::<C>();
    
    // Create witness
    let mut pw = PartialWitness::new();
    pw.set_hash_target(input_hash, plonky2::hash::hash_types::HashOut {
        elements: [F::ONE, F::TWO, F::ZERO, F::ONE],
    });
    
    // Prove
    let proof = data.prove(pw).expect("Proof generation should succeed");
    
    // Verify proof
    assert!(data.verify(proof).is_ok(), "Proof should verify");
}

#[test]
fn test_batch_verify_circuit_construction() {
    let num_signatures = 2;
    let chains_per_signature = 4;
    let w = 16;
    
    // Build circuit
    let (builder, targets) = BatchVerifyCircuit::build_circuit::<F, D>(
        num_signatures,
        chains_per_signature,
        w,
        "TSL",
    );
    
    // Verify targets were created correctly
    assert_eq!(targets.signatures.len(), num_signatures);
    assert_eq!(targets.public_keys.len(), num_signatures);
    assert_eq!(targets.message_digits.len(), num_signatures);
    
    for i in 0..num_signatures {
        assert_eq!(targets.signatures[i].len(), chains_per_signature);
        assert_eq!(targets.public_keys[i].len(), chains_per_signature);
        assert_eq!(targets.message_digits[i].len(), chains_per_signature);
    }
    
    // Build the circuit
    let data = builder.build::<C>();
    
    // Check public inputs count
    // message_hash (4) + num_signatures * chains_per_signature * 4 (for public keys)
    let expected_public_inputs = 4 + num_signatures * chains_per_signature * 4;
    assert_eq!(
        data.common.num_public_inputs, expected_public_inputs,
        "Incorrect number of public inputs"
    );
}

#[test]
fn test_conditional_hash_update() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Create two hash targets
    let hash1 = builder.add_virtual_hash();
    let hash2 = builder.add_virtual_hash();
    
    // Create condition
    let condition = builder.add_virtual_bool_target_safe();
    
    // Perform conditional update
    let result = Poseidon2WotsGadget::conditional_hash_update(
        &mut builder,
        hash1,
        hash2,
        condition,
    );
    
    // Register outputs
    for i in 0..4 {
        builder.register_public_input(result.elements[i]);
    }
    
    // Build circuit
    let data = builder.build::<C>();
    
    // Test case 1: condition = true (should select hash2)
    let mut pw1 = PartialWitness::new();
    pw1.set_hash_target(hash1, plonky2::hash::hash_types::HashOut {
        elements: [F::ONE, F::TWO, F::ZERO, F::ONE],
    });
    pw1.set_hash_target(hash2, plonky2::hash::hash_types::HashOut {
        elements: [F::TWO, F::ONE, F::ONE, F::ZERO],
    });
    pw1.set_bool_target(condition, true);
    
    let proof1 = data.prove(pw1).expect("Proof generation should succeed");
    
    // Verify we got hash2
    assert_eq!(proof1.public_inputs[0], F::TWO);
    assert_eq!(proof1.public_inputs[1], F::ONE);
    assert_eq!(proof1.public_inputs[2], F::ONE);
    assert_eq!(proof1.public_inputs[3], F::ZERO);
    
    // Test case 2: condition = false (should select hash1)
    let mut pw2 = PartialWitness::new();
    pw2.set_hash_target(hash1, plonky2::hash::hash_types::HashOut {
        elements: [F::ONE, F::TWO, F::ZERO, F::ONE],
    });
    pw2.set_hash_target(hash2, plonky2::hash::hash_types::HashOut {
        elements: [F::TWO, F::ONE, F::ONE, F::ZERO],
    });
    pw2.set_bool_target(condition, false);
    
    let proof2 = data.prove(pw2).expect("Proof generation should succeed");
    
    // Verify we got hash1
    assert_eq!(proof2.public_inputs[0], F::ONE);
    assert_eq!(proof2.public_inputs[1], F::TWO);
    assert_eq!(proof2.public_inputs[2], F::ZERO);
    assert_eq!(proof2.public_inputs[3], F::ONE);
}