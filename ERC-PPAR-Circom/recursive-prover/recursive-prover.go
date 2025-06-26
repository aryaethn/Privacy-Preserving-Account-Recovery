package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/circom2gnark/parser"
)

type RecursiveProofCircuit struct {
	HeaderProof stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	HeaderVk    stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
	HeaderPub   stdgroth16.Witness[sw_bn254.ScalarField] `gnark:",public"`

	BodyProof   stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	BodyVk      stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
	BodyPub     stdgroth16.Witness[sw_bn254.ScalarField] `gnark:",public"`
}

func (c *RecursiveProofCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	if err := verifier.AssertProof(c.HeaderVk, c.HeaderProof, c.HeaderPub, stdgroth16.WithCompleteArithmetic()); err != nil {
		return fmt.Errorf("header proof failed: %w", err)
	}
	if err := verifier.AssertProof(c.BodyVk, c.BodyProof, c.BodyPub, stdgroth16.WithCompleteArithmetic()); err != nil {
		return fmt.Errorf("body proof failed: %w", err)
	}
	return nil
}

func main() {
	// Load header proof, vkey, public signals
	headerProofData, err := os.ReadFile("header_proof.json")
	if err != nil {
		log.Fatalf("failed to read header proof: %v", err)
	}
	headerVkData, err := os.ReadFile("header_vkey.json")
	if err != nil {
		log.Fatalf("failed to read header vkey: %v", err)
	}
	headerPubData, err := os.ReadFile("header_public_signals.json")
	if err != nil {
		log.Fatalf("failed to read header public signals: %v", err)
	}

	// Load body proof, vkey, public signals
	bodyProofData, err := os.ReadFile("body_proof.json")
	if err != nil {
		log.Fatalf("failed to read body proof: %v", err)
	}
	bodyVkData, err := os.ReadFile("body_vkey.json")
	if err != nil {
		log.Fatalf("failed to read body vkey: %v", err)
	}
	bodyPubData, err := os.ReadFile("body_public_signals.json")
	if err != nil {
		log.Fatalf("failed to read body public signals: %v", err)
	}

	// Unmarshal header
	headerProof, err := parser.UnmarshalCircomProofJSON(headerProofData)
	if err != nil {
		log.Fatalf("failed to unmarshal header proof: %v", err)
	}
	headerVk, err := parser.UnmarshalCircomVerificationKeyJSON(headerVkData)
	if err != nil {
		log.Fatalf("failed to unmarshal header vkey: %v", err)
	}
	headerPub, err := parser.UnmarshalCircomPublicSignalsJSON(headerPubData)
	if err != nil {
		log.Fatalf("failed to unmarshal header public signals: %v", err)
	}

	// Unmarshal body
	bodyProof, err := parser.UnmarshalCircomProofJSON(bodyProofData)
	if err != nil {
		log.Fatalf("failed to unmarshal body proof: %v", err)
	}
	bodyVk, err := parser.UnmarshalCircomVerificationKeyJSON(bodyVkData)
	if err != nil {
		log.Fatalf("failed to unmarshal body vkey: %v", err)
	}
	bodyPub, err := parser.UnmarshalCircomPublicSignalsJSON(bodyPubData)
	if err != nil {
		log.Fatalf("failed to unmarshal body public signals: %v", err)
	}

	// Convert to gnark recursion format
	headerPlaceholders, err := parser.PlaceholdersForRecursion(headerVk, len(headerPub), true)
	if err != nil {
		log.Fatalf("failed to create header placeholders: %v", err)
	}
	headerRecursion, err := parser.ConvertCircomToGnarkRecursion(headerVk, headerProof, headerPub, true)
	if err != nil {
		log.Fatalf("failed to convert header proof to recursion: %v", err)
	}

	bodyPlaceholders, err := parser.PlaceholdersForRecursion(bodyVk, len(bodyPub), true)
	if err != nil {
		log.Fatalf("failed to create body placeholders: %v", err)
	}
	bodyRecursion, err := parser.ConvertCircomToGnarkRecursion(bodyVk, bodyProof, bodyPub, true)
	if err != nil {
		log.Fatalf("failed to convert body proof to recursion: %v", err)
	}

	// Create placeholder circuit
	placeholderCircuit := &RecursiveProofCircuit{
		HeaderProof: headerPlaceholders.Proof,
		HeaderVk:    headerPlaceholders.Vk,
		HeaderPub:   headerPlaceholders.Witness,
		BodyProof:   bodyPlaceholders.Proof,
		BodyVk:      bodyPlaceholders.Vk,
		BodyPub:     bodyPlaceholders.Witness,
	}

	fmt.Println("Compiling recursive circuit...")
	startTime := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, placeholderCircuit)
	if err != nil {
		log.Fatalf("failed to compile recursive circuit: %v", err)
	}
	fmt.Printf("Compilation time: %v\n", time.Since(startTime)))

	fmt.Println("Setting up proving and verifying keys...")
	startTime = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("failed to setup keys: %v", err)
	}
	fmt.Printf("Setup time: %v\n", time.Since(startTime))\n")

	// Create the circuit assignment with actual values
	assignment := &RecursiveProofCircuit{
		HeaderProof: headerRecursion.Proof,
		HeaderVk:    headerRecursion.Vk,
		HeaderPub:   headerRecursion.PublicInputs,
		BodyProof:   bodyRecursion.Proof,
		BodyVk:      bodyRecursion.Vk,
		BodyPub:     bodyRecursion.PublicInputs,
	}

	fmt.Println("Creating witness...")
	startTime = time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("failed to create witness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("failed to create public witness: %v", err)
	}
	fmt.Printf("Witness creation time: %v\n", time.Since(startTime))\n")

	fmt.Println("Proving...")
	startTime = time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("proving failed: %v", err)
	}
	fmt.Printf("Proving time: %v\n", time.Since(startTime))\n")

	fmt.Println("Verifying recursive proof...")
	startTime = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("recursive proof verification failed: %v", err)
	}
	fmt.Printf("Recursive proof verification succeeded! took %s\n", time.Since(startTime))

	// Optionally, export the recursive proof to Circom format
	fmt.Println("Exporting recursive proof to Circom format...")
	recProof, recVk, recPub, err := parser.ConvertGnarkToCircom(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("failed to convert recursive proof to Circom: %v", err)
	}
	os.WriteFile("recursive_proof.json", parser.MustMarshalCircomProofJSON(recProof), 0644)
	os.WriteFile("recursive_vkey.json", parser.MustMarshalCircomVerificationKeyJSON(recVk), 0644)
	os.WriteFile("recursive_public_signals.json", parser.MustMarshalCircomPublicSignalsJSON(recPub), 0644)
	fmt.Println("Recursive proof exported as recursive_proof.json, recursive_vkey.json, recursive_public_signals.json")
}
