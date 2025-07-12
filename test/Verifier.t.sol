// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Verifier.sol";
import {SP1Verifier} from "../lib/sp1-contracts/contracts/src/v4.0.0-rc.3/SP1VerifierGroth16.sol";

contract VerifierTest is Test {
    VerifierGooglePw public verifier;
    SP1Verifier public sp1Verifier;
    
    // Example verification key elements (from your JSON)
    uint256[2] public vkAlpha1 = [
        20976409993838605113628735449863593822954518178383435615121408450244994548439,
        18282594373444936932317296193780046043385734779977447701943904688486334282231
    ];
    
    uint256[2][2] public vkBeta2 = [
        [4288951421882385310436487506999938293310148594500350914174606369056989848072, 1771462175964778807989478400541222923789903429331502286157733254308570356588],
        [16086494190984521148921242231685160238089272970786434931783488518455888687043, 657319604068759818570729597518336932569197089623200348652880373083735138288]
    ];
    
    uint256[2][2] public vkGamma2 = [
        [10857046999023057135944570762232829481370756359578518086990519993285655852781, 11559732032986387107991004021392285783925812861821192530917403151452391805634],
        [8495653923123431417604973247489272438418190587263600148770280649306958101930, 4082367875863433681332203403145435568316851327593401208105741076214120093531]
    ];
    
    uint256[2][2] public vkDelta2 = [
        [20018535582458808817455169556315239954049518797855589775844233954464884636176, 14536980768905640891068762656876067780413330231964798779733651563383886990483],
        [7645888909008564664711131104584964892479431885250485728968382867380516634083, 6392662713037391267098942533649249259537173880247782363656762798410415370205]
    ];
    
    // Example IC array (all values from your verification key)
    uint256[3][8] public IC = [
        [
            6783199315912826852739246175158318312152334394183654108365867127541601907150,
            13845402849808177073741152929241920332147499272553869275590576122636473123826,
            1
        ],
        [
            17325373863977389596892223872115283230766118784070704809430727046432476973049,
            17379636717181866828513283597133697401254295294213792739490675929386073536257,
            1
        ],
        [
            19024432505570803598090844464779220152519451614370038112482402424881479480707,
            12703745787871359850179098869282481342998381721815270436565911689641806506355,
            1
        ],
        [
            6300677688456410523518875006884396717863465094556746265224223663082187251216,
            12426224349390033213849328788218516835717755776535883692688335480909218783363,
            1
        ],
        [
            18409837736434104339742536493787630556396473907014142195582468732350333729536,
            5057959744206880422272798866513318160645768581729311022273560257447948176348,
            1
        ],
        [
            10791982872407406380681726527764617969539247197580614580855836994165703890334,
            18649849565622303263070432107216113388723741094016248803051534425619806366960,
            1
        ],
        [
            13118055080671390887903562614846657009620256224683953757631785315635007366066,
            17344476890077063681945949113580231201886752283888344652529171760920524183963,
            1
        ],
        [
            6401994498921359817994194157430352098839856514761173267409850157101543612540,
            17616061167283212821221797760347974671173220481453854209789084387970206238721,
            1
        ]
    ];
    
    // Example public inputs (from your array)
    uint256[] public publicInputs = [
        1,
        246127725997902171843216266411412620186,
        157182345745625868579308743359038762261,
        129459970215064382700745067547549175035,
        140081306066886963849559495895445845290,
        302812829736204631741346322141012841344,
        131338071530641479437195446566097714441
    ];
    
    // Example Groth16 proof (from your JSON)
    Groth16Proof proof;
    
    function setUp() public {
        // Deploy a custom SP1 verifier with your VERIFIER_HASH
        sp1Verifier = new SP1Verifier();
        verifier = new VerifierGooglePw(address(sp1Verifier));
        
        // Set up the proof with your example values
        proof.pi_a = [
            6946154138962140151629866789783611097416042993449764283097316949792380093292,
            10616524098008254499890835412182053539247936545320105895375775146442999897834
        ];
        
        proof.pi_b = [
            [14229680880636575509345895669255320396736184594029795213002826417407902394441, 10161418466505334928101497213197549422321804346121445988576680709975805019217],
            [21050288723966195383031593329551729970683595953669365085068265939231203533503, 16964126921543683457689100815860923151660977100916927661467306938177860658009]
        ];
        
        proof.pi_c = [
            8802797099711969414972972800695423253387004516323446310599897963806877635064,
            12369770765659770687784168740550985457373166662120735997016642801350517529603
        ];
    }
    
    function testPublicInputsToBytes() public {
        bytes memory encoded = verifier.publicInputsToBytes(publicInputs);
        
        console.log("Public inputs encoded length:", encoded.length);
        console.log("Public inputs encoded (hex):", vm.toString(encoded));
        
        // Verify the encoding is not empty
        assertTrue(encoded.length > 0, "Encoded public inputs should not be empty");
        
        // Verify we can decode it back (basic sanity check)
        uint256[] memory decoded = abi.decode(encoded, (uint256[]));
        assertEq(decoded.length, publicInputs.length, "Decoded length should match original");
        
        for (uint256 i = 0; i < publicInputs.length; i++) {
            assertEq(decoded[i], publicInputs[i], "Decoded value should match original");
        }
    }
    
    function testGroth16ProofToBytes() public {
        bytes memory encoded = verifier.groth16ProofToBytes(proof);
        
        console.log("Proof encoded length:", encoded.length);
        console.log("Proof encoded (hex):", vm.toString(encoded));
        
        // Verify the encoding is not empty
        assertTrue(encoded.length > 0, "Encoded proof should not be empty");
        
        // Verify we can decode it back (basic sanity check)
        Groth16Proof memory decoded = abi.decode(encoded, (Groth16Proof));
        
        // Check pi_a
        assertEq(decoded.pi_a[0], proof.pi_a[0], "pi_a[0] should match");
        assertEq(decoded.pi_a[1], proof.pi_a[1], "pi_a[1] should match");
        
        // Check pi_b
        assertEq(decoded.pi_b[0][0], proof.pi_b[0][0], "pi_b[0][0] should match");
        assertEq(decoded.pi_b[0][1], proof.pi_b[0][1], "pi_b[0][1] should match");
        assertEq(decoded.pi_b[1][0], proof.pi_b[1][0], "pi_b[1][0] should match");
        assertEq(decoded.pi_b[1][1], proof.pi_b[1][1], "pi_b[1][1] should match");
        
        // Check pi_c
        assertEq(decoded.pi_c[0], proof.pi_c[0], "pi_c[0] should match");
        assertEq(decoded.pi_c[1], proof.pi_c[1], "pi_c[1] should match");
    }
    
    function testEncodeGroth16Proof() public {
        bytes memory encoded = verifier.encodeGroth16Proof(
            proof.pi_a,
            proof.pi_b,
            proof.pi_c
        );
        
        console.log("Proof encoded via individual params length:", encoded.length);
        console.log("Proof encoded via individual params (hex):", vm.toString(encoded));
        
        // Verify the encoding is not empty
        assertTrue(encoded.length > 0, "Encoded proof should not be empty");
        
        // Verify it matches the struct-based encoding
        bytes memory structEncoded = verifier.groth16ProofToBytes(proof);
        assertEq(encoded.length, structEncoded.length, "Both encoding methods should produce same length");
        assertEq(keccak256(encoded), keccak256(structEncoded), "Both encoding methods should produce same result");
    }
    
    function computeVerificationKeyHash() public view returns (bytes32) {
        bytes memory vkData = abi.encode(
            vkAlpha1[0], vkAlpha1[1], uint256(1),
            vkBeta2[0][0], vkBeta2[0][1],
            vkBeta2[1][0], vkBeta2[1][1],
            vkGamma2[0][0], vkGamma2[0][1],
            vkGamma2[1][0], vkGamma2[1][1],
            vkDelta2[0][0], vkDelta2[0][1],
            vkDelta2[1][0], vkDelta2[1][1]
        );
        // Append all IC values (flattened)
        for (uint256 i = 0; i < IC.length; i++) {
            vkData = bytes.concat(vkData, abi.encode(IC[i][0], IC[i][1], IC[i][2]));
        }
        return keccak256(vkData);
    }
    
    function testVerificationKeyHash() public view {
        bytes32 hash = computeVerificationKeyHash();
        console.log("Verification key hash:", vm.toString(hash));
        assertTrue(hash != bytes32(0), "Verification key hash should not be zero");
    }
    
    function testCompleteVerificationFlow() public view {
        // This test simulates the complete verification flow
        // Note: Since we're using a mock SP1 verifier, this won't actually verify the proof
        // but it will test that all the encoding functions work together
        // 1. Compute the verification key hash that includes all IC values
        bytes32 programVKey = computeVerificationKeyHash();
        // 2. Reduce public inputs modulo Fr
        uint256 Fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256[] memory reducedInputs = new uint256[](publicInputs.length);
        for (uint256 i = 0; i < publicInputs.length; i++) {
            reducedInputs[i] = publicInputs[i] % Fr;
        }
        // 3. Encode public inputs
        bytes memory publicValues = verifier.publicInputsToBytes(publicInputs);
        console.log("Public values:", vm.toString(publicValues));
        // 4. Prepare proof as uint256[8]
        uint256[8] memory proofArray = [
            proof.pi_a[0], proof.pi_a[1],
            proof.pi_b[0][0], proof.pi_b[0][1],
            proof.pi_b[1][0], proof.pi_b[1][1],
            proof.pi_c[0], proof.pi_c[1]
        ];
        // 5. Call verifySP1 with the real SP1 verifier
        bool result = verifier.verifySP1(programVKey, publicValues, proofArray);
        assertTrue(result, "Proof should verify successfully");
        // Verify all encoded data is valid
        assertTrue(programVKey != bytes32(0), "Program VKey should not be zero");
        assertTrue(publicValues.length > 0, "Public values should not be empty");
    }
    
    function testProofValues() public view{
        // Test that the proof values are correctly set
        console.log("Proof values:");
        console.log("pi_a[0]:", proof.pi_a[0]);
        console.log("pi_a[1]:", proof.pi_a[1]);
        console.log("pi_b[0][0]:", proof.pi_b[0][0]);
        console.log("pi_b[0][1]:", proof.pi_b[0][1]);
        console.log("pi_b[1][0]:", proof.pi_b[1][0]);
        console.log("pi_b[1][1]:", proof.pi_b[1][1]);
        console.log("pi_c[0]:", proof.pi_c[0]);
        console.log("pi_c[1]:", proof.pi_c[1]);
        
        // Verify all proof values are non-zero
        assertTrue(proof.pi_a[0] != 0, "pi_a[0] should not be zero");
        assertTrue(proof.pi_a[1] != 0, "pi_a[1] should not be zero");
        assertTrue(proof.pi_b[0][0] != 0, "pi_b[0][0] should not be zero");
        assertTrue(proof.pi_b[0][1] != 0, "pi_b[0][1] should not be zero");
        assertTrue(proof.pi_b[1][0] != 0, "pi_b[1][0] should not be zero");
        assertTrue(proof.pi_b[1][1] != 0, "pi_b[1][1] should not be zero");
        assertTrue(proof.pi_c[0] != 0, "pi_c[0] should not be zero");
        assertTrue(proof.pi_c[1] != 0, "pi_c[1] should not be zero");
    }
} 