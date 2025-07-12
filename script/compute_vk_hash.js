const { ethers } = require('ethers');

// Your verification key JSON data
const vk = {
  "protocol": "groth16",
  "curve": "bn128",
  "nPublic": 7,
  "vk_alpha_1": [
    "20976409993838605113628735449863593822954518178383435615121408450244994548439",
    "18282594373444936932317296193780046385734779977447701943904688486334282231",
    "1"
  ],
  "vk_beta_2": [
    [
      "4288951421882385310436487506999938293310148594500350914174606369056989848072",
      "1771462175964778807989478400541222923789903429331502286157733254308570356588"
    ],
    [
      "16086494190984521148921242231685160238089272970786434931783488518455888687043",
      "657319604068759818570729597518336932569197089623200348652880373083735138288"
    ],
    [
      "1",
      "0"
    ]
  ],
  "vk_gamma_2": [
    [
      "10857046999023057135944570762232829481370756359578518086990519993285655852781",
      "11559732032986387107991004021392285783925812861821192530917403151452391805634"
    ],
    [
      "8495653923123431417604973247489272438418190587263600148770280649306958101930",
      "4082367875863433681332203403145435568316851327593401208105741076214120093531"
    ],
    [
      "1",
      "0"
    ]
  ],
  "vk_delta_2": [
    [
      "20018535582458808817455169556315239954049518797855589775844233954464884636176",
      "14536980768905640891068762656876067780413330231964798779733651563383886990483"
    ],
    [
      "7645888909008564664711131104584964892479431885250485728968382867380516634083",
      "6392662713037391267098942533649249259537173880247782363656762798410415370205"
    ],
    [
      "1",
      "0"
    ]
  ],
  "vk_alphabeta_12": [
    [
      [
        "1366090414768760123241832417234246772835670883052710709541251939478494905486",
        "18813215388446397358318073891287548877548045712333299783054642224898897915643"
      ],
      [
        "17714134675856957726622792025444878722280971621277678435169882583518906135665",
        "12899254337889408688537725526738617187053122539093489586146713036410598856716"
      ],
      [
        "9330373079585738919378907633322480696392237667306012410879719211099322981415",
        "18464784343370546068630215802707053985856452250211676326535821470962969563654"
      ]
    ],
    [
      [
        "21739493689288055313953683341024899296808631677886034974510808764016923496323",
        "6760411626649764131045235153729012006881688663080978538928238205512423369615"
      ],
      [
        "3976541446776385635516578936802906995119542561837290963961491619727119832483",
        "597455851302745032253072236300297434044637721863935085585185821507544811877"
      ],
      [
        "7591172177424030936326676790506153488300211185323588046763217606565532135007",
        "16018401545541418428225357164667022745485524943092289791215728125276181614023"
      ]
    ]
  ],
  "IC": [
    [
      "6783199315912826852739246175158318312152334394183654108365867127541601907150",
      "13845402849808177073741152929241920332147499272553869275590576122636473123826",
      "1"
    ],
    [
      "17325373863977389596892223872115283230766118784070704809430727046432476973049",
      "17379636717181866828513283597133697401254295294213792739490675929386073536257",
      "1"
    ],
    [
      "19024432505570803598090844464779220152519451614370038112482402424881479480707",
      "12703745787871359850179098869282481342998381721815270436565911689641806506355",
      "1"
    ],
    [
      "6300677688456410523518875006884396717863465094556746265224223663082187251216",
      "12426224349390033213849328788218516835717755776535883692688335480909218783363",
      "1"
    ],
    [
      "18409837736434104339742536493787630556396473907014142195582468732350333729536",
      "5057959744206880422272798866513318160645768581729311022273560257447948176348",
      "1"
    ],
    [
      "10791982872407406380681726527764617969539247197580614580855836994165703890334",
      "18649849565622303263070432107216113388723741094016248803051534425619806366960",
      "1"
    ],
    [
      "13118055080671390887903562614846657009620256224683953757631785315635007366066",
      "17344476890077063681945949113580231201886752283888344652529171760920524183963",
      "1"
    ],
    [
      "6401994498921359817994194157430352098839856514761173267409850157101543612540",
      "17616061167283212821221797760347974671173220481453854209789084387970206238721",
      "1"
    ]
  ]
};

// Your Groth16 proof
const groth16Proof = {
  "pi_a": [
    "6946154138962140151629866789783611097416042993449764283097316949792380093292",
    "10616524098008254499890835412182053539247936545320105895375775146442999897834",
    "1"
  ],
  "pi_b": [
    [
      "14229680880636575509345895669255320396736184594029795213002826417407902394441",
      "10161418466505334928101497213197549422321804346121445988576680709975805019217"
    ],
    [
      "21050288723966195383031593329551729970683595953669365085068265939231203533503",
      "16964126921543683457689100815860923151660977100916927661467306938177860658009"
    ],
    [
      "1",
      "0"
    ]
  ],
  "pi_c": [
    "8802797099711969414972972800695423253387004516323446310599897963806877635064",
    "12369770765659770687784168740550985457373166662120735997016642801350517529603",
    "1"
  ],
  "protocol": "groth16",
  "curve": "bn128"
};

function publicInputsToBytes(publicInputs) {
  // Convert string array to uint256 array
  const uint256Inputs = publicInputs.map(input => BigInt(input));
  
  // Encode the array to bytes
  const encodedBytes = ethers.AbiCoder.defaultAbiCoder().encode(
    ['uint256[]'],
    [uint256Inputs]
  );
  
  console.log('Public Inputs:', publicInputs);
  console.log('Encoded Bytes:', encodedBytes);
  console.log('Bytes Length:', encodedBytes.length);
  console.log('Bytes (without 0x):', encodedBytes.slice(2));
  
  return encodedBytes;
}

function groth16ProofToBytes(proof) {
  // Convert string values to BigInt
  const pi_a = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])];
  const pi_b = [
    [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
    [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])]
  ];
  const pi_c = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])];
  
  // Encode the proof to bytes
  const encodedBytes = ethers.AbiCoder.defaultAbiCoder().encode(
    ['tuple(uint256[2],uint256[2][2],uint256[2])'],
    [[pi_a, pi_b, pi_c]]
  );
  
  console.log('Groth16 Proof:', proof);
  console.log('Encoded Proof Bytes:', encodedBytes);
  console.log('Proof Bytes Length:', encodedBytes.length);
  console.log('Proof Bytes (without 0x):', encodedBytes.slice(2));
  
  return encodedBytes;
}

function computeVerificationKeyHash() {
  // Create the verification key data by concatenating the key elements
  const vkData = ethers.AbiCoder.defaultAbiCoder().encode(
    ['uint256[]'],
    [[
      // vk_alpha_1 (G1 point)
      vk.vk_alpha_1[0],
      vk.vk_alpha_1[1],
      vk.vk_alpha_1[2],
      
      // vk_beta_2 (G2 point) - first element
      vk.vk_beta_2[0][0],
      vk.vk_beta_2[0][1],
      
      // vk_beta_2 (G2 point) - second element
      vk.vk_beta_2[1][0],
      vk.vk_beta_2[1][1],
      
      // vk_gamma_2 (G2 point) - first element
      vk.vk_gamma_2[0][0],
      vk.vk_gamma_2[0][1],
      
      // vk_gamma_2 (G2 point) - second element
      vk.vk_gamma_2[1][0],
      vk.vk_gamma_2[1][1],
      
      // vk_delta_2 (G2 point) - first element
      vk.vk_delta_2[0][0],
      vk.vk_delta_2[0][1],
      
      // vk_delta_2 (G2 point) - second element
      vk.vk_delta_2[1][0],
      vk.vk_delta_2[1][1],
      
      // IC[0] (first public input)
      vk.IC[0][0],
      vk.IC[0][1],
      vk.IC[0][2]
    ]]
  );
  
  // Compute the keccak256 hash
  const hash = ethers.keccak256(vkData);
  
  console.log('Verification Key Hash:', hash);
  console.log('Verification Key Hash (without 0x):', hash.slice(2));
  
  return hash;
}

// Alternative function that creates a more compact hash
function computeCompactVerificationKeyHash() {
  // Create a more compact representation by hashing the essential elements
  const compactData = ethers.AbiCoder.defaultAbiCoder().encode(
    ['uint256[]'],
    [[
      // Only include the most important verification key elements
      vk.vk_alpha_1[0],
      vk.vk_alpha_1[1],
      vk.vk_beta_2[0][0],
      vk.vk_beta_2[0][1],
      vk.vk_beta_2[1][0],
      vk.vk_beta_2[1][1],
      vk.vk_gamma_2[0][0],
      vk.vk_gamma_2[0][1],
      vk.vk_gamma_2[1][0],
      vk.vk_gamma_2[1][1],
      vk.vk_delta_2[0][0],
      vk.vk_delta_2[0][1],
      vk.vk_delta_2[1][0],
      vk.vk_delta_2[1][1]
    ]]
  );
  
  const hash = ethers.keccak256(compactData);
  
  console.log('Compact Verification Key Hash:', hash);
  console.log('Compact Verification Key Hash (without 0x):', hash.slice(2));
  
  return hash;
}

// Function to hash the entire JSON string
function computeJSONVerificationKeyHash() {
  const jsonString = JSON.stringify(vk);
  const hash = ethers.keccak256(ethers.toUtf8Bytes(jsonString));
  
  console.log('JSON Verification Key Hash:', hash);
  console.log('JSON Verification Key Hash (without 0x):', hash.slice(2));
  
  return hash;
}

// Example public inputs
const examplePublicInputs = [
  "1",
  "246127725997902171843216266411412620186",
  "157182345745625868579308743359038762261",
  "129459970215064382700745067547549175035",
  "140081306066886963849559495895445845290",
  "302812829736204631741346322141012841344",
  "131338071530641479437195446566097714441"
];

// Run all methods
console.log('=== Public Inputs to Bytes ===\n');
publicInputsToBytes(examplePublicInputs);

console.log('\n=== Groth16 Proof to Bytes ===\n');
groth16ProofToBytes(groth16Proof);

console.log('\n=== Verification Key Hash Computation ===\n');

console.log('1. Full Verification Key Hash:');
computeVerificationKeyHash();

console.log('\n2. Compact Verification Key Hash:');
computeCompactVerificationKeyHash();

console.log('\n3. JSON String Hash:');
computeJSONVerificationKeyHash();

console.log('\n=== Usage in Solidity ===');
console.log('You can use any of these hashes as your programVKey in the verifySP1 function.');
console.log('Example:');
console.log('bytes32 programVKey = 0x...; // Use one of the hashes above');
console.log('bytes memory publicValues = publicInputsToBytes(yourPublicInputs);');
console.log('bytes memory proofBytes = groth16ProofToBytes(yourProof);');
console.log('verifier.verifySP1(programVKey, publicValues, proofBytes);'); 