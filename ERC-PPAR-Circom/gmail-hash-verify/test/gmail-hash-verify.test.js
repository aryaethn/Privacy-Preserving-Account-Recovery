import { assert } from "chai";
import path from "path";
import { createHash } from "crypto";
import { wasm as build } from "circom_tester";
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// --- Helper Functions ---
function stringToBytes(str, len) {
    const bytes = Array(len).fill(0n);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = BigInt(str.charCodeAt(i));
    }
    return bytes;
}

function getPaddedHashChunks(str, maxLen) {
    const paddedBytes = Buffer.alloc(maxLen);
    paddedBytes.write(str, 'utf-8');
    const hashHex = createHash('sha256').update(paddedBytes).digest('hex');
    const high_hex = hashHex.substring(0, 32);
    const low_hex = hashHex.substring(32, 64);
    const high_dec = BigInt('0x' + high_hex).toString();
    const low_dec = BigInt('0x' + low_hex).toString();
    return [high_dec, low_dec];
}

// --- Test Suite ---
import fs from "fs";



describe("ExtractAndVerifyHash Final Circom Tests", function () {
    this.timeout(400000);

    describe("When maxSliceLen is 16", () => {
        let circuit;
        const maxSliceLen = 16;
        const maxOutputLen = 32;

        before(async () => {
            // Compile the specific test circuit for maxSliceLen=16
            const circuitPath = path.resolve(__dirname, "./circuits/test_16.circom");
            circuit = await build(circuitPath); // No options object needed anymore
            await circuit.loadSymbols();
        });

        it("✅ should succeed for a valid 16-byte header", async () => {
            const headerStr = "This from:<test>";
            const extractedStr = "test";
            const input = {
                header: stringToBytes(headerStr, maxSliceLen),
                gmailHash: getPaddedHashChunks(extractedStr, maxOutputLen)
            };
            const witness = await circuit.calculateWitness(input, true);
            assert.ok(witness);
        });
    });

    describe("When maxSliceLen is 64", () => {
        let circuit;
        const maxSliceLen = 64;
        const maxOutputLen = 64;

        before(async () => {
            // Compile the specific test circuit for maxSliceLen=64
            const circuitPath = path.resolve(__dirname, "./circuits/test_64.circom");
            circuit = await build(circuitPath); // No options object needed anymore
            await circuit.loadSymbols();
        });

        it("✅ should succeed for a valid 64-byte header", async () => {
            const headerStr = "from:<a.longer.email.address@example.com> is the sender.reach 64";
            const extractedStr = "a.longer.email.address@example.com";
            const input = {
                header: stringToBytes(headerStr, maxSliceLen),
                gmailHash: getPaddedHashChunks(extractedStr, maxOutputLen)
            };
            const witness = await circuit.calculateWitness(input, true);
            assert.ok(witness);
        });
    });


    // Additional test using input from gmail-hash-input.json and dynamic circuit generation


    const inputJsonPath = path.resolve(__dirname, "../../input-files/gmail-hash-input.json");
    const circuitTemplatePath = path.resolve(__dirname, "./circuits/test_online.circom");
    const circuitIncludePath = "../../circuits/gmail-hash-verify.circom/";

    let inputData;
    let headerLen;

    before(async () => {
        // Read and parse the JSON input file
        const raw = fs.readFileSync(inputJsonPath, "utf8");
        inputData = JSON.parse(raw);

        // Extract header length from the JSON input
        if (!inputData.header) {
            throw new Error("Input JSON must contain a 'header' field.");
        }
        headerLen = inputData.header.length;

        // Generate the circuit file dynamically
        const circuitText = `pragma circom 2.0.0;
include "${circuitIncludePath}";
component main {public [gmailHash]} = ExtractAndVerifyHash(${headerLen}, 32);
`;
        fs.writeFileSync(circuitTemplatePath, circuitText, "utf8");
    });

    it("✅ should succeed for the header and gmailHash from JSON input", async () => {
        // Prepare input for the circuit
        const headerBytes = inputData.header;
        let gmailHash;
        if (inputData.gmailHash) {
            // If gmailHash is already provided in JSON, use it
            gmailHash = inputData.gmailHash;
        } else if (inputData.extracted) {
            // If extracted string is provided, hash it
            gmailHash = getPaddedHashChunks(inputData.extracted, 32);
        } else {
            throw new Error("Input JSON must contain either 'gmailHash' or 'extracted' field.");
        }

        // Compile and test the circuit
        const circuit = await build(circuitTemplatePath);
        await circuit.loadSymbols();

        const input = {
            header: headerBytes,
            gmailHash: gmailHash
        };

        const witness = await circuit.calculateWitness(input, true);
        
        assert.ok(witness);
    });
});