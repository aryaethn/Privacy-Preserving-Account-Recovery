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
});