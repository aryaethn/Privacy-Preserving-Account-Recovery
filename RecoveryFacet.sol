event KeyRotated(
    address indexed account,   // recovered EOA (= address(this))
    address indexed guardian,  // tx.origin
    uint256 pkX,
    uint256 pkY
);

function rotateKey(
    uint256 newX, uint256 newY,
    bytes calldata proof, uint256[3] calldata pubIn,
    bytes32[] calldata path, uint256 idx,
    uint256 headerNum, uint8 rootSrc   // 0=direct, 1=relay
) external {
    // 0. Resolve state root
    bytes32 root = rootSrc == 0
        ? blockhash(headerNum)
        : StateRootRelay(RELAY).rootOf(headerNum);
    require(root != 0, "PPAR: unknown root");

    // 1. Merkle inclusion
    uint256 depth = path.length;
    require(depth > 0 && depth <= 256,    "PPAR: bad depth");
    require(idx < (1 << depth),           "PPAR: idx big");
    require(_verifyPath(root, path, idx,
            bytes32(pubIn[0]), depth),    "PPAR: bad path");

    // 2. Public-input sanity
    require(newX == pubIn[1] && newY == pubIn[2],
            "PPAR: pubIn mismatch");

    // 3. SNARK verification
    require(Verifier.verifyProof(proof, pubIn),
            "PPAR: invalid ZK proof");

    // 4. On-curve check
    require(_isOnCurve(newX, newY),       "PPAR: bad key");

    // 5. Rotate key (executing in EOA frame)
    assembly {
        sstore(PK_X_SLOT, newX)
        sstore(PK_Y_SLOT, newY)
    }
    emit KeyRotated(address(this), tx.origin, newX, newY);
}
