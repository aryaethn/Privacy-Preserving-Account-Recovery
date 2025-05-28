mapping(uint256 => bytes32) public rootOf;
function pushRoot(uint256 blk, bytes32 root) external {
    require(block.number <= blk + 256, "relay: too late");
    require(blockhash(blk) != 0,        "relay: bad blk");
    require(rootOf[blk] == 0,           "relay: set");
    rootOf[blk] = root;
}
