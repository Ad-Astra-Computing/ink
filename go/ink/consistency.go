package ink

// emptyTreeRoot is the RFC 6962 Merkle Tree Hash of the empty tree, SHA-256 of
// the empty string. A fresh witness with no submissions reports this root, and
// the empty tree is a prefix of every tree, so a consistency proof from size 0
// carries no nodes and pins this exact value.
const emptyTreeRoot = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// VerifyConsistencyProof verifies an RFC 6962 §2.1.2 consistency proof: that the
// Merkle tree of first leaves with root firstRoot is a prefix of the tree of
// second leaves with root secondRoot. A valid proof attests the log only ever
// appended; it is what detects a witness that forks its history (a split view)
// rather than merely growing, which the second >= first size comparison alone
// cannot. proof is the ordered list of node hashes, each 64 lowercase hex
// characters. Internal nodes are hashed SHA-256(0x01 || left || right), the same
// construction VerifyInclusionProof uses, so the two agree on tree shape.
//
// Returns false (never panics) for malformed input, a size past the JS
// safe-integer range, first > second, or any proof that does not reconstruct
// both roots with every element consumed. This is a low-level primitive: it
// attests only prefix consistency between two roots, not the witness signature
// that committed to either checkpoint. That check belongs to the caller.
func VerifyConsistencyProof(first int, firstRoot string, second int, secondRoot string, proof []string) bool {
	if first < 0 || second < 0 {
		return false
	}
	if first > maxSafeInteger || second > maxSafeInteger {
		return false
	}
	if !isMerkleHashHex(firstRoot) || !isMerkleHashHex(secondRoot) {
		return false
	}
	if len(proof) > maxProofLength {
		return false
	}
	for _, p := range proof {
		if !isMerkleHashHex(p) {
			return false
		}
	}
	if first > second {
		return false
	}
	// Same size: the roots must match and there is nothing to prove.
	if first == second {
		return len(proof) == 0 && firstRoot == secondRoot
	}
	// The empty tree is a prefix of every tree; its root is fixed and the proof
	// carries no nodes.
	if first == 0 {
		return len(proof) == 0 && firstRoot == emptyTreeRoot
	}

	// 0 < first < second. Walk the path from leaf first-1 up to the roots,
	// shifting node/last together. node indexes the first tree's rightmost leaf,
	// last the second tree's.
	node := first - 1
	last := second - 1
	for node%2 == 1 {
		node /= 2
		last /= 2
	}

	i := 0
	take := func() (string, bool) {
		if i < len(proof) {
			v := proof[i]
			i++
			return v, true
		}
		return "", false
	}

	// When first is an exact power of two, node has shifted to 0 and the old
	// subtree hash is firstRoot itself; otherwise it is the first proof node.
	var oldHash string
	if node > 0 {
		h, ok := take()
		if !ok {
			return false
		}
		oldHash = h
	} else {
		oldHash = firstRoot
	}
	newHash := oldHash

	for node > 0 {
		if node%2 == 1 {
			// Right child: the sibling on the left is shared by both trees.
			h, ok := take()
			if !ok {
				return false
			}
			no, err := merkleNodeHash(h, oldHash)
			if err != nil {
				return false
			}
			nn, err := merkleNodeHash(h, newHash)
			if err != nil {
				return false
			}
			oldHash, newHash = no, nn
		} else if node < last {
			// Left child with a right sibling that exists only in the second tree.
			h, ok := take()
			if !ok {
				return false
			}
			nn, err := merkleNodeHash(newHash, h)
			if err != nil {
				return false
			}
			newHash = nn
		}
		node /= 2
		last /= 2
	}

	// Remaining nodes extend only the second tree to its root.
	for last > 0 {
		h, ok := take()
		if !ok {
			return false
		}
		nn, err := merkleNodeHash(newHash, h)
		if err != nil {
			return false
		}
		newHash = nn
		last /= 2
	}

	// Every proof element must be consumed, and both reconstructions must match.
	if i != len(proof) {
		return false
	}
	return oldHash == firstRoot && newHash == secondRoot
}
