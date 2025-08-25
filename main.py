import hashlib
import os
from random import randint
from typing import List, Tuple, Dict, Any


def find_abandon_index(M: int, N: int) -> list[int]:
    """
    For those trees with leaf nodes not a power of two, we use this function to find the layers at which the last node 
    can be deleted from the GGM tree.
    """
    Lm = (M - 1).bit_length()
    Ln = (N - 1).bit_length()
    H = Lm + Ln

    diff = (1 << H) - M * N
    out = []
    while diff:
        i = diff.bit_length() - 1  # index of current MSB
        out.append(H - i)
        diff ^= (1 << i)  # clear that bit
    return out


def prg_split_shake_16(key: bytes) -> Tuple[bytes, bytes]:
    stream = hashlib.shake_256(key).digest(32)
    return stream[:16], stream[16:]



# Expand the seeds at layer i to two children nodes at the layer i+1
def ggm_generate(seed: bytes, M: int, N: int) -> List[List[bytes]]:
    abandon_layers = set(find_abandon_index(M, N))
    H = (M - 1).bit_length() + (N - 1).bit_length()
    layers: List[List[bytes]] = [[seed]]
    for d in range(H):
        current = layers[d]  # a list with current nodes
        next_level: List[bytes] = []
        for node in current:
            L, R = prg_split_shake_16(node)
            next_level.append(L)
            next_level.append(R)
        if (d + 1) in abandon_layers:
            layers.append(next_level[:-1])
        else:
            layers.append(next_level)
    return layers


def ggm_open(layers: List[List[bytes]], A: List[int]) -> list[dict[str, Any]]:
    """
    This function generates octopus proof for multiple openings in the GGM tree. 

    Basically, the octopus algorithm is by treating the authentication paths of opening all the challenge nodes as a subtree
    of the whole GGM tree. The octopus path only includes the "leaf nodes" in the subtree, that is, the nodes in the subtree
    whose children nodes are not in the subtree.  
    """
    H = len(layers) - 1
    target = sorted(set(A))
    opening: List[Dict[str, Any]] = []
    for L in range(H, 0, -1):
        if not target:
            # Nothing more to prove; still record an empty step for completeness
            opening.append({"layer": L, "indices": [], "values": []})
            target = []  # stay empty going up
            continue
        pairs = []
        for i in target:
            sib = i ^ 1
            pairs.append((min(i, sib), max(i, sib)))  # label of the challenge and its sibling
        B_pruned = sorted(set(pairs))
        flat = {x for p in B_pruned for x in p}
        need = sorted(flat.difference(target))
        layer_size = len(layers[L])
        need = [i for i in need if i < layer_size]
        opening.append({
            "layer": L,
            "indices": need,
            "values": [layers[L][k] for k in need],
        })

        # Parents for next iteration (even index from each pair, halved)
        parents = sorted({p[0] // 2 for p in B_pruned})
        target = parents

    return opening

# Compute actual layer size (respect the abandoned nodes)
def _layer_sizes_from_MN(M: int, N: int) -> list[int]:
    H = (M - 1).bit_length() + (N - 1).bit_length()
    abandon = set(find_abandon_index(M, N))  # 1-based layers
    sizes = [1]
    for d in range(H):
        s = sizes[-1]
        if (d + 1) in abandon and s > 0:
            sizes.append(2 * s - 1)                  # drop last node BEFORE expanding to layer d+1
        else:
            sizes.append(2 * s)
    return sizes

# expand a subtree to leaves
def _expand_to_leaves(node: bytes,start_layer: int, node_index: int, H: int, sizes: list[int],) -> tuple[int, list[bytes]]:
    level_nodes = [node]
    lo = hi = node_index
    for d in range(start_layer, H):  # produce layer d+1
        nxt = []
        for x in level_nodes:
            Lc, Rc = prg_split_shake_16(x)
            nxt.append(Lc)
            nxt.append(Rc)

        # interval if no pruning at next layer
        lo2, hi2 = 2 * lo, 2 * hi + 1

        # if layer d+1 was abandoned, drop the very last node of that layer
        last_global = sizes[d + 1]
        if lo2 <= last_global <= hi2:
            nxt = nxt[:-1]
            hi2 -= 1

        level_nodes = nxt
        lo, hi = lo2, hi2

    return lo, level_nodes


# Using the octopus opening to recover all the leaf nodes except for those in the challenge set
def ggm_verify(proof: List[Dict[str, Any]], M: int, N: int) -> List[bytes]:
    sizes = _layer_sizes_from_MN(M, N)
    H = len(sizes) - 1
    total = sizes[-1]
    recovered: List[bytes] = [b''] * total

    for level in proof:
        L = level["layer"]
        idxs = level.get("indices", [])
        vals = level.get("values", [])
        for i, node in zip(idxs, vals):
            base, leaves = _expand_to_leaves(node, L, i, H, sizes)
            for off, leaf in enumerate(leaves):
                gi = base + off
                if 0 <= gi < total:
                    recovered[gi] = leaf
                else:
                    raise IndexError(f"leaf index {gi} out of range 0..{total - 1}")
    return recovered


if __name__ == '__main__':
    # An example 
    M = 3
    N = 4
    # Expand the sd to obtain a GGM tree
    sd = os.urandom(16)
    tree = ggm_generate(sd, M, N)
    
    # simulate the BAVC opening
    challenge_ind: List[int] = []
    for j in range(M):
        challenge_ind.append(j + randint(0, N - 1) * M)

    # Compute the opening
    proof = ggm_open(tree, challenge_ind)
    # Verify the path (get the leaves except for those in the challenge set)
    recovered_leaves = ggm_verify(proof, M, N)
