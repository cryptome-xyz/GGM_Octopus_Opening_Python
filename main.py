import hashlib
import os
from random import randint
from typing import List, Tuple, Dict, Any


def find_abandon_index(M: int, N: int) -> list[int]:
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
    pass


def prg_split_shake_16(key: bytes) -> Tuple[bytes, bytes]:
    stream = hashlib.shake_256(key).digest(32)
    return stream[:16], stream[16:]


def bcavc_generate(seed: bytes, M: int, N: int) -> List[List[bytes]]:
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


def bcavc_open(layers: List[List[bytes]], A: List[int]) -> list[dict[str, Any]]:
    H = len(layers) - 1
    target = sorted(set(A))
    proof: List[Dict[str, Any]] = []
    for L in range(H, 0, -1):
        if not target:
            # Nothing more to prove; still record an empty step for completeness
            proof.append({"layer": L, "indices": [], "values": []})
            target = []  # stay empty going up
            continue
        pairs = []
        for i in target:
            sib = i ^ 1
            pairs.append((min(i, sib), max(i, sib))) # label of the challenge and its sibling
        B_pruned = sorted(set(pairs))
        flat = {x for p in B_pruned for x in p}
        need = sorted(flat.difference(target))
        layer_size = len(layers[L])
        need = [i for i in need if i < layer_size]
        proof.append({
            "layer": L,
            "indices": need,
            "values": [layers[L][k] for k in need],
        })

        # Parents for next iteration (even index from each pair, halved)
        parents = sorted({p[0] // 2 for p in B_pruned})
        target = parents

    return proof

if __name__ == '__main__':
    # Set the parameters
    M = 27
    N = 4096
    trial_num = 100
    sum_nodes = 0
    for i in range(trial_num):
        # Expand the sd to obtain a GGM tree
        sd = os.urandom(16)

        tree = bcavc_generate(sd, M, N)
        # Simulate random opening for BCAVC
        challenge_ind: List[int] = []
        for j in range(M):
            challenge_ind.append(j + randint(0, N - 1) * M)

        # Open the tree
        proof = bcavc_open(tree, challenge_ind)

        # Compute the number of nodes in the opening
        total_nodes = sum(len(step["indices"]) for step in proof)

        sum_nodes += total_nodes
    sum_nodes /= trial_num

    print("Average Opening Size for",trial_num,"trials is",sum_nodes)
