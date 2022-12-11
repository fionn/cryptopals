#!/usr/bin/env python3
"""Kelsey and Kohno's Nostradamus Attack"""
# Herding Hash Functions
# https://ia.cr/2005/281

from math import log
from random import choice
from typing import NamedTuple, Iterator
from functools import cached_property

from Crypto.Random import get_random_bytes

from m28 import merkle_pad
from m52 import all_possible_block_pairs, md, MDHash, CheapHash as Hash

BinaryNodes = NamedTuple("BinaryNodes", [("left", "Node"), ("right", "Node")])

class Node:
    """Merkle tree node with outbound edge value"""

    def __init__(self, node_left: "Node", node_right: "Node",
                 message: bytes = None) -> None:
        self.child = BinaryNodes(node_left, node_right)
        self.message: bytes = message  # This is the outbound edge.

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.hash.hexdigest()})"

    @cached_property
    def hash(self) -> MDHash:
        """Hash of Merkle subtree"""
        if not self.child.left:
            return Hash(bytes(Hash.block_size))
        # We just look at the left subtree since it is
        # symmetric by construction.
        h = self.child.left.hash.copy()
        h.update(self.child.left.message)
        return h

class Tree:
    """Collision Tree"""

    def __init__(self, leaves: list[Node]) -> None:
        self.leaves = leaves
        self.k = int(log(len(leaves), 2))
        self.root = self.brute_force_merkle_tree(leaves)

    @classmethod
    def brute_force_merkle_tree(cls, nodes: list[Node]) -> Node:
        """Create a Merkle tree from leaf nodes via recursive hash collisions"""
        # This is the diamond structure from §2.
        if len(nodes) == 1:
            return nodes.pop()

        half = len(nodes) // 2
        left = cls.brute_force_merkle_tree(nodes[:half])
        right = cls.brute_force_merkle_tree(nodes[half:])

        for m, m_prime in all_possible_block_pairs(Hash.digest_size):
            if md(m, left.hash.digest()) == md(m_prime, right.hash.digest()):
                left.message = pad(m)
                right.message = pad(m_prime)
                return Node(left, right)

        raise RuntimeError("Failed to find collision for node")

    @classmethod
    def path_to_root(cls, root: Node, target_node: Node,
                     path: list[Node] = None) -> list[Node]:
        """Returns a path from target_node to root"""
        if not root:
            return []

        path = path or []
        path.append(root)

        if root.hash.digest() == target_node.hash.digest():
            return path[::-1]

        left_route = cls.path_to_root(root.child.left, target_node, path)
        right_route = cls.path_to_root(root.child.right, target_node, path)

        path.pop()

        return left_route or right_route

    @classmethod
    def preorder_traverse(cls, node: Node,
                          traversed: list[Node] = None) -> list[Node]:
        """Traverse via the left and then right subtree"""
        traversed = traversed or []
        if node:
            traversed.append(node)

            if node.child.left:
                assert md(node.child.left.message,
                          node.child.left.hash.digest()) == node.hash.digest()
                assert md(node.child.right.message,
                          node.child.right.hash.digest()) == node.hash.digest()

            cls.preorder_traverse(node.child.left, traversed)
            cls.preorder_traverse(node.child.right, traversed)

        return traversed

    @classmethod
    def level_traverse(cls, nodes: list[Node],
                       traversed: list[Node] = None) -> list[Node]:
        """Traverse level-by-level"""
        traversed = traversed or []
        node = nodes.pop(0)

        if node:
            traversed.append(node)
            nodes.append(node.child.left)
            nodes.append(node.child.right)

            if node.child.left:
                assert md(node.child.left.message,
                          node.child.left.hash.digest()) == node.hash.digest()
                assert md(node.child.right.message,
                          node.child.right.hash.digest()) == node.hash.digest()

            cls.level_traverse(nodes, traversed)

        return traversed

    @classmethod
    def height(cls, node: Node) -> int:
        """Get the height of a node (including source nodes)"""
        if node:
            return cls.height(node.child.left) + 1
        return -1  # Zero-indexing.

def pad(message: bytes) -> bytes:
    """Opinionated Merkle padding, not idempotent"""
    return merkle_pad(message, Hash.block_size, "big", 4)

def generate_leaves(k: int) -> Iterator[Node]:
    """Generate 2ᵏ random leaf nodes"""
    for _ in range(2 ** k):
        # Generate a new "source node" for each leaf, since we store the
        # outgoing edge label in the child nodes.
        source_node = Node(None, None)
        leaf = Node(source_node, source_node)

        # Initialise with random messages.
        leaf.child.left.message = get_random_bytes(Hash.block_size)
        assert leaf.child.left is leaf.child.right
        yield leaf

def build_diamond_structure(k: int) -> Tree:
    """Construct a 2ᵏ collision tree"""
    leaves = list(generate_leaves(k))
    return Tree(leaves)

def guess_spare_blocks(prefixes: list[bytes]) -> int:
    """Guess the number of blocks in the forced prefix and linking message"""
    required_spare_blocks = set()

    for prefix in prefixes:
        required_spare_blocks.add(len(pad(prefix)) // Hash.block_size + 1)

    if len(required_spare_blocks) == 1:
        return required_spare_blocks.pop()

    raise RuntimeError("Cannot reliably guess required spare blocks")

def chosen_target(tree: Tree, spare_blocks: int) -> MDHash:
    """Hash the expected padding block in"""
    root_hash = tree.root.hash.copy()

    length = root_hash.block_size * (tree.k + spare_blocks)
    padding = pad(bytes(length))[length:]
    assert len(padding) % root_hash.block_size == 0

    root_hash.update(padding)
    return root_hash

def find_linking_message(forced_prefix: bytes, tree: Tree) -> tuple[bytes, Node]:
    """Find a block that hashes to one of the leaf nodes"""
    assert len(forced_prefix) % tree.root.hash.block_size == 0
    leaf_hashes = set(leaf.hash.digest() for leaf in tree.leaves)

    for m_int in range(2 ** (8 * tree.root.hash.digest_size)):
        m = pad(m_int.to_bytes(tree.root.hash.digest_size, "big"))
        h = md(forced_prefix + m, tree.root.hash.register)
        if h in leaf_hashes:
            leaf = [leaf for leaf in tree.leaves
                    if leaf.hash.digest() == h].pop()
            return m, leaf

    raise RuntimeError("Failed to find collision for linking message")

def main() -> None:
    """Entry point"""
    with open("data/54.txt", "rb") as f:
        predictions = [l.strip() for l in f.readlines()]

    k = 3

    tree = build_diamond_structure(k)
    print("Root hash:", tree.root.hash.hexdigest())

    spare_blocks = guess_spare_blocks(predictions)
    commitment = chosen_target(tree, spare_blocks)
    print("Precommitment hash:", commitment.hexdigest())

    forced_prefix = choice(predictions)
    print("Forced prefix:", forced_prefix.decode())
    forced_prefix = pad(forced_prefix)

    required_spare_blocks = len(forced_prefix) // Hash.block_size + 1
    if spare_blocks != required_spare_blocks:
        raise RuntimeError(f"Guessed {spare_blocks} spare blocks, "
                           f"but needed {required_spare_blocks}")

    link_message, leaf = find_linking_message(forced_prefix, tree)
    print("Linking message:", link_message.hex())

    message = forced_prefix + link_message
    assert leaf.hash.digest() == md(message, leaf.hash.register)

    path = tree.path_to_root(tree.root, leaf)
    print("Path to root:", " → ".join([node.hash.hexdigest() for node in path]))

    # Skip the root node since it doesn't have a message.
    for i, node in enumerate(path[:-1]):
        message += node.message
        assert md(message, node.hash.register) == path[i + 1].hash.digest()

    padded_message = pad(message)

    assert md(message, tree.root.hash.register) == tree.root.hash.digest()
    assert md(padded_message, tree.root.hash.register) == commitment.digest()

    print("Prediction:", padded_message.hex())

if __name__ == "__main__":
    main()
