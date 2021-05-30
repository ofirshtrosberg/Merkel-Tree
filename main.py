class Node:
    #value, left, right = None
    def __init__(self, value):
        self.left = None
        self.right = None
        self.value = value

class MerkleTree:
    def __init__(self):
            self.root = None

    def insert_node(self, node):
        # what if self null
        if node.value < self.value: # left side
            if self.left is not None:
                self.insert_node(self.left, node)
            else:
                self.left = node

        if node.value > self.value: # right side
            if self.right is not None:
                self.insert_node(self.right, node.value)
            else:
                self.right = node

    def printTree(self, node):
        if node is not None:
            self.printTree(node.l)
            print(str(node.v) + ' ')
            self.printTree(node.r)

def main():
    node1 = Node(1)
    node2 = Node(2)
    node3 = Node(3)
    node4 = Node(4)

    mt = MerkleTree()
    mt.insert_node(node1)
    mt.printTree(node1)
    # mt.insert_nod

