import hashlib
import math

def calculate_hash_for_constructor(value):
    value_encode = value.encode('utf-8')
    return hashlib.sha256(value_encode).hexdigest()


class NodeOfMerkleTree:
    def __init__(self, value, index):
        # self.value = value
        # self.hashed_value = calculate_hash_for_constructor(value)
        self.value = value
        self.left_node = None
        self.right_node = None
        self.index = index


# merkel tree is an almost complete tree
# we will use dynamic list for the tree
def invalid_input():
    print("invalid input\n") # should print just \n

class MerkelTree:
    def __init__(self):
        self.nodesList = []

    def insert_node(self, value): # input 1
        if value is None:
            return
        else:
            self.nodesList.append(NodeOfMerkleTree(value, len(self.nodesList)))
            # if its just root it doesnt have parent
            if len(self.nodesList) == 1:
                return
            else:
                # update parent that this node is his child
                last_index = len(self.nodesList) - 1
                parent_index = int((last_index - 1) / 2)
                # is left child
                if len(self.nodesList) % 2 == 0:
                    self.nodesList[parent_index].left_node = self.nodesList[last_index]
                # is right child
                else:
                    self.nodesList[parent_index].right_node = self.nodesList[last_index]

    def update_tree_after_insert(self): # helper input 1
        max_len = int(len(self.nodesList) / 2)
        if len(self.nodesList) % 2 == 1: # odd case -> should update
            for i in range(0, max_len):
                # parent = self.nodesList[int((i - 1) / 2)]
                # left_child = self.nodesList[(2 * i) + 1]
                # right_child = self.nodesList[(2 * i) + 2]
                self.nodesList[i].value = str(self.nodesList[(2 * i) + 1].value) + "+" + str(self.nodesList[(2 * i) + 2].value)

        # print(parent.value)

    def get_root(self): # input 2
        return self.nodesList[0].value   #should return in hex

    def proof_of_inclusion(self, leaf_number): # input 3
        proof = str(self.nodesList[0].value) # proof start with root

        if len(self.nodesList) is 1:
            return proof

        # finding the leaf number zero (the most left leaf)
        i = 0
        if self.nodesList[i].left_node != None:
            i += 1
        while (self.nodesList[i].left_node != None):
            i *= 2
        leaf_zero = self.nodesList[i - 1]

        # if (leaf_number >  amount_of_leafs): # bad input, should check cases
        #     invalid_input()

        #print(leaf_zero.value) # just for check
        # the specific given leaf
        leaf = self.nodesList[leaf_zero.index + leaf_number]
        leaf_ptr = leaf
        #print(leaf.value) # just for check
        # collecting the nodes necessary to proof
        # define leaf_ptr as leaf parent
        if leaf_ptr.index % 2 == 1:  # leaf is left child
            parent_index = math.floor(leaf_ptr.index / 2)
            if parent_index < 0:
                parent_index = 0
            leaf_parent = self.nodesList[parent_index]
            proof += " "
            proof += str(leaf_parent.right_node.value)
        else:  # right child
            parent_index = math.floor(leaf_ptr.index / 2) - 1
            if parent_index < 0:
                parent_index = 0
            leaf_parent = self.nodesList[parent_index]
            proof += " "
            proof += str(leaf_parent.left_node.value)

        leaf_ptr = leaf_parent

        while (leaf_ptr != self.nodesList[0]):
            if leaf_ptr.index % 2 == 1:  # leaf is left child
                leaf_parent = self.nodesList[int(leaf_ptr.index / 2)]
                proof += " "
                proof += str(leaf_parent.right_node.value)
            else: # right child
                leaf_parent = self.nodesList[int(leaf_ptr.index / 2) - 1]
                proof += " "
                proof += str(leaf_parent.left_node.value)
            leaf_ptr = leaf_parent

        print(proof) # just for check
        return proof

    def check_proof_of_inclusion(self, string_value, proof): # input 4
        # finding the leaf number zero (the most left leaf)
        i = 0
        if self.nodesList[i].left_node != None:
            i += 1
        while (self.nodesList[i].left_node != None):
            i *= 2
        leaf_zero = self.nodesList[i - 1]
        if leaf_zero.value is string_value:
            leaf = leaf_zero
        else:
            for j in range(leaf_zero.index + 1, len(self.nodesList)):
                if self.nodesList[j].value is string_value:
                    leaf = self.nodesList[j]


        correct_proof = self.proof_of_inclusion(leaf.index - leaf_zero.index)
        if correct_proof == proof:
            print("True") # just for check
            return True
        print("False")  # just for check
        return False




    def print_heap(self): # just for check
        # print(self.nodesList[0].value)
        # print(self.nodesList[0].left_node.value)
        # print(self.nodesList[0].right_node.value)
        # print(self.nodesList[1].left_node.value)
        # print(self.nodesList[1].right_node.value)
        # print(self.nodesList[2].left_node.value)
        # print(self.nodesList[2].right_node.value)
        #

        for i in range(0, len(self.nodesList)):
            print(str(self.nodesList[i].value) + " index: " + str(self.nodesList[i].index))


# main

def main():
    mt = MerkelTree()
    for i in range(1, 14):
        mt.insert_node(i)
    #mt.update_tree_after_insert()
    #mt.print_heap()
    #mt.proof_of_inclusion(0) # check input 3
    #check input 4 ::
    check_input4_string = "1 13 7 2"
    check_input4_leaf_value = 12
    mt.check_proof_of_inclusion(check_input4_leaf_value, check_input4_string)

if __name__ == "__main__":
    main()
