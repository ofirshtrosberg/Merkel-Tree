import hashlib
import math
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# need to change to 256 now its 4 just for check
last_level_sparse_tree = 4


# we will use it in the end just for now use string values

# hash funcs
def calculate_hash(value):
    value_encode = value.encode('utf-8')
    return hashlib.sha256(value_encode).hexdigest()


class Node:
    def __init__(self, value):
        # self.hashed_value = calculate_hash(value)
        self.value = str(value)  # remove str in the end just for check
        self.left = None
        self.right = None
        self.parent = None
        self.depth = 0


class NodeSparseTree:
    def __init__(self, value, depth):
        # self.hashed_value = calculate_hash(value)
        self.value = value  # remove str in the end just for check
        self.left = None
        self.right = None
        self.parent = None
        self.depth = depth
        # self.index_in_the_tree = index_in_the_tree


# need to fix it

# def invalid_input():
#     print("invalid input\n") # should print just \n

class MerkelTree:
    def __init__(self):
        self.leavesList = []
        self.nodesList = []

    def insert_leaf(self, value):  # input 1
        self.leavesList.append(Node(value))

    def update_tree(self, nodes):  # helper function
        # in this function we update the nodesList of all the tree
        unique_nodes = []
        for i in range(len(nodes) - 1, -1, -1):
            if nodes[i] not in unique_nodes:
                unique_nodes.append(nodes[i])

        for i in range(1, len(unique_nodes), 2):
            if (i + 1) < len(unique_nodes):
                temp = unique_nodes[i]
                unique_nodes[i] = unique_nodes[i + 1]
                unique_nodes[i + 1] = temp

        for i in range(0, (len(unique_nodes))):
            if unique_nodes[i] not in self.nodesList:
                self.nodesList.insert(i, unique_nodes[i])
            if unique_nodes[i].left not in self.nodesList:
                self.nodesList.insert((2 * i + 1), unique_nodes[i].left)
            if unique_nodes[i].right not in self.nodesList:
                self.nodesList.insert((2 * i + 2), unique_nodes[i].right)

        self.nodesList = [i for i in self.nodesList if i]  # remove None values if exists
        # at the end of the function, self.nodesList hold the lists of nodes
        # in the tree not include the leaves (the leaves in leavesList)

        # for i in range(0, len(self.nodesList)):
        #     print(self.nodesList[i].value)

    def generate_mt(self):
        mt_nodes = self.leavesList
        nodes = []
        while len(mt_nodes) != 1:  # recursion until get the root
            temp_arr = []
            for i in range(0, len(mt_nodes), 2):
                left_node = mt_nodes[i]
                if (i + 1) < len(mt_nodes):
                    right_node = mt_nodes[i + 1]
                else:
                    nodes.append(mt_nodes[i])
                    temp_arr.append(mt_nodes[i])
                    break
                parent_value = left_node.value + right_node.value
                parent = Node(parent_value)
                parent.left = left_node
                parent.right = right_node
                nodes.append(parent)
                temp_arr.append(parent)
            mt_nodes = temp_arr

        self.update_tree(nodes)
        return mt_nodes[0]

    def get_root(self):  # input 2
        for leaf in self.leavesList:  # should rebuild the tree
            if leaf not in self.nodesList:
                self.generate_mt()

        return self.nodesList[0]  # should return in hex

    def proof_of_inclusion(self, leaf_number):  # input 3
        for leaf in self.leavesList:  # should rebuild the tree
            if leaf not in self.nodesList:
                self.generate_mt()

        proof = []
        proof.append(self.nodesList[0].value)  # proof start with root
        # if the list contain just one node (the root) -> return the proof.
        if len(self.nodesList) == 1:
            return proof[0]
        # finding the specific given leaf as input
        leaf = self.leavesList[leaf_number]
        leaf_ptr = leaf  # define ptr that will "jump" on the tree
        leaf_ptr_index = self.nodesList.index(leaf_ptr)
        if leaf_ptr_index % 2 == 1:  # leaf is left child
            parent_index = math.floor(leaf_ptr_index / 2)
            if parent_index < 0:  # needed for edge cases
                parent_index = 0
            leaf_parent = self.nodesList[parent_index]
            if leaf_parent.right.value not in proof:
                proof.append(leaf_parent.right.value)  # adding to the proof
        else:  # right child
            parent_index = math.floor(leaf_ptr_index / 2) - 1
            if parent_index < 0:  # needed for edge cases
                parent_index = 0
            leaf_parent = self.nodesList[parent_index]
            if leaf_parent.left.value not in proof:
                proof.append(leaf_parent.left.value)  # adding to the proof

        leaf_ptr = leaf_parent  # jump to the parent
        leaf_ptr_index = self.nodesList.index(leaf_ptr)

        while (leaf_ptr != self.nodesList[0]):  # keep calculating general case's
            if leaf_ptr_index % 2 == 1:  # leaf is left child
                leaf_parent = self.nodesList[int(leaf_ptr_index / 2)]
                if leaf_parent.right.value not in proof:
                    proof.append(leaf_parent.right.value)  # adding to the proof
            else:  # right child
                leaf_parent = self.nodesList[int(leaf_ptr_index / 2) - 1]
                if leaf_parent.left.value not in proof:
                    proof.append(leaf_parent.left.value)  # adding to the proof

            leaf_ptr_index = self.nodesList.index(leaf_ptr)
            leaf_ptr = leaf_parent

        str_proof = " "
        str_proof += str_proof.join(proof)
        str_proof = str_proof[1:]
        # print(str_proof)
        return str_proof

    def check_proof_of_inclusion(self, string_value, proof):  # input 4
        for i in range(0, len(self.leavesList)):
            if self.leavesList[i].value == string_value:
                leaf = self.leavesList[i]
                break
        # take the actually correct proof using the function proof_of_inclusion
        correct_proof = self.proof_of_inclusion(self.leavesList.index(leaf))
        print(correct_proof)
        if correct_proof == proof:  # compare the proof's and return result
            print("True")  # just for check
            return True
        print("False")  # just for check
        return False

    # here its the code hemi gave us from make rsa and signitaure i couldn't run it but its looks like this
    # check it, its just copy paste from hemi he says we need to do that

    # def generate_keys(self): # input 5
    #     private_key = rsa.generate_private_key(public_exponent=65537,
    #                                            key_size=2048,
    #                                            backend=default_backend())
    #     pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
    #                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
    #                                     encryption_algorithm=alg
    #                                     )
    #     alg = serialization.BestAvailableEncryption(password)
    #     secret_key = pem
    #
    #     public_key = private_key.public_key()
    #     pem = public_key.public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo
    #     )
    #
    #     public_key = pem
    #     return_value = str(private_key) + " " + str(public_key)
    #     return return_value
    #
    # def generate_signature(self, private_key):
    #     signature = private_key.sign(
    #         self.nodesList[0].value
    #         padding.PES(
    #             mgf=padding.MGF1(hashes.SHA256()),
    #             salt_length=padding.PSS.MAX_LENGTH
    #         ),
    #         hashes.SHA256()
    #     )
    #
    #     # maybe need to add padding like Hemi did

    def print_mt(self):  # just for check
        for i in range(0, len(self.leafsList)):
            print(self.leafsList[i].value)


def calculate_zero_hash():
    zero_hash_by_depth = []
    for i in range(0, last_level_sparse_tree + 1):
        zero_hash_by_depth.append(None)
    value = "0"
    zero_hash_by_depth[len(zero_hash_by_depth) - 1] = value
    for i in range(last_level_sparse_tree - 1, -1, -1):
        # value = calculate_hash(value + value)
        # zero_hash_by_depth[i] = value
        value += value  # just for check
        zero_hash_by_depth[i] = value  # for check
    return zero_hash_by_depth


class SparseMerkleTree:
    def __init__(self, zero_hash_by_depth):
        # -1 means not updated yet
        self.root = NodeSparseTree("-1", 0)
        self.zero_hash_by_depth = zero_hash_by_depth

    def insert_leaf(self, digest):
        current_node = self.root
        flag_error = 0
        for i in range(0, len(digest)):
            if digest[i] != "0" and digest[i] != "1":
                flag_error = 1
        ########
        if len(digest) != last_level_sparse_tree:
            flag_error = 1
        if flag_error == 1:
            print()
            return
        for i in range(0, len(digest)):
            # left child
            if digest[i] == "0":
                if current_node.left is None:
                    # -1 means not updated yet
                    current_node.left = NodeSparseTree("-1", current_node.depth + 1)
                else:
                    current_node.left.value = "-1"
                current_node.left.parent = current_node
                current_node = current_node.left
            # right child
            # digest == 1
            else:
                if current_node.right is None:
                    # -1 means not updated yet
                    current_node.right = NodeSparseTree("-1", current_node.depth + 1)
                else:
                    current_node.right.value = "-1"
                current_node.right.parent = current_node
                current_node = current_node.right
            if current_node.depth == last_level_sparse_tree:
                current_node.value = "1"
        self.update_path(digest)

    # update from leaves to root values

    def update_path(self, digest):
        current_node = self.root
        for i in range(0, len(digest)):
            if digest[i] == "0":
                current_node = current_node.left
            else:
                current_node = current_node.right
        for i in range(0, len(digest)):
            current_node = current_node.parent
            if current_node.left is None:
                left_child_value = self.zero_hash_by_depth[current_node.depth + 1]
            else:
                left_child_value = current_node.left.value
            if current_node.right is None:
                right_child_value = self.zero_hash_by_depth[current_node.depth + 1]
            else:
                right_child_value = current_node.right.value
            current_node.value = left_child_value + right_child_value

    # still need to improve the case in which the current digest is not in the tree
    # need to add the leaf to b?
    def proof_of_inclusion(self, digest):
        b = []
        current_node = self.root
        # find the leaf
        for i in range(0, len(digest)):
            if digest[i] != "0" and digest[i] != "1":
                print()
                return
            elif digest[i] == "0":
                if current_node.left is None:
                    b.append(self.zero_hash_by_depth[current_node.depth+1])
                    return b
                else:
                    current_node = current_node.left
            else:
                if current_node.right is None:
                    b.append(self.zero_hash_by_depth[current_node.depth + 1])
                    return b
                else:
                    current_node = current_node.right
        for i in range(len(digest)-1, -1, -1):
            current_node = current_node.parent
            if digest[i] == "0":
                if current_node.right is None:
                    value = self.zero_hash_by_depth[current_node.depth+1]
                else:
                    value = current_node.right.value
                b.append(value)
            if digest[i] == "1":
                if current_node.left is None:
                    value = self.zero_hash_by_depth[current_node.depth+1]
                else:
                    value = current_node.left.value
                b.append(value)
        return b
    # def check_proof_of_inclusion(self, digest, flag, proof):

def main():
    # mt = MerkelTree()
    # for i in range(0, 6):
    #     mt.insert_leaf(i)
    # mt.proof_of_inclusion(0)
    # # check input 4 ::
    # check_input4_string = "012345 5 0123"
    # check_input4_leaf_value = "4"
    # mt.check_proof_of_inclusion(check_input4_leaf_value, check_input4_string)

    # keys = mt.generate_keys()
    # print(keys)

    # avoid conflict use the main from here below , above will be my checks

    # here
    # mt.generate_mt()

    # check still without hash
    zero_hash = calculate_zero_hash()
    print("arr", zero_hash)
    merkle_sparse = SparseMerkleTree(zero_hash)
    merkle_sparse.insert_leaf("0000")
    print(merkle_sparse.root.value)
    print(merkle_sparse.root.left.value)
    print(merkle_sparse.root.left.left.value)
    print(merkle_sparse.root.left.left.left.value)
    print(merkle_sparse.root.left.left.left.left.value)
    print("root")
    print(merkle_sparse.proof_of_inclusion("0000"))

    # print(merkle_sparse.nodesList[1].right)

    # commands menu down here

    # while True:
    #     input_line = input()
    #     argument = ""
    #     if input_line[0] == "1" and input_line[1] == " ":  # command 1
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     elif input_line[0] == "2" and input_line[1] == " ":  # command 2
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     elif input_line[0] == "3" and input_line[1] == " ":  # command 3
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     elif input_line[0] == "4" and input_line[1] == " ":  # command 4
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     elif input_line[0] == "5" and input_line[1] == " ":  # command 5
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     elif input_line[0] == "6" and input_line[1] == " ":  # command 6
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     elif input_line[0] == "7" and input_line[1] == " ":  # command 7
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     elif input_line[0] == "8" and input_line[1] == " ":  # command 8
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         mt.sparse(argument)
    #     elif input_line[0] == "9" and input_line[1] == " ":  # command 9
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     elif input_line[0] == "10" and input_line[1] == " ":  # command 10
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     elif input_line[0] == "11" and input_line[1] == " ":  # command 11
    #         for i in range(2, len(input_line)):
    #             argument = argument + input_line[i]
    #         # need to add call to the relevant function
    #     else:  # invalid input
    #         print("\n")


if __name__ == "__main__":
    main()
