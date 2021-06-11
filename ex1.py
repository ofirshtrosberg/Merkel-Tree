# Ofir Shtrosberg, 207828641, Itamar Laredo, 311547087
import hashlib
import math
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64

def calculate_hash_for_constructor(value):
    value_encode = value.encode('utf-8')
    return hashlib.sha256(value_encode).hexdigest()

class Node:
    def __init__(self, value):
        self.value = calculate_hash_for_constructor(value)
        self.left = None
        self.right = None

class NodeSparseTree:
    def __init__(self, value, depth):
        # self.hashed_value = calculate_hash(value)
        self.value = value  # remove str in the end just for check
        self.left = None
        self.right = None
        self.parent = None
        self.depth = depth
        # self.index_in_the_tree = index_in_the_tree

class MerkelTree:
    def __init__(self):
        self.leavesList = []
        self.nodesList = []

    def insert_leaf(self, value):  # input 1
        self.leavesList.append(Node(value))
        self.generate_mt()

    def generate_mt(self):
        nodes = []  # store all the nodes in the mt except leaves
        mt_nodes = self.leavesList
        if len(mt_nodes) == 1:
            nodes.append(mt_nodes[0])
        else:
            while True:
                if (len(mt_nodes) == 1): # while until get the root
                    break
                level_nodes = []  # store the nodes of each level
                for i in range(0, len(mt_nodes), 2):
                    left_node = mt_nodes[i]
                    if (i + 1) < len(mt_nodes):
                        right_node = mt_nodes[i + 1]
                    else:
                        nodes.append(mt_nodes[i])
                        level_nodes.append(mt_nodes[i])
                        break
                    parent_value = left_node.value + right_node.value
                    parent = Node(parent_value)
                    parent.left = left_node
                    parent.right = right_node
                    nodes.append(parent)
                    level_nodes.append(parent)
                mt_nodes = level_nodes
        # update data belong to the MT
        self.nodesList.clear()
        unique_nodes = []
        for i in reversed(nodes):
            unique_nodes.append(i)
        for i in range(1, len(unique_nodes), 2): # swap the values to represent heap correct
            if (i + 1) < len(unique_nodes):
                unique_nodes[i], unique_nodes[i + 1] = unique_nodes[i + 1], unique_nodes[i]
        for i in range(0, (len(unique_nodes))): # fix the heap: nodesList
            if unique_nodes[i] not in self.nodesList:
                self.nodesList.insert(i, unique_nodes[i])
            if unique_nodes[i].left not in self.nodesList:
                self.nodesList.insert((2 * i + 1), unique_nodes[i].left)
            if unique_nodes[i].right not in self.nodesList:
                self.nodesList.insert((2 * i + 2), unique_nodes[i].right)
        self.nodesList = [i for i in self.nodesList if i]  # remove None values if exists

    def get_root(self):  # input 2
        if len(self.leavesList) == 0:
            print() # invalid input
        else:
            print(self.nodesList[0].value)
            #return self.nodesList[0]

    def proof_of_inclusion(self, leaf_idx):  # input 3
        leaf_number = int(leaf_idx)
        if len(self.nodesList) == 0:  # no nodes - edge case
            print() # invalid input
            return
        proof = []
        proof.append(self.nodesList[0].value)  # proof start with root
        # if the list contain just one node (the root) -> return the proof.
        if len(self.nodesList) == 1:
            return proof[0]
        # finding the specific given leaf
        leaf = self.leavesList[leaf_number]
        leaf_ptr = leaf  # define ptr that will "jump" on the tree
        leaf_ptr_index = self.nodesList.index(leaf_ptr) # get index in nodesList

        if leaf_ptr_index % 2 == 1:  # leaf is left child
            parent_index = math.floor(leaf_ptr_index / 2)
            if parent_index < 0:  # needed for edge cases
                parent_index = 0
            leaf_parent = self.nodesList[parent_index]
            concatenate_str = "1" + leaf_parent.right.value
            proof.append(concatenate_str)  # adding to the proof
        else:  # right child
            parent_index = math.floor(leaf_ptr_index / 2) - 1
            if parent_index < 0:  # needed for edge cases
                parent_index = 0
            leaf_parent = self.nodesList[parent_index]
            concatenate_str = "0" + leaf_parent.left.value
            proof.append(concatenate_str)  # adding to the proof

        leaf_ptr = leaf_parent  # jump to the parent
        leaf_ptr_index = self.nodesList.index(leaf_ptr)

        while (leaf_ptr != self.nodesList[0]):  # keep calculating general case's
            if leaf_ptr_index % 2 == 1:  # leaf is left child
                leaf_parent = self.nodesList[int(leaf_ptr_index / 2)]
                concatenate_str = "1" + leaf_parent.right.value
                proof.append(concatenate_str)
            else:  # right child
                leaf_parent = self.nodesList[int(leaf_ptr_index / 2) - 1]
                concatenate_str = "0" + leaf_parent.left.value
                proof.append(concatenate_str)

            leaf_ptr_index = self.nodesList.index(leaf_ptr)
            leaf_ptr = leaf_parent
        str_proof = " "
        str_proof += str_proof.join(proof)
        str_proof = str_proof[1:]
        return str_proof

    def check_proof_of_inclusion(self, string_value, proof):  # input 4
        value_hashed = calculate_hash_for_constructor(string_value)
        index = None
        for i in range(0, len(self.leavesList)):
            if self.leavesList[i].value == value_hashed:
                index = i
                break
        if index == None:
            print() # invalid
            return

        correct_proof = self.proof_of_inclusion(index)
        if correct_proof == proof:  # compare the proof's and return result
            return True
        return False

    def generate_keys(self):  # input 5
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=default_backend())
        # encode the private key
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption()
                                        )
        secret_key = pem.decode('utf-8')
        public_key = private_key.public_key()
        # encode the public key
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_key = pem.decode('utf-8')
        return_value = str(secret_key) + "\n" + str(public_key)
        return return_value

    def generate_signature(self, key):  # input 6
        k = serialization.load_pem_private_key(key.encode(), None, default_backend())
        signature = k.sign(
            base64.b64encode(self.nodesList[0].value.encode()),
            #self.nodesList[0].value.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('ASCII')

    def verify_signature(self, key, signature, text):  # input 7
        pk = serialization.load_pem_public_key(key.encode(), default_backend())
        try:
            # verify and add padding
            pk.verify(
                base64.decodebytes(signature.encode()),
                text.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False


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

mt = MerkelTree()
while True:
    input_line = input()
    #print(input())
    option = input_line[:1]
    args = input_line[2:]
    #print(args)
    if option == "1":
        mt.insert_leaf(args)
    elif option == "2":
        mt.get_root() # check if should returned or printed value
    elif option == "3":
        print(mt.proof_of_inclusion(args))
    elif option == "4":
        args_arr = args.split(" ", 1)
        print(mt.check_proof_of_inclusion(args_arr[0], args_arr[1]))
    elif option == "5":
        print(mt.generate_keys())
    elif option == "6":
        print(mt.generate_signature(args))
    elif option == "7":
        print("here")
        # args_arr = args.split(" ", 2)
        # print(mt.verify_signature(args_arr[1], args_arr[2], args_arr[3]))

    # if input_line[0] == "1" and input_line[1] == " ":  # command 1
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    # elif input_line[0] == "2" and input_line[1] == " ":  # command 2
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    #     elif input_line[0] == "3" and input_line[1] == " ":  # command 3
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    # elif input_line[0] == "4" and input_line[1] == " ":  # command 4
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    # elif input_line[0] == "5" and input_line[1] == " ":  # command 5
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    # elif input_line[0] == "6" and input_line[1] == " ":  # command 6
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    # elif input_line[0] == "7" and input_line[1] == " ":  # command 7
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    # elif input_line[0] == "8" and input_line[1] == " ":  # command 8
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     mt.sparse(argument)
    # elif input_line[0] == "9" and input_line[1] == " ":  # command 9
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    # elif input_line[0] == "10" and input_line[1] == " ":  # command 10
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    # elif input_line[0] == "11" and input_line[1] == " ":  # command 11
    #     for i in range(2, len(input_line)):
    #         argument = argument + input_line[i]
    #     # need to add call to the relevant function
    # else:  # invalid input
    #     print("\n")
