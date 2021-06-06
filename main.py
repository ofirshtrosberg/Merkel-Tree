import hashlib
import math
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# we will use it in the end just for now use string values

# # hash funcs
# def calculate_hash_for_constructor(value):
#     value_encode = value.encode('utf-8')
#     return hashlib.sha256(value_encode).hexdigest()


class Node:
    def __init__(self, value):
        # self.hashed_value = calculate_hash_for_constructor(value)
        self.value = str(value)  # remove str in the end just for check
        self.left = None
        self.right = None


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

    def sparse(self, argument):
        print(argument)

    def print_mt(self):  # just for check
        for i in range(0, len(self.leafsList)):
            print(self.leafsList[i].value)


def main():
    mt = MerkelTree()
    for i in range(0, 6):
        mt.insert_leaf(i)

    mt.proof_of_inclusion(0)
    # check input 4 ::
    check_input4_string = "012345 5 0123"
    check_input4_leaf_value = "4"
    mt.check_proof_of_inclusion(check_input4_leaf_value, check_input4_string)

    # keys = mt.generate_keys()
    # print(keys)

    # avoid conflict use the main from here below , above will be my checks

    # here

    while True:
        input_line = input()
        argument = ""
        if input_line[0] == "1" and input_line[1] == " ":  # command 1
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        elif input_line[0] == "2" and input_line[1] == " ":  # command 2
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        elif input_line[0] == "3" and input_line[1] == " ":  # command 3
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        elif input_line[0] == "4" and input_line[1] == " ":  # command 4
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        elif input_line[0] == "5" and input_line[1] == " ":  # command 5
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        elif input_line[0] == "6" and input_line[1] == " ":  # command 6
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        elif input_line[0] == "7" and input_line[1] == " ":  # command 7
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        elif input_line[0] == "8" and input_line[1] == " ":  # command 8
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            mt.sparse(argument)
        elif input_line[0] == "9" and input_line[1] == " ":  # command 9
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        elif input_line[0] == "10" and input_line[1] == " ":  # command 10
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        elif input_line[0] == "11" and input_line[1] == " ":  # command 11
            for i in range(2, len(input_line)):
                argument = argument + input_line[i]
            # need to add call to the relevant function
        else:  # invalid input
            print("\n")


#


if __name__ == "__main__":
    main()
