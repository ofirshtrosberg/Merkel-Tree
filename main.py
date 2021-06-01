import hashlib
import math

# couldn't install the libraries but its needed from input 5,6,7

# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding

# hash func
def calculate_hash_for_constructor(value):
    value_encode = value.encode('utf-8')
    return hashlib.sha256(value_encode).hexdigest()


class NodeOfMerkleTree:
    def __init__(self, value, index):
        # self.hashed_value = calculate_hash_for_constructor(value)
        self.value = value # set value as number just for check all the program
        self.left_node = None
        self.right_node = None
        self.index = index # index of the node in the node list -- we need it dont delete.


# merkel tree is an almost complete tree
# we will use dynamic list for the tree

def invalid_input():
    print("invalid input\n") # should print just \n


# i changed the signature of the class didn't worked with object
# and i dont know why is needed
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
        max_len = int(len(self.nodesList) / 2) # max len is just half of the list
        if len(self.nodesList) % 2 == 1: # odd case -> should update
            for i in range(0, max_len):
                self.nodesList[i].value = str(self.nodesList[(2 * i) + 1].value) + "+" + str(self.nodesList[(2 * i) + 2].value)
        # for even case we will not update the merkle tree cuz we update the parent only when he have both child's
        # print(parent.value) # just for check parent value

    def get_root(self): # input 2
        return self.nodesList[0].value   #should return in hex

    def proof_of_inclusion(self, leaf_number): # input 3
        proof = str(self.nodesList[0].value) # proof start with root

        # if the list contain just one node (the root) -> return the proof.
        if len(self.nodesList) is 1:
            return proof

        # finding the leaf number zero (the most left leaf)
        i = 0
        if self.nodesList[i].left_node != None: # needed for edge case
            i += 1
        while (self.nodesList[i].left_node != None): # keep calculating general case's
            i *= 2
        leaf_zero = self.nodesList[i - 1]

        # now we should check if we got wrong number as input goto error
        # if (leaf_number >  amount_of_leafs): # bad input, should check cases
        #     invalid_input()

        #print(leaf_zero.value) # just for check

        # finding the specific given leaf as input
        leaf = self.nodesList[leaf_zero.index + leaf_number]
        leaf_ptr = leaf # define ptr that will "jump" on the tree
        #print(leaf.value) # just for check
        # collecting the nodes necessary to proof
        # make leaf_ptr as leaf parent
        if leaf_ptr.index % 2 == 1:  # leaf is left child
            parent_index = math.floor(leaf_ptr.index / 2)
            if parent_index < 0: # needed for edge cases
                parent_index = 0
            leaf_parent = self.nodesList[parent_index]
            proof += " "               # adding to the proof
            proof += str(leaf_parent.right_node.value)
        else:  # right child
            parent_index = math.floor(leaf_ptr.index / 2) - 1
            if parent_index < 0: # needed for edge cases
                parent_index = 0
            leaf_parent = self.nodesList[parent_index]
            proof += " "               # adding to the proof
            proof += str(leaf_parent.left_node.value)

        leaf_ptr = leaf_parent # jump to the parent

        while (leaf_ptr != self.nodesList[0]): # keep calculating general case's
            if leaf_ptr.index % 2 == 1:  # leaf is left child
                leaf_parent = self.nodesList[int(leaf_ptr.index / 2)]
                proof += " "
                proof += str(leaf_parent.right_node.value)
            else: # right child
                leaf_parent = self.nodesList[int(leaf_ptr.index / 2) - 1]
                proof += " "
                proof += str(leaf_parent.left_node.value)
            leaf_ptr = leaf_parent

        print(proof) # just for check the proof
        # if u dont know what the proof looks like see hemi explanation this question in
        # tirgul6 when he explained the homework
        return proof

    def check_proof_of_inclusion(self, string_value, proof): # input 4
        # finding the leaf number zero (the most left leaf)
        i = 0
        if self.nodesList[i].left_node != None: # needed for edge case
            i += 1
        while (self.nodesList[i].left_node != None): # keep calculating general case's
            i *= 2
        leaf_zero = self.nodesList[i - 1]
        # edge case -> the leaf given is the most left leaf aka leaf_zero
        if leaf_zero.value is string_value:
            leaf = leaf_zero
        else: # general case -> should find the leaf as given in input with its value
            for j in range(leaf_zero.index + 1, len(self.nodesList)):
                if self.nodesList[j].value is string_value:
                    leaf = self.nodesList[j]


        # take the actually correct proof using the function above
        correct_proof = self.proof_of_inclusion(leaf.index - leaf_zero.index)
        if correct_proof == proof: # compare the proof's and return result
            print("True") # just for check
            return True
        print("False")  # just for check
        return False


    # here its the code hemi gave us from make rsa and signitaure i couldn't run it but its looks like this
    # check it, its just copy paste from hemi he says we need to do that

    # def generate_keys(self): # input 5
    #     private_key = rsa.genetate_private_key(public_exponent=65537,
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
    #
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
