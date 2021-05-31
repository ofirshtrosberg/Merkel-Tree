import hashlib


def calculate_hash_for_constructor(value):
    value_encode = value.encode('utf-8')
    return hashlib.sha256(value_encode).hexdigest()


class NodeOfMerkleTree(object):
    def __init__(self, value):
        #self.value = value
        self.hashed_value = calculate_hash_for_constructor(value)
        self.left_node = None
        self.right_node = None


# merkel tree is an almost complete tree
# we will use dynamic list for the tree


class MerkelTree(object):
    def __init__(self):
        self.nodesList = []

    def insert_node(self, value):
        if value is None:
            return
        else:
            self.nodesList.append(NodeOfMerkleTree(value))
            # if its just root it doesnt have parent
            if len(self.nodesList) == 1:
                return
            else:
                # update parent that this node is his child
                last_index = len(self.nodesList) - 1
                parent_index = (last_index - 1) / 2
                # is left child
                if len(self.nodesList) % 2 == 0:
                    self.nodesList[parent_index].left_node = self.nodesList[last_index]
                # is right child
                else:
                    self.nodesList[parent_index].right_node = self.nodesList[last_index]

    def update_tree_after_insert(self):
        for i in range(0, len(self.nodesList)):
            # i want to concatenate the values of both children if exist and then do hash on the result

# main
