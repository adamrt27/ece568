#!/usr/bin/python3

# ECE568
# Lab 2: merkleTree.py

# The source materials you are provided in this lab are for your personal
# use only, as part of ECE568. Please do not post this file publicly
# (including on sites like GitHub, CourseHero, etc.).

# Please send any bug reports to Courtney Gibson <courtney.gibson@utoronto.ca>


import	collections.abc
from	cryptography.exceptions				import InvalidSignature
from	cryptography.hazmat.backends			import default_backend
from	cryptography.hazmat.primitives			import hashes
from	cryptography.hazmat.primitives			import serialization
from	cryptography.hazmat.primitives.asymmetric	import padding
from	hashlib						import sha256
import	hmac
import	json
import	os.path
from	sys						import argv


valuesFile	= 'values.json'
privateKeyFile	= 'privateKey.pem'
publicKeyFile	= 'publicKey.pem'

values		= []
hmacKey		= b'ECE568'

def hash(left, right=None):
    global hmacKey
    if right is not None:
        # For two arguments, assume they are hex strings representing binary hash values.
        try:
            left_bytes = bytes.fromhex(left)
            right_bytes = bytes.fromhex(right)
        except ValueError:
            # If conversion fails, fallback to UTF-8 encoding.
            left_bytes = left.encode('UTF-8')
            right_bytes = right.encode('UTF-8')
        message_bytes = left_bytes + right_bytes
    else:
        # For a single argument, if it is a 64-character hex string,
        # then convert it to binary. Otherwise, use UTF-8 encoding.
        if len(left) == 64 and all(c in "0123456789abcdefABCDEF" for c in left):
            message_bytes = bytes.fromhex(left)
        else:
            message_bytes = left.encode('UTF-8')
    
    h = hmac.new(hmacKey, message_bytes, sha256)
    return h.hexdigest()

# define merkle tree class
class MerkleTree:
	def __init__(self, values):
		"""Initialize Merkle Tree with given leaf values."""
		self.values = values
		self.tree_levels = self.build_tree(values)  # Store full tree structure

	def build_tree(self, values):
		"""Builds a Merkle Tree from leaf values and returns levels of the tree."""
		if not values:
			return []

		# Start with the leaf hashes
		tree = [[hash(value) for value in values]]

		# Build up the tree
		while len(tree[-1]) > 1:
			level = tree[-1]
			parent_level = []

			# Process pairs of nodes
			for i in range(0, len(level) - 1, 2):
				parent_level.append(hash(level[i], level[i + 1]))

			# If there is an odd node out, hash it alone (without duplicating it)
			if len(level) % 2 == 1:
				parent_level.append(hash(level[-1]))

			tree.append(parent_level)

		return tree

	def get_root(self):
		"""Returns the Merkle Root."""
		return self.tree_levels[-1][0] if self.tree_levels else None

	def get_parent(self, level, index):
		"""
		Returns the parent's hash value for the node at (level, index).
		
		Parameters:
			level (int): The current level of the node (0 = leaves).
			index (int): The index of the node in that level.
		
		Returns:
			The parent's hash (a hex string) if it exists, or None if the node is the root.
		"""
		# If the node is at the root level, it has no parent.
		if level >= len(self.tree_levels) - 1:
			return None
		
		parent_level = level + 1
		parent_index = index // 2  # each parent's index is the integer division of child's index by 2.
		return self.tree_levels[parent_level][parent_index]

	def get_left_child(self, level, index):
		"""
		Returns the left child's hash value for the node at (level, index).
		
		Parameters:
			level (int): The current level of the node (level > 0, since leaves have no children).
			index (int): The index of the node in that level.
		
		Returns:
			The left child's hash (a hex string) if it exists, or None.
		"""
		# Leaves (level 0) do not have children.
		if level == 0:
			return None
		
		child_level = level - 1
		left_index = index * 2
		if left_index < len(self.tree_levels[child_level]):
			return self.tree_levels[child_level][left_index]
		return None

	def get_right_child(self, level, index):
		"""
		Returns the right child's hash value for the node at (level, index).
		
		Parameters:
			level (int): The current level of the node (level > 0, since leaves have no children).
			index (int): The index of the node in that level.
		
		Returns:
			The right child's hash (a hex string) if it exists, or None.
			(This can be None if the node was formed from a single odd child.)
		"""
		if level == 0:
			return None
		
		child_level = level - 1
		right_index = index * 2 + 1
		if right_index < len(self.tree_levels[child_level]):
			return self.tree_levels[child_level][right_index]
		return None

	def get_children(self, level, index):
		"""
		Returns a tuple of (left_child, right_child) for the node at (level, index).
		
		For a node that has only one child (e.g. an odd node in the tree), the right child
		will be None.
		
		Parameters:
			level (int): The current level of the node (level > 0).
			index (int): The index of the node in that level.
		
		Returns:
			A tuple (left_child_hash, right_child_hash) or (None, None) if no children exist.
		"""
		left = self.get_left_child(level, index)
		right = self.get_right_child(level, index)
		return (left, right)

	def print_tree(self):
		"""Prints the Merkle Tree in a structured format, aligning hashes properly above leaves."""
		tree_levels_reversed = list(reversed(self.tree_levels))  # Start from root

		max_width = len(self.tree_levels[0]) * 8 * 2  # Calculate maximum width for proper spacing

		for i, level in enumerate(tree_levels_reversed):
			indent = max_width // (len(level) + 1)  # Adjust spacing dynamically

			# Print current level (shortened hashes in brackets)
			print(" " * indent + "   ".join(f"[{h[:8]}]" for h in level))

		# Print leaf values below
		indent = max_width // (len(self.values) + 1)

		print(" " * indent + "   ".join((f"'{val}'" + " " * (indent)) for val in self.values))

def sign(message):

	# Signs the message with the privateKey using SHA256 and
	# secure padding. Note that, for this lab, the signature
	# should be created on the ASCII encoding of the root hash.
	#
	# For example:
	# 'a9424f4004232abe6a074543035172da3460f1f4d2c47a110c0e5f9a74a610b6'
	#
	# NOT:
	# '\xa9\x42\x4f...'

	global	privateKey

	if isinstance(message, str):
		# If "message" is a string then encode it as a byte array
		message = message.encode('UTF-8')
	
	signature = privateKey.sign(message,
			padding.PSS(mgf = padding.MGF1(hashes.SHA256()),
				salt_length = padding.PSS.MAX_LENGTH),
			hashes.SHA256() )

	return signature


def verifySignature(message, signature):

	# Verifies the message signature that was created with the private key

	# *** TODO: You will need to add some code to verify the
	# *** signature created in sign(), above

	return False	# Returns False, for now, until you add your code



def checkProofFormat(proof):

	# Checks that your "proof" structure appears to be in the
	# correct format. This is provided to help make sure you
	# program output adheres to the format specified in the
	# lab assignment; it's not a guarantee, but it should help

	# Check that it's a sequence: ['39abd...', '42abc...']
	assert isinstance(proof, collections.abc.Sequence)

	# Check that there are at least two elements
	assert len(proof) >= 2

	# Check that the first (N-1) elements are all 64-byte
	# hex strings (or None)

	for i in range(0,len(proof)-1):

		# An entry of None is acceptable
		if ( proof[i] is None ):
			continue

		# The element should be a string (not a byte array)
		assert isinstance(proof[i], str)

		# SHA256 hashes should be 64 bytes
		assert len(proof[i]) == 64

		# Check that it's a valid hex string
		try:
			hexValue = bytes.fromhex(proof[i])
			validHexString = True
		except:
			validHexString = False
		assert validHexString == True

	# Check that the last element (the signature) is a
	# 1024-byte hex string

	# The signature should be a string (not a byte array)
	assert isinstance(proof[-1], str)

	# The signature should be 1024 bytes
	assert len(proof[-1]) == 1024

	# Check that it's a valid hex string
	try:
		hexValue = bytes.fromhex(proof[-1])
		validHexString = True
	except:
		validHexString = False
	assert validHexString == True


def generateProof(hashedValue):
    # If hashedValue is bytes, convert it to a hex string.
    if isinstance(hashedValue, bytes):
        hashedValue = hashedValue.hex()

    # Find the index of hashedValue in the leaf level.
    try:
        current_index = merkle_tree.tree_levels[0].index(hashedValue)
    except ValueError:
        return None

    proof = []
    # Append the leaf itself.
    proof.append(hashedValue)

    # For each level from the leaves (level 0) up to (but not including) the root.
    for level in range(0, len(merkle_tree.tree_levels) - 1):
        nodes = merkle_tree.tree_levels[level]
        # Determine the sibling:
        if current_index % 2 == 0:
            # For an even index, the sibling is the next element if it exists.
            sibling = nodes[current_index + 1] if current_index + 1 < len(nodes) else None
        else:
            # For an odd index, the sibling is the previous element.
            sibling = nodes[current_index - 1]
        proof.append(sibling)
        # Update current_index for the next level.
        current_index = current_index // 2

    # Append the root from the top level (the only element at that level).
    proof.append(merkle_tree.tree_levels[-1][0])
    
    # Sign the root hash.
    signature = sign(proof[-1])
    proof.append(signature.hex())
    
    # check the proof
    checkProofFormat(proof)

    return proof


def loadValues(filename):

	# Loads the values from the values.json file. New test values
	# can be generated by running ./createValues.py

	global	values

	# Check that the JSON file exists
	if not os.path.isfile(filename):
		print("ERROR: Could not find %s" % filename)
		quit()

	# Load the entries from the JSON file
	with open(filename, 'r') as inputFile:
		values = json.load(inputFile)


def loadPrivateKey(filename):

	# Loads the private key from privateKey.pem. A new keypair can
	# be generated by running ./generateKeypair.py

	# Check that the file exists
	if not os.path.isfile(filename):
		print("ERROR: Could not find %s" % filename)
		quit()

	with open(filename, 'rb') as file:
		privateKey = serialization.load_pem_private_key(
			file.read(),
			password = None,
			backend = default_backend())

	return privateKey


def loadPublicKey(filename):

	# Loads the public key from privateKey.pem. A new keypair can
	# be generated by running ./generateKeypair.py

	# *** TODO: You will need to add code here, to load the public key.
	# *** See loadPrivateKey() for the general format of what you need
	# *** to do.
 
	# Placeholder, until you add your code	
	publicKey = None


	return publicKey

# Test building a Merkle Tree
leaf_values = ['a', 'b', 'c']
merkle_tree = MerkleTree(leaf_values)
merkle_tree.print_tree()
print("Root hash:", merkle_tree.get_root())
print("Hash c", hash('c'))
print("Hash a", hash('a'))

# Load the values 
loadValues(valuesFile)

# Load the private key
privateKey = loadPrivateKey(privateKeyFile)

# Load the public key
publicKey = loadPublicKey(publicKeyFile)

# Parse the command-line arguments

if ( len(argv) < 2 ):
	quit()

elif ( len(argv) == 2 ):

	# Generate a proof for the specified HMAC

	try:
		hashedValue = bytes.fromhex(argv[1])
	except:
		quit()

	proof = generateProof(hashedValue)

	print(proof)

else:

	# Verify the proof provided in the command arguments

	# Load the user's proof from the command-line arguments

	suppliedProof = []

	for i in range(1,len(argv)):

		if ( argv[i].lower() == 'none' ):
			suppliedProof += [ None ]
		else:
			suppliedProof += [ argv[i] ]

	# Check that it's a validly-formatted proof

	if ( checkProofFormat(suppliedProof) == False ):
		quit()

	# Calculate our own proof, based on the first hash

	# *** TODO: Add your code to check if the provided proof
	# *** matches what you would calculate -- and check that
	# *** the signature is valid

	print(False)	# Placeholder, until you add your code

