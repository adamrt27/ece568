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

# define hash function
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

	# If message is a string, convert it to bytes.
	if isinstance(message, str):
		message_bytes = message.encode('utf-8')
	else:
		message_bytes = message

	# If signature is a string, convert it to bytes.
	if isinstance(signature, str):
		signature = bytes.fromhex(signature)
  
	# Verify the signature.
	try:
		publicKey.verify(
			signature,
			message_bytes,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
						salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256()
		)
		return True
	except InvalidSignature:
		return False



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
 
	# Check that the file exists
	if not os.path.isfile(filename):
		print("ERROR: Could not find %s" % filename)
		quit()
	# Load the public key from the file
	with open(filename, 'rb') as file:
		publicKey = serialization.load_pem_public_key(
			file.read(),
			backend=default_backend())
	return publicKey

# Load the values 
loadValues(valuesFile)

# Create a Merkle Tree
merkle_tree = MerkleTree(values)

# test the Merkle Tree

# print("Merkle Tree:")
# merkle_tree.print_tree()
# print("Hash f", hash("f"))

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

	# Uncomment to test the proof verification
	# print("./merkleTree.py \ ")
	# for i in range(0,len(proof)):
	# 	if ( proof[i] is None ):
	# 		print("none \ ")
	# 	else:
	# 		print(proof[i] + " \ ")

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
  
	# *** TODO: Add your code to check if the provided proof
	# *** matches what you would calculate -- and check that
	# *** the signature is valid
 
	# Calculate our own proof based on the first hash.
	hashedValue = suppliedProof[0]
	computedProof = generateProof(hashedValue)

	# Now, compare the two proofs (excluding the signature) and verify the signature.
	# The root hash is the second-to-last element.
	if computedProof[:-1] == suppliedProof[:-1] and verifySignature(computedProof[-2], suppliedProof[-1]):
		print(True)
	else:
		print(False)	

