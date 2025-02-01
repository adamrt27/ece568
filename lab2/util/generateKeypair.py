#!/usr/bin/python3

# ECE568
# Lab 2: generateKeypair.py

# The source materials you are provided in this lab are for your personal
# use only, as part of ECE568. Please do not post this file publicly
# (including on sites like GitHub, CourseHero, etc.).

# Please send any bug reports to Courtney Gibson <courtney.gibson@utoronto.ca>


from cryptography.hazmat.backends		import default_backend
from cryptography.hazmat.primitives		import serialization
from cryptography.hazmat.primitives.asymmetric	import rsa


privateKeyFile		= 'privateKey.pem'
publicKeyFile		= 'publicKey.pem'


# Generate a 4096-bit RSA private key

key = rsa.generate_private_key(
	key_size = 4096,
	public_exponent = 65537,
	backend = default_backend() )

# Write out the private key in PEM format

print("Writing RSA private key to %s..." % privateKeyFile)

with open(privateKeyFile, 'w') as file:

	privateKey = key.private_bytes(
			encryption_algorithm = serialization.NoEncryption(),
			encoding = serialization.Encoding.PEM,
			format = serialization.PrivateFormat.PKCS8).decode()

	file.write(privateKey)

# Write out the public key in PEM format

print("Writing RSA public key to %s..." % publicKeyFile)

with open(publicKeyFile, 'w') as file:

	publicKey = key.public_key().public_bytes(
			encoding = serialization.Encoding.PEM,
			format = serialization.PublicFormat.PKCS1).decode()

	file.write(publicKey)

