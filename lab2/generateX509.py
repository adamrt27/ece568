#!/usr/bin/python3

# ECE568
# Lab 2: generateX509.py

# The source materials you are provided in this lab are for your personal
# use only, as part of ECE568. Please do not post this file publicly
# (including on sites like GitHub, CourseHero, etc.).

# Please send any bug reports to Courtney Gibson <courtney.gibson@utoronto.ca>


from	cryptography					import x509
from	cryptography.hazmat.backends			import default_backend
from	cryptography.hazmat.primitives			import hashes
from	cryptography.hazmat.primitives			import serialization
from	cryptography.x509.oid				import NameOID
import	datetime


privateKeyFile	= 'privateKey.pem'
CA_certFile	= './util/CA_cert.pem'
CA_keyFile	= './util/CA_key.pem'

CSR = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, 'CA'),
		x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'ON'),
		x509.NameAttribute(NameOID.LOCALITY_NAME, 'Toronto'),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ECE568'),
		x509.NameAttribute(NameOID.COMMON_NAME, 'ECE568 Lab2')
	]))

# *** TODO: Complete the code to generate a Certificate Signing Request
# *** (CSR) for the private key in privateKey.pem, and an X509 certificate
# *** signed by the Certificate Authority key in CA_keyFile

# PKI - Public Key Infrastructure
# 1. Authority creates a private key
# 2. Create certificate for users public key
# 3. Sign the certificate with the private key of the authority
# 4. User send the certificate along with their public key to the server
# 5. Server verifies the certificate with the public key of the authority
# 6. Server uses the public key of the user to encrypt the data


# open the key file, whether it is private or public
def loadKey(filename, type = 'private'):
	with open(filename, 'rb') as file:
		if type == 'private':
			key = serialization.load_pem_private_key(
				file.read(),
				password = None,
				backend = default_backend())
		else:
			key = serialization.load_pem_public_key(
				file.read(),
				backend = default_backend())

	return key

# Load the private key from the file
privateKey = loadKey(privateKeyFile, type = 'private')

# sign CSR with private key of the CA
certificate = CSR.sign(privateKey, hashes.SHA256(), default_backend())

# print out CSR in PEM format
print(certificate.public_bytes(serialization.Encoding.PEM).decode().strip())

# use Certificate Authority files to sign the CSR and generate X509 certificate
# load CA certificate and CA private key
CA_privateKey = loadKey(CA_keyFile, type = 'private')
CA_cert = x509.load_pem_x509_certificate(open(CA_certFile, 'rb').read(), default_backend())

# assign values for X509 certificate
x509_cert = x509.CertificateBuilder()
# set the subject name
x509_cert = x509_cert.subject_name(certificate.subject)
# set the issuer name
x509_cert = x509_cert.issuer_name(CA_cert.subject)
# set the serial number
x509_cert = x509_cert.serial_number(x509.random_serial_number())
# set the not valid before date
x509_cert = x509_cert.not_valid_before(datetime.datetime.utcnow())
# set the not valid after date
x509_cert = x509_cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
# set the public key
x509_cert = x509_cert.public_key(certificate.public_key())

# set the subject key identifier
ski = x509.SubjectKeyIdentifier.from_public_key(certificate.public_key())
x509_cert = x509_cert.add_extension(ski, critical=False)

# set the authority key identifier
aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(CA_cert.public_key())
x509_cert = x509_cert.add_extension(aki, critical=False)

# set usage flags, to indicate that the certificate can be used for digital signatures
ku = x509.KeyUsage(
	digital_signature=True,
	content_commitment=False,
	key_encipherment=False,
	data_encipherment=False,
	key_agreement=False,
	key_cert_sign=False,
	crl_sign=False,
	encipher_only=False,
	decipher_only=False)
x509_cert = x509_cert.add_extension(ku, critical=True)

# Sign X509 certificate with CA private key
x509_cert = x509_cert.sign(CA_privateKey, hashes.SHA256(), default_backend())

# Convert X509 certificate to PEM format
x509_cert = x509_cert.public_bytes(serialization.Encoding.PEM).decode()

# print out certificate chain: blank line, CA certificate, X509 certificate
print()
print(open(CA_certFile, 'r').read().strip())
print(x509_cert.strip())
