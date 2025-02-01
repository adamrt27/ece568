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

