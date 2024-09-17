#!/usr/bin/env python
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import datetime

# private_key = ec.generate_private_key(ec.SECP256R1())
# public_key = private_key.public_key()
# builder = x509.CertificateBuilder()
# builder = builder.subject_name(x509.Name([
#     x509.NameAttribute(NameOID.COMMON_NAME, 'V2G ROOT CA'),
#     x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
#     x509.NameAttribute(NameOID.DOMAIN_COMPONENT, 'V2G'),
#     x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Sandia National Labs'),
#     x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Electric Vehicle'),
#     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'New Mexico'),
# ]))
# builder = builder.issuer_name(x509.Name([
#     x509.NameAttribute(NameOID.COMMON_NAME, 'V2G ROOT CA'),
#     x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
#     x509.NameAttribute(NameOID.DOMAIN_COMPONENT, 'V2G'),
#     x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Sandia National Labs'),
#     x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Electric Vehicle'),
#     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'New Mexico'),
# ]))
# now = datetime.datetime.today()
# one_year_later = now.replace(year = now.year + 1)
# builder = builder.not_valid_before(now)
# builder = builder.not_valid_after(one_year_later)
# builder = builder.serial_number(x509.random_serial_number())
# builder = builder.public_key(public_key)
# builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
# certificate = builder.sign(
#     private_key=private_key, algorithm=hashes.SHA256(),
# )
# cert = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
# with open(str(certificate.serial_number)+".pem","w") as file:
#     file.write(cert)
# key = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
# with open(str(certificate.serial_number)+".key","w") as file:
#     file.write(key)

with open("root.pem","r") as file:
    certificate_data = file.read().encode('utf-8')
certificate = load_pem_x509_certificate(certificate_data)
with open("root.key","r") as file:
    private_key_data = file.read().encode('utf-8')
private_key = load_pem_private_key(private_key_data, password=None)

subca_private_key = ec.generate_private_key(ec.SECP256R1())
public_key = subca_private_key.public_key()
builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'Root Responder'),
    x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
    x509.NameAttribute(NameOID.DOMAIN_COMPONENT, 'OCSP'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Sandia National Labs'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Electric Vehicle'),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'New Mexico'),
]))
builder = builder.issuer_name(certificate.issuer)
now = datetime.datetime.today()
one_month_later = now + datetime.timedelta(30,0,0)
builder = builder.not_valid_before(now)
builder = builder.not_valid_after(one_month_later)
builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(public_key)
builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=True)
certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(),
)
subca_cert = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
subca_key = subca_private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
with open(str(certificate.serial_number)+".pem","w") as file:
    file.write(subca_cert)
with open(str(certificate.serial_number)+".key","w") as file:
    file.write(subca_key)