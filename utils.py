from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from typing import Union, Tuple

import sys
from pathlib import Path
abs_path = str(Path(__file__).absolute().parent)

def get_name(name: str, domain: str) -> x509.Name:
    return x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, domain),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Sandia National Labs'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Electric Vehicles'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'New Mexico'),
        ])

async def save_cert_and_key(cert: x509.Certificate, key: Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]):
    cert_data = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
    with open(abs_path+"/vault/"+str(cert.serial_number)+".pem","w") as file:
        file.write(cert_data)
    key_data = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
    with open(abs_path+"/vault/"+str(cert.serial_number)+".key","w") as file:
        file.write(key_data)

async def load_cert_and_key(serial: str) -> Tuple[x509.Certificate, Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]]:
    with open(abs_path+"/vault/"+serial+".pem","r") as file:
        cert_data = file.read().encode()
    cert = load_pem_x509_certificate(cert_data)
    with open(abs_path+"/vault/"+serial+".key","r") as file:
        key_data = file.read().encode()
    key = load_pem_private_key(key_data, password=None)
    return cert, key

async def load_cert(serial: str) -> x509.Certificate:
    with open(abs_path+"/vault/"+serial+".pem","r") as file:
        cert_data = file.read().encode()
    cert = load_pem_x509_certificate(cert_data)
    return cert