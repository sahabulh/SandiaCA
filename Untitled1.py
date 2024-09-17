#!/usr/bin/env python
from fastapi import FastAPI, Depends, HTTPException, Response, status, Query
from fastapi.security import APIKeyHeader
import datetime
from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

full_access_key = ['iamdev','iamadmin']
user_access_key = ['iamuser']

access_type = None

# You would use as an environment var in real life
X_API_KEY = APIKeyHeader(name='X-API-Key')

class SubCA_POST(BaseModel):
    serial: str
    name: str

def api_key_auth(x_api_key: str = Depends(X_API_KEY)):
    global access_type
    """ takes the X-API-Key header and validate it with the X-API-Key in the database/environment"""
    if x_api_key not in full_access_key and x_api_key not in user_access_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key. Check that you are passing a 'X-API-Key' on your header."
        )
    elif x_api_key in full_access_key:
        access_type = "full"
    else:
        access_type = "user"

app = FastAPI()
        
@app.post("/rootCA", summary="Create RootCA certificates", dependencies=[Depends(api_key_auth)])
async def create_rootCA_cert(response: Response):
    if access_type == "full":
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'V2G ROOT CA'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, 'V2G'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Sandia National Labs'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Electric Vehicle'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'New Mexico'),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'V2G ROOT CA'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, 'V2G'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Sandia National Labs'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Electric Vehicle'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'New Mexico'),
        ]))
        now = datetime.datetime.today()
        one_year_later = now.replace(year = now.year + 1)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(one_year_later)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(),
        )
        cert = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        with open(str(certificate.serial_number)+".pem","w") as file:
            file.write(cert)
        return cert
    elif access_type == "user":
        error = {"error":"This is an admin function. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error
    
@app.get("/rootCA", summary="List RootCA certificate serials", dependencies=[Depends(api_key_auth)])
async def list_rootCA_cert(response: Response):
    data = {
        "serials":["52916341631662061215530779252080356099286263865","677777872243453799052937534314355996284295077020"]
    }
    return data
    
@app.post("/subCA", summary="Create SubCA certificates", dependencies=[Depends(api_key_auth)])
async def create_subCA_cert(data: SubCA_POST, response: Response):
    if access_type == "full":
        with open(data.serial+".pem","r") as file:
            issuer_data = file.read().encode()
        issuer = load_pem_x509_certificate(issuer_data)

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
        # builder = builder.issuer_name()
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
        return issuer_data
    elif access_type == "user":
        error = {"error":"This is an admin function. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error

@app.get("/cert/{serial}", summary="Get certificate by serial", dependencies=[Depends(api_key_auth)])
async def get_cert_by_serial(serial: str, response: Response):
    with open(str(serial)+".pem","r") as file:
        data = file.read()
    return data
