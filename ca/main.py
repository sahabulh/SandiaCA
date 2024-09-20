#!/usr/bin/env python
import sys, os, datetime
from pathlib import Path
sys.path.append(str(Path(__file__).absolute().parent.parent))

from pydantic import BaseModel

from fastapi import FastAPI, Depends, HTTPException, Response, status, Query
from fastapi.security import APIKeyHeader

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import serialization

import utils

full_access_key = ['iamdev','iamadmin']
user_access_key = ['iamuser']

access_type = None

# You would use as an environment var in real life
X_API_KEY = APIKeyHeader(name='X-API-Key')

class ROOT_CERT(BaseModel):
    domain: str

class SUBCA_CERT(BaseModel):
    issuer_serial: str
    domain: str
    tier: int

class OCSP_CERT(BaseModel):
    issuer_serial: str

class LEAF_CERT(BaseModel):
    issuer_serial: str
    domain: str
    id: str

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
        
@app.post("/rootca", summary="Create RootCA certificates", dependencies=[Depends(api_key_auth)])
async def create_rootCA_cert(data: ROOT_CERT, response: Response):
    if access_type == "full":
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(utils.get_name(data.domain+' ROOT CA', data.domain))
        builder = builder.issuer_name(utils.get_name(data.domain+' ROOT CA', data.domain))
        now = datetime.datetime.today()
        ten_years_later = now.replace(year = now.year + 10)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(ten_years_later)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        builder = builder.add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False), critical=True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key=public_key), critical=False)
        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
        await utils.save_cert_and_key(cert=certificate, key=private_key)
        return {"data":certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')}
    else:
        error = {"error":"This is an admin end-point. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error
    
@app.post("/subca", summary="Create SubCA certificates", dependencies=[Depends(api_key_auth)])
async def create_subCA_cert(data: SUBCA_CERT, response: Response):
    if access_type == "full":
        issuer_cert, issuer_key = await utils.load_cert_and_key(data.issuer_serial)
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(utils.get_name(name=data.domain+' SubCA '+str(data.tier), domain=data.domain))
        builder = builder.issuer_name(issuer_cert.subject)
        now = datetime.datetime.today()
        three_years_later = now.replace(year = now.year + 3)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(three_years_later)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=2-data.tier), critical=True)
        builder = builder.add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False), critical=True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key=public_key), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value), critical=False)
        builder = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier("http://ocsp.patriasecurity.com:8001"))]), critical=False)
        certificate = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
        await utils.save_cert_and_key(cert=certificate, key=private_key)
        return {"data":certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')}
    else:
        error = {"error":"This is an admin end-point. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error
    
@app.post("/ocsp", summary="Create OCSP signer/responder certificates", dependencies=[Depends(api_key_auth)])
async def create_ocsp_signer_cert(data: OCSP_CERT, response: Response):
    if access_type == "full":
        issuer_cert, issuer_key = await utils.load_cert_and_key(data.issuer_serial)
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(utils.get_name(name='OCSP Responder', domain='OCSP'))
        builder = builder.issuer_name(issuer_cert.subject)
        now = datetime.datetime.today()
        three_years_later = now.replace(year = now.year + 3)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(three_years_later)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key=public_key), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value), critical=False)
        certificate = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
        await utils.save_cert_and_key(cert=certificate, key=private_key)
        return {"data":certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')}
    else:
        error = {"error":"This is an admin end-point. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error
    
@app.post("/leaf", summary="Create leaf certificates", dependencies=[Depends(api_key_auth)])
async def create_leaf_cert(data: LEAF_CERT, response: Response):
    if access_type == "full":
        issuer_cert, issuer_key = await utils.load_cert_and_key(data.issuer_serial)
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(utils.get_name(name=data.id, domain=data.domain))
        builder = builder.issuer_name(issuer_cert.subject)
        now = datetime.datetime.today()
        three_month_later = datetime.timedelta(90, 0, 0)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + three_month_later)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(x509.KeyUsage(True,True,False,False,True,False,False,False,False), critical=True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key=public_key), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value), critical=False)
        builder = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier("http://host.docker.internal:8001"))]), critical=False)
        certificate = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
        await utils.save_cert_and_key(cert=certificate, key=private_key)
        return {"data":certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')}
    else:
        error = {"error":"This is an admin end-point. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error
    
@app.get("/cert", summary="List certificate serials")
async def list_certs():
    data = []
    path = str(Path(__file__).absolute().parent.parent)+'/vault'
    for filename in os.listdir(path):
        if filename.endswith(".pem"):
            serial = filename[:-4]
            cert = await utils.load_cert(serial)
            data.append({
                "serial": serial,
                "name": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            })
    data = {
        "data": data
    }
    return data

@app.get("/cert/{serial}", summary="Get certificate by serial", dependencies=[Depends(api_key_auth)])
async def get_cert_by_serial(serial: str):
    cert_filename = str(serial)+".pem"
    path = str(Path(__file__).absolute().parent.parent)+'/vault/'
    if Path(path+cert_filename).is_file():
        with open(path+cert_filename,"r") as file:
            data = file.read()
        return {"data": data}
    else:
        raise HTTPException(
            status_code=404,
            detail="Requested certificate not found."
        )
