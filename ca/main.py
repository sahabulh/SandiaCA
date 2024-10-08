#!/usr/bin/env python
import sys, os, datetime, json
from pathlib import Path
sys.path.append(str(Path(__file__).absolute().parent.parent))

from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Response, status
from fastapi.security import APIKeyHeader

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure
from pymongo.collection import Collection

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import serialization

import utils, models

# Define API keys
full_access_key = ['iamdev','iamadmin']
user_access_key = ['iamuser']

# Define variable for storing access type (full access, user access, etc.)
access_type = None

# Define the database variable
sandia_ca = None

# You would use as an environment var in real life
X_API_KEY = APIKeyHeader(name='X-API-Key')

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    global sandia_ca
    # Connect to MongoDB
    mongodb_client = MongoClient("localhost",27017, serverSelectionTimeoutMS=10, connectTimeoutMS=1000)
    sandia_ca = mongodb_client.sandia_ca
    yield
    # Disconnect from MongoDB
    mongodb_client.close()

app = FastAPI(lifespan=lifespan)
        
@app.post("/rootca", summary="Create RootCA certificates", dependencies=[Depends(api_key_auth)])
async def create_rootCA_cert(data: models.RootCert, response: Response):
    if access_type == "full":
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(utils.get_name(data.domain+' ROOT CA', data.domain))
        builder = builder.issuer_name(utils.get_name(data.domain+' ROOT CA', data.domain))
        now = datetime.datetime.now(datetime.UTC)
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
        return {"serial":certificate.serial_number}
    else:
        error = {"error":"This is an admin end-point. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error
    
@app.post("/subca", summary="Create SubCA certificates", dependencies=[Depends(api_key_auth)])
async def create_subCA_cert(data: models.SubCACert, response: Response):
    if access_type == "full":
        issuer_cert, issuer_key = await utils.load_cert_and_key(data.issuer_serial)
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(utils.get_name(name=data.domain+' SubCA '+str(data.tier), domain=data.domain))
        builder = builder.issuer_name(issuer_cert.subject)
        now = datetime.datetime.now(datetime.UTC)
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
        return {"serial":certificate.serial_number}
    else:
        error = {"error":"This is an admin end-point. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error
    
@app.post("/ocsp", summary="Create OCSP signer/responder certificates", dependencies=[Depends(api_key_auth)])
async def create_ocsp_signer_cert(data: models.OCSPCert, response: Response):
    if access_type == "full":
        issuer_cert, issuer_key = await utils.load_cert_and_key(data.issuer_serial)
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(utils.get_name(name='OCSP Responder', domain='OCSP'))
        builder = builder.issuer_name(issuer_cert.subject)
        now = datetime.datetime.now(datetime.UTC)
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
        return {"serial":certificate.serial_number}
    else:
        error = {"error":"This is an admin end-point. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error
    
@app.post("/leaf", summary="Create leaf certificates", dependencies=[Depends(api_key_auth)])
async def create_leaf_cert(data: models.LeafCert, response: Response):
    if access_type == "full":
        issuer_cert, issuer_key = await utils.load_cert_and_key(data.issuer_serial)
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(utils.get_name(name=data.name, domain=data.domain))
        builder = builder.issuer_name(issuer_cert.subject)
        now = datetime.datetime.now(datetime.UTC)
        three_month_later = datetime.timedelta(90, 0, 0)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + three_month_later)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(x509.KeyUsage(True,True,False,False,True,False,False,False,False), critical=True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key=public_key), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value), critical=False)
        builder = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier("http://ocsp.patriasecurity.com:8001"))]), critical=False)
        certificate = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
        await utils.save_cert_and_key(cert=certificate, key=private_key)
        return {"serial":certificate.serial_number}
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

@app.get("/cert/{serial}", summary="Get PEM encoded certificate by serial", dependencies=[Depends(api_key_auth)])
async def get_cert_by_serial(serial: str):
    cert_filename = str(serial)+".pem"
    path = str(Path(__file__).absolute().parent.parent)+'/vault/'
    if Path(path+cert_filename).is_file():
        with open(path+cert_filename,"r") as file:
            data = file.read()
        return {"pem_cert": data}
    else:
        raise HTTPException(
            status_code=500,
            detail="Requested certificate not found in the server database"
        )
    
@app.post("/revoke/{serial}", summary="Revoke certificate by serial", dependencies=[Depends(api_key_auth)])
async def revoke_cert_by_serial(serial: str, response: Response):
    if access_type == "full":
        try:
            with open("../cert_db.json","r") as file:
                cert_db = json.load(file)
            if cert_db[serial]["status"] != 1:
                cert_db[serial]["status"] = 1
                cert_db[serial]["revocation_time"] = datetime.datetime.now(datetime.UTC).isoformat()
                json_object = json.dumps(cert_db, indent=4)
                with open("../cert_db.json", "w") as outfile:
                    outfile.write(json_object)
                return {"details": "The certificate has been revoked"}
            else:
                response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
                return {"details":"The certificate is already revoked"}
        except FileNotFoundError:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"details":"Database file not found"}
        except KeyError:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"details":"Entry for the serial not found in the database"}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"details":repr(err)}
    else:
        error = {"error":"This is an admin end-point. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error
    
@app.post("/unrevoke/{serial}", summary="Unrevoke certificate by serial", dependencies=[Depends(api_key_auth)])
async def unrevoke_cert_by_serial(serial: str, response: Response):
    if access_type == "full":
        try:
            with open("../cert_db.json","r") as file:
                cert_db = json.load(file)
            if cert_db[serial]["status"] == 1:
                cert_db[serial]["status"] = 0
                cert_db[serial]["revocation_time"] = None
                json_object = json.dumps(cert_db, indent=4)
                with open("../cert_db.json", "w") as outfile:
                    outfile.write(json_object)
                return {"details": "The certificate has been unrevoked"}
            else:
                response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
                return {"details":"The certificate is already unrevoked"}
        except FileNotFoundError:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"details":"Database file not found"}
        except KeyError:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"details":"Entry for the serial not found in the database"}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"details":repr(err)}
    else:
        error = {"error":"This is an admin end-point. You are not authorized to use it as an user."}
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return error

@app.post("/profile/crypto", summary="Create a cryptographic profile", dependencies=[Depends(api_key_auth)])
async def create_crypto(profile: models.CryptoProfile, response: Response):
    profiles = sandia_ca.crypto_profiles
    post = {"name": profile.name, "key_algorithm": profile.key_algorithm, "signature_hash": profile.signature_hash}
    try:
        post_id = profiles.insert_one(post).inserted_id
        del post["_id"]
        return {"entry_id": str(post_id), "details": post}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        error = {"error": "Failed to connect to MongoDB server"}
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return error

@app.get("/profile/crypto/{profile_name}", summary="Get a cryptographic profile", dependencies=[Depends(api_key_auth)])
async def get_crypto(profile_name: str, response: Response):
    profiles = sandia_ca.crypto_profiles
    query = {"name": profile_name}
    try:
        profile = profiles.find_one(query)
        entry_id = str(profile["_id"])
        del profile["_id"]
        if profile:
            return {"entry_id": entry_id, "details": profile}
        else:
            return {"error": "Profile with the requested name not found"}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        error = {"error": "Failed to connect to MongoDB server"}
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return error
    
@app.post("/profile/entity", summary="Create an entity profile", dependencies=[Depends(api_key_auth)])
async def create_entity(profile: models.EntityProfile, response: Response):
    profiles = sandia_ca.entity_profiles
    post = {"name": profile.name, "key_usage": profile.key_usage, "extended_key_usage": profile.extended_key_usage, "basic_constraints": profile.basic_constraints}
    try:
        post_id = profiles.insert_one(post).inserted_id
        del post["_id"]
        return {"entry_id": str(post_id), "details": post}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        error = {"error": "Failed to connect to MongoDB server"}
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return error

@app.get("/profile/entity/{profile_name}", summary="Get an entity profile", dependencies=[Depends(api_key_auth)])
async def get_entity(profile_name: str, response: Response):
    profiles = sandia_ca.entity_profiles
    query = {"name": profile_name}
    try:
        profile = profiles.find_one(query)
        entry_id = str(profile["_id"])
        del profile["_id"]
        if profile:
            return {"entry_id": entry_id, "details": profile}
        else:
            return {"error": "Profile with the requested name not found"}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        error = {"error": "Failed to connect to MongoDB server"}
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return error
