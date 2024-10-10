#!/usr/bin/env python
import sys, os, datetime, json
from pathlib import Path
sys.path.append(str(Path(__file__).absolute().parent.parent))

from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Response, status
from fastapi.security import APIKeyHeader

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure

from cryptography.x509.oid import NameOID

import utils, models
from exceptions import EntryNotFoundError

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
    """ takes the X-API-Key header and validate it with the X-API-Key in the database/environment"""
    global access_type
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
    await utils.load_db(sandia_ca)
    yield
    # Disconnect from MongoDB
    mongodb_client.close()

app = FastAPI(lifespan=lifespan)
        
@app.post("/rootca", summary="Create RootCA certificates", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def create_rootCA_cert(data: models.RootCert, response: Response):
    if access_type == "full":
        try:
            certificate, private_key = await utils.build_cert(data=data)
            await utils.save_cert_and_key(cert=certificate, key=private_key, issuer_serial=certificate.serial_number, profile=data.profile)
            return {"serial": str(certificate.serial_number)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
    
@app.post("/subca", summary="Create SubCA certificates", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def create_subCA_cert(data: models.SubCACert, response: Response):
    if access_type == "full":
        try:
            certificate, private_key = await utils.build_cert(data=data)
            await utils.save_cert_and_key(cert=certificate, key=private_key, issuer_serial=int(data.issuer_serial), profile=data.profile)
            return {"serial": str(certificate.serial_number)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
    
@app.post("/ocsp", summary="Create OCSP signer/responder certificates", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def create_ocsp_signer_cert(data: models.OCSPCert, response: Response):
    if access_type == "full":
        try:
            certificate, private_key = await utils.build_cert(data=data)
            await utils.save_cert_and_key(cert=certificate, key=private_key, issuer_serial=int(data.issuer_serial), profile=data.profile)
            return {"serial": str(certificate.serial_number)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
    
@app.post("/leaf", summary="Create leaf certificates", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def create_leaf_cert(data: models.LeafCert, response: Response):
    if access_type == "full":
        try:
            certificate, private_key = await utils.build_cert(data=data)
            await utils.save_cert_and_key(cert=certificate, key=private_key, issuer_serial=int(data.issuer_serial), profile=data.profile)
            return {"serial": str(certificate.serial_number)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
    
@app.get("/cert", summary="List certificate serials and common names", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def list_certs():
    data = []
    path = str(Path(__file__).absolute().parent.parent)+'/vault'
    for filename in os.listdir(path):
        if filename.endswith(".pem"):
            serial = filename[:-4]
            cert = utils.load_cert(serial)
            data.append({
                "serial": serial,
                "name": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            })
    data = {
        "data": data
    }
    return data

@app.get("/cert/{serial}", summary="Get PEM encoded certificate by serial", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def get_cert_by_serial(serial: str, response: Response):
    try:
        return {"details": utils.load_cert(serial)}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}
    
@app.get("/key/{serial}", summary="Get PEM encoded private key by serial", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def get_key_by_serial(serial: str, response: Response):
    if access_type == "full":
        try:
            return {"details": utils.load_key(serial)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
    
@app.post("/revoke/{serial}", summary="Revoke certificate by serial", dependencies=[Depends(api_key_auth)], tags=["Revocation"])
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
    
@app.post("/unrevoke/{serial}", summary="Unrevoke certificate by serial", dependencies=[Depends(api_key_auth)], tags=["Revocation"])
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

@app.post("/profile/crypto", summary="Create a cryptographic profile", dependencies=[Depends(api_key_auth)], tags=["Profile"])
async def create_crypto(profile: models.CryptoProfile, response: Response):
    profiles = sandia_ca.crypto_profiles
    post = {"name": profile.name, "key_algorithm": profile.key_algorithm, "signature_hash": profile.signature_hash}
    try:
        post_id = profiles.insert_one(post).inserted_id
        del post["_id"]
        return {"entry_id": str(post_id), "details": post}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": "Failed to connect to MongoDB server"}

@app.get("/profile/crypto/{profile_name}", summary="Get a cryptographic profile", dependencies=[Depends(api_key_auth)], tags=["Profile"])
async def get_crypto(profile_name: str, response: Response):
    try:
        return await utils.get_profile(type="crypto", name=profile_name)
    except EntryNotFoundError as err:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"error": str(err)}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}
    
@app.post("/profile/entity", summary="Create an entity profile", dependencies=[Depends(api_key_auth)], tags=["Profile"])
async def create_entity(profile: models.EntityProfile, response: Response):
    profiles = sandia_ca.entity_profiles
    post = profile.__dict__
    try:
        post_id = profiles.insert_one(post).inserted_id
        del post["_id"]
        return {"entry_id": str(post_id), "details": post}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": "Failed to connect to MongoDB server"}

@app.get("/profile/entity/{profile_name}", summary="Get an entity profile", dependencies=[Depends(api_key_auth)], tags=["Profile"])
async def get_entity(profile_name: str, response: Response):
    try:
        return await utils.get_profile(type="entity", name=profile_name)
    except EntryNotFoundError as err:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"error": str(err)}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}