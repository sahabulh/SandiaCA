import os
from pathlib import Path

from fastapi import APIRouter, Depends, Response, status

from cryptography.x509.oid import NameOID

import app.ca_server.utils as utils
import app.models.models as models
from app.ca_server.auth import api_key_auth

from app.database.db import update

router = APIRouter()

@router.post("/rootca", summary="Create RootCA certificates", tags=["Certificate"])
async def create_rootCA_cert(data: models.RootCert, response: Response, role: str = Depends(api_key_auth)):
    if role == "full":
        try:
            certificate, private_key = await utils.build_cert(data=data)
            await utils.save_cert_and_key(cert=certificate, key=private_key, issuer_serial=certificate.serial_number, profile=data.profile)
            await utils.build_crl([], issuer_cert=certificate, issuer_priv_key=private_key)
            return {"serial": str(certificate.serial_number)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
    
@router.post("/subca", summary="Create SubCA certificates", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def create_subCA_cert(data: models.SubCACert, response: Response, role: str = Depends(api_key_auth)):
    if role == "full":
        try:
            certificate, private_key = await utils.build_cert(data=data)
            await utils.save_cert_and_key(cert=certificate, key=private_key, issuer_serial=int(data.issuer_serial), profile=data.profile)
            await utils.build_crl([], issuer_cert=certificate, issuer_priv_key=private_key)
            return {"serial": str(certificate.serial_number)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
    
@router.post("/ocsp", summary="Create OCSP signer/responder certificates", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def create_ocsp_signer_cert(data: models.OCSPCert, response: Response, role: str = Depends(api_key_auth)):
    if role == "full":
        try:
            certificate, private_key = await utils.build_cert(data=data)
            await utils.save_cert_and_key(cert=certificate, key=private_key, issuer_serial=int(data.issuer_serial), profile=data.profile)
            await update(query={"serial": data.issuer_serial}, value={"responder": str(certificate.serial_number)}, collection_name="certs")
            return {"serial": str(certificate.serial_number)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
    
@router.post("/leaf", summary="Create leaf certificates", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def create_leaf_cert(data: models.LeafCert, response: Response, role: str = Depends(api_key_auth)):
    if role == "full":
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
    
@router.get("/cert", summary="List certificate serials and common names", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def list_certs(role: str = Depends(api_key_auth)):
    data = []
    path = str(Path(__file__).absolute().parent.parent.parent)+'/vault'
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

@router.get("/cert/{serial}", summary="Get PEM encoded certificate by serial", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def get_cert_by_serial(serial: str, response: Response, role: str = Depends(api_key_auth)):
    try:
        return {"details": utils.load_cert_as_string(serial)}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}

@router.get("/issuer/{serial}", summary="Get serial number of certificate issuer", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def get_issuer_by_serial(serial: str, response: Response, role: str = Depends(api_key_auth)):
    try:
        cert_info = await utils.get_cert_info(serial=serial)
        return {"details": cert_info.issuer}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}
    
@router.get("/key/{serial}", summary="Get PEM encoded private key by serial", dependencies=[Depends(api_key_auth)], tags=["Certificate"])
async def get_key_by_serial(serial: str, response: Response, role: str = Depends(api_key_auth)):
    if role == "full":
        try:
            return {"details": await utils.load_key_as_string(serial)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}