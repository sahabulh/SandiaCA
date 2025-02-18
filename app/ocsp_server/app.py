#!/usr/bin/env python
import sys, datetime, base64, requests
from pathlib import Path
sys.path.append(str(Path(__file__).absolute().parent.parent))

from fastapi import FastAPI, Request, Response

from cryptography.x509 import ocsp, load_pem_x509_certificate
from cryptography.x509.ocsp import load_der_ocsp_request, OCSPCertStatus, OCSPResponseStatus
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import utils
from database.db import connect_and_init_db, close_db
from exceptions import SHA1Error, WrongIssuerError, ResponseNotAllowedError, EntryNotFoundError

ca_url = "http://ca:8000/"
headers = {
    'accept':       'application/json',
    'X-API-KEY':    'iamadmin',
    'Content-Type': 'application/json',
}

app = FastAPI()

app.add_event_handler("startup", connect_and_init_db)
app.add_event_handler("shutdown", close_db)

@app.post("/")
async def post_method_process(request: Request):
    try:
        req_data = await request.body()
        req = load_der_ocsp_request(req_data)
        res = await get_response(req)
    except Exception as err:
        res = bad_status(err, OCSPResponseStatus.MALFORMED_REQUEST)
    return Response(content=res, media_type="application/ocsp-response")

@app.get("/{full_path:path}")
async def get_method_process(full_path: str):
    try:
        req_data = base64.b64decode(full_path)
        req = load_der_ocsp_request(req_data)
        res = await get_response(req)
    except Exception as err:
        res = bad_status(err, OCSPResponseStatus.MALFORMED_REQUEST)
    return Response(content=res, media_type="application/ocsp-response")

async def get_response(req: ocsp.OCSPRequest):
    target_serial = str(req.serial_number)
    builder = ocsp.OCSPResponseBuilder()

    try:
        try:
            target_cert_info = await utils.get_cert_info(serial=target_serial)
            issuer_serial = target_cert_info.issuer
            issuer_cert_info = await utils.get_cert_info(serial=issuer_serial)
            ocsp_serial = issuer_cert_info.responder
            if not ocsp_serial:
                raise ResponseNotAllowedError("Information about the responder is not available.")
        except EntryNotFoundError:
            raise ResponseNotAllowedError("Information not available in the database. This might mean that the responder is not authorized to send a response for this certificate.")
        
        r = requests.get(ca_url+"cert/"+target_serial, headers=headers)
        target_cert = load_pem_x509_certificate(r.json()["details"].encode())
        r = requests.get(ca_url+"cert/"+issuer_serial, headers=headers)
        issuer_cert = load_pem_x509_certificate(r.json()["details"].encode())

        req_builder = ocsp.OCSPRequestBuilder()
        req_builder = req_builder.add_certificate(target_cert, issuer_cert, req.hash_algorithm)
        target_req = req_builder.build()

        if req.issuer_key_hash != target_req.issuer_key_hash or req.issuer_name_hash != target_req.issuer_name_hash:
            raise WrongIssuerError()

        r = requests.get(ca_url+"cert/"+ocsp_serial, headers=headers)
        responder_cert = load_pem_x509_certificate(r.json()["details"].encode())
        r = requests.get(ca_url+"key/"+ocsp_serial, headers=headers)
        responder_key = serialization.load_pem_private_key(r.json()["details"].encode(), password=None)
        if target_cert_info.revocation_time:
            revocation_time = datetime.datetime.fromisoformat(target_cert_info.revocation_time)
        else:
            revocation_time = None
        
        builder = builder.add_response(
            cert=target_cert, issuer=issuer_cert, algorithm=req.hash_algorithm,
            cert_status=OCSPCertStatus(target_cert_info.status),
            this_update=datetime.datetime.now(),
            next_update=datetime.datetime.now() + datetime.timedelta(1,0,0),
            revocation_time=revocation_time, revocation_reason=None
        ).certificates(
            certs = [responder_cert]
        ).responder_id(
            ocsp.OCSPResponderEncoding.HASH, responder_cert
        )
        if isinstance(responder_key, ec.EllipticCurvePrivateKey):
            response = builder.sign(responder_key, hashes.SHA256())
        else:
            response = builder.sign(responder_key, None)
        res = response.public_bytes(encoding=serialization.Encoding.DER)
    except (ResponseNotAllowedError, SHA1Error, WrongIssuerError) as err:
        res = bad_status(err, OCSPResponseStatus.UNAUTHORIZED)
    except Exception as err:
        res = bad_status(err, OCSPResponseStatus.INTERNAL_ERROR)
    finally:
        return res
    
def bad_status(err: Exception, status: OCSPResponseStatus) -> bytes:
    print(f"{type(err).__name__}: {err}")
    response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        response_status=status
    )
    res = response.public_bytes(encoding=serialization.Encoding.DER)
    return res
