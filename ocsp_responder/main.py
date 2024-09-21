#!/usr/bin/env python
import sys, datetime, base64, json
from pathlib import Path
sys.path.append(str(Path(__file__).absolute().parent.parent))

from fastapi import FastAPI, Request, Response
from cryptography.x509.ocsp import load_der_ocsp_request, OCSPCertStatus, OCSPResponseStatus
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

import utils

app = FastAPI()

@app.post("/")
async def post_method_process(request: Request):
    try:
        req_data = await request.body()
        req = load_der_ocsp_request(req_data)
        res = await get_response(req)
    except:
        res = cert_status(OCSPResponseStatus.MALFORMED_REQUEST)
    return Response(content=res, media_type="application/ocsp-response")

@app.get("/{full_path:path}")
async def get_method_process(full_path: str):
    try:
        req_data = base64.b64decode(full_path)
        req = load_der_ocsp_request(req_data)
        res = await get_response(req)
    except Exception as err:
        print(f"{type(err).__name__}: {err.args}")
        res = cert_status(OCSPResponseStatus.MALFORMED_REQUEST)
    return Response(content=res, media_type="application/ocsp-response")

async def get_response(req: ocsp.OCSPRequest):
    target_serial = str(req.serial_number)

    builder = ocsp.OCSPResponseBuilder()
    
    try:
        with open("../cert_db.json","r") as file:
            cert_db = json.load(file)
        with open("../ocsp_db.json","r") as file:
            ocsp_db = json.load(file)
        issuer_serial = str(cert_db[target_serial]["issuer"])
        ocsp_serial = str(ocsp_db[issuer_serial])
        target_cert = await utils.load_cert(target_serial)
        issuer_cert = await utils.load_cert(issuer_serial)
        responder_cert, responder_key = await utils.load_cert_and_key(ocsp_serial)
        if cert_db[target_serial]["revocation_time"]:
            revocation_time = datetime.datetime.fromisoformat(cert_db[target_serial]["revocation_time"])
        else:
            revocation_time = None
        
        builder = builder.add_response(
            cert=target_cert, issuer=issuer_cert, algorithm=req.hash_algorithm,
            cert_status=OCSPCertStatus(cert_db[target_serial]["status"]),
            this_update=datetime.datetime.now(),
            next_update=datetime.datetime.now() + datetime.timedelta(1,0,0),
            revocation_time=revocation_time, revocation_reason=None
        ).certificates(
            certs = [responder_cert]
        ).responder_id(
            ocsp.OCSPResponderEncoding.HASH, responder_cert
        )
        response = builder.sign(responder_key, hashes.SHA256())
        res = response.public_bytes(encoding=serialization.Encoding.DER)
    except KeyError:
        res = cert_status(OCSPResponseStatus.UNAUTHORIZED)
    except Exception as err:
        print(f"{type(err).__name__}: {err.args}")
        res = cert_status(OCSPResponseStatus.INTERNAL_ERROR)
    finally:
        return res
    
def cert_status(status: OCSPResponseStatus) -> bytes:
    response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        response_status=status
    )
    res = response.public_bytes(encoding=serialization.Encoding.DER)
    return res