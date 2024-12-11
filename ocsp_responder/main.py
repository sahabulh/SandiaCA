#!/usr/bin/env python
import sys, datetime, base64, json
from pathlib import Path
sys.path.append(str(Path(__file__).absolute().parent.parent))

from fastapi import FastAPI, Request, Response

from cryptography.x509 import ocsp
from cryptography.x509.ocsp import load_der_ocsp_request, OCSPCertStatus, OCSPResponseStatus
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from contextlib import asynccontextmanager

from pymongo import MongoClient

import utils
from exceptions import SHA1Error, WrongIssuerError, ResponseNotAllowedError, EntryNotFoundError

# Define the database variable
sandia_ca = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global sandia_ca
    # Connect to MongoDB
    mongodb_client = MongoClient("mongodb://root:example@mongo",27017, serverSelectionTimeoutMS=10, connectTimeoutMS=1000)
    sandia_ca = mongodb_client.sandia_ca
    await utils.load_db(sandia_ca)
    yield
    # Disconnect from MongoDB
    mongodb_client.close()

app = FastAPI(lifespan=lifespan)

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
        except EntryNotFoundError:
            raise ResponseNotAllowedError("Information not available in the database. This might mean that the responder is not authorized to send a response for this certificate.")
        
        target_cert = utils.load_cert(target_serial)
        issuer_cert = utils.load_cert(issuer_serial)

        req_builder = ocsp.OCSPRequestBuilder()
        req_builder = req_builder.add_certificate(target_cert, issuer_cert, req.hash_algorithm)
        target_req = req_builder.build()

        if req.issuer_key_hash != target_req.issuer_key_hash or req.issuer_name_hash != target_req.issuer_name_hash:
            raise WrongIssuerError()

        responder_cert, responder_key = utils.load_cert_and_key(ocsp_serial)
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
