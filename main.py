#!/usr/bin/env python
from fastapi import FastAPI, Request, Response
from cryptography.x509.ocsp import load_der_ocsp_request
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate, ocsp

app = FastAPI()
        
# @app.post("/")
# async def print_request(request: Request):
#     reqData = await request.body()
#     req = load_der_ocsp_request(reqData)

#     with open("root.pem","r") as file:
#         pem_issuer = file.read().encode()
#     with open("subca1.pem","r") as file:
#         pem_cert = file.read().encode()
#     with open("root.pem","r") as file:
#         pem_responder_cert = file.read().encode()
#     with open("root.key","r") as file:
#         pem_responder_key = file.read().encode()

#     cert = load_pem_x509_certificate(pem_cert)
#     issuer = load_pem_x509_certificate(pem_issuer)
#     responder_cert = load_pem_x509_certificate(pem_responder_cert)
#     responder_key = serialization.load_pem_private_key(pem_responder_key, None)
#     builder = ocsp.OCSPResponseBuilder()
#     # SHA256 is in this example because while RFC 5019 originally
#     # required SHA1 RFC 6960 updates that to SHA256.
#     # However, depending on your requirements you may need to use SHA1
#     # for compatibility reasons.
#     builder = builder.add_response(
#         cert=cert, issuer=issuer, algorithm=hashes.SHA256(),
#         cert_status=ocsp.OCSPCertStatus.GOOD,
#         this_update=datetime.datetime.now(),
#         next_update=datetime.datetime.now() + datetime.timedelta(1,0,0),
#         revocation_time=None, revocation_reason=None
#     ).responder_id(
#         ocsp.OCSPResponderEncoding.HASH, responder_cert
#     )
#     response = builder.sign(responder_key, hashes.SHA256())
#     res = response.public_bytes(encoding=serialization.Encoding.DER)
#     return Response(content=res, media_type="application/ocsp-response")

@app.post("/")
async def print_request(request: Request):
    reqData = await request.body()
    req = load_der_ocsp_request(reqData)

    with open("root.pem","r") as file:
        pem_issuer = file.read().encode()
    with open("subca1.pem","r") as file:
        pem_cert = file.read().encode()
    with open("ocsp.pem","r") as file:
        pem_responder_cert = file.read().encode()
    with open("ocsp.key","r") as file:
        pem_responder_key = file.read().encode()

    cert = load_pem_x509_certificate(pem_cert)
    issuer = load_pem_x509_certificate(pem_issuer)
    responder_cert = load_pem_x509_certificate(pem_responder_cert)
    responder_key = serialization.load_pem_private_key(pem_responder_key, None)
    builder = ocsp.OCSPResponseBuilder()
    # SHA256 is in this example because while RFC 5019 originally
    # required SHA1 RFC 6960 updates that to SHA256.
    # However, depending on your requirements you may need to use SHA1
    # for compatibility reasons.
    builder = builder.add_response(
        cert=cert, issuer=issuer, algorithm=hashes.SHA256(),
        cert_status=ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.now(),
        next_update=datetime.datetime.now() + datetime.timedelta(1,0,0),
        revocation_time=None, revocation_reason=None
    ).certificates(
        certs = [responder_cert]
    ).responder_id(
        ocsp.OCSPResponderEncoding.HASH, responder_cert
    )
    response = builder.sign(responder_key, hashes.SHA256())
    res = response.public_bytes(encoding=serialization.Encoding.DER)
    return Response(content=res, media_type="application/ocsp-response")