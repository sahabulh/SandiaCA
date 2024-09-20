#!/usr/bin/env python
import sys, datetime, base64
from pathlib import Path
sys.path.append(str(Path(__file__).absolute().parent.parent))

from fastapi import FastAPI, Request, Response
from cryptography.x509.ocsp import load_der_ocsp_request, OCSPCertStatus, OCSPResponseStatus
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate, ocsp

import utils

app = FastAPI()

@app.post("/")
async def post_method_process(request: Request):
    try:
        req_data = await request.body()
        req = load_der_ocsp_request(req_data)
        res = await get_response(req)
        return Response(content=res, media_type="application/ocsp-response")
    except:
        response = ocsp.OCSPResponseBuilder.build_unsuccessful(
            response_status=OCSPResponseStatus.MALFORMED_REQUEST
        )
        res = response.public_bytes(encoding=serialization.Encoding.DER)
        return res

@app.get("/{full_path:path}")
async def get_method_process(full_path: str):
    try:
        req_data = base64.b64decode(full_path)
        req = load_der_ocsp_request(req_data)
        res = await get_response(req)
        return Response(content=res, media_type="application/ocsp-response")
    except:
        response = ocsp.OCSPResponseBuilder.build_unsuccessful(
            response_status=OCSPResponseStatus.MALFORMED_REQUEST
        )
        res = response.public_bytes(encoding=serialization.Encoding.DER)
        return res

async def get_response(req: ocsp.OCSPRequest):
    target_serial = str(req.serial_number)

    cert_db = {
        "561701649493570780787482249804312571274040861525": {
            "issuer": "69209529157338116039252351700117378586588815973", "status": OCSPCertStatus.GOOD
        },
        "389508052321321231067569383502957568726385089613": {
            "issuer": "69209529157338116039252351700117378586588815973", "status": OCSPCertStatus.GOOD
        },
        "690313673106402814742737005971587091061095654995": {
            "issuer": "69209529157338116039252351700117378586588815973", "status": OCSPCertStatus.GOOD
        },
        "581630872413036450974836315753860275504974935158": {
            "issuer": "561701649493570780787482249804312571274040861525", "status": OCSPCertStatus.GOOD
        },
        "128556349660193405357182079178126112038514604970": {
            "issuer": "389508052321321231067569383502957568726385089613", "status": OCSPCertStatus.GOOD
        },
        "658996003604651521483986334700486280164753882559": {
            "issuer": "690313673106402814742737005971587091061095654995", "status": OCSPCertStatus.GOOD
        },
        "374617140707097836686052571009661348878180924238":{
            "issuer": "581630872413036450974836315753860275504974935158", "status": OCSPCertStatus.GOOD
        },
        "296194067679946149034109232930999221584174531521":{
            "issuer": "581630872413036450974836315753860275504974935158", "status": OCSPCertStatus.GOOD
        },
        "619397267564651281466950675672152490811542760994":{
            "issuer": "128556349660193405357182079178126112038514604970", "status": OCSPCertStatus.GOOD
        },
        "624488486153779385012898618052261053952745460311":{
            "issuer": "658996003604651521483986334700486280164753882559", "status": OCSPCertStatus.GOOD
        },
        "373304069203686263112032072910449946790994875326":{
            "issuer": "69209529157338116039252351700117378586588815973", "status": OCSPCertStatus.GOOD
        },
        "566591043559320403425012530516490216268664725918":{
            "issuer": "373304069203686263112032072910449946790994875326", "status": OCSPCertStatus.GOOD
        },
        "701533419137984456677667550840201066948765340390":{
            "issuer": "69209529157338116039252351700117378586588815973", "status": OCSPCertStatus.GOOD
        },
        "642027254343517846020644926428544681955124579176":{
            "issuer": "701533419137984456677667550840201066948765340390", "status": OCSPCertStatus.GOOD
        },
        "454446033521019253649963954762034922134910170419":{
            "issuer": "69209529157338116039252351700117378586588815973", "status": OCSPCertStatus.GOOD
        },
        "538847279514479163941697216058505528318000845584":{
            "issuer": "454446033521019253649963954762034922134910170419", "status": OCSPCertStatus.GOOD
        },
        "547679598800635087099671454293219579124887904666":{
            "issuer": "538847279514479163941697216058505528318000845584", "status": OCSPCertStatus.GOOD
        },
        "520937790916359686847353583789754844938908729302":{
            "issuer": "642027254343517846020644926428544681955124579176", "status": OCSPCertStatus.GOOD
        },
        "279376602087796469417693740046258382731804211775":{
            "issuer": "566591043559320403425012530516490216268664725918", "status": OCSPCertStatus.GOOD
        },
        "167119368555070031495277023117829477397300998023":{
            "issuer": "566591043559320403425012530516490216268664725918", "status": OCSPCertStatus.GOOD
        }
    }

    ocsp_db = {
        "69209529157338116039252351700117378586588815973": "333374691794672534085673823042433262207170052506",
        "373304069203686263112032072910449946790994875326": "394066176157673464004936138546125423417451157424",
        "566591043559320403425012530516490216268664725918": "366656474897724910837458024286802260535128069362",
        "701533419137984456677667550840201066948765340390": "574098456380946583451969446721621864721440784836",
        "642027254343517846020644926428544681955124579176": "467480953831025684276580163212158818658177352438",
        "454446033521019253649963954762034922134910170419": "481072577847742077109167227590019375019946250309",
        "538847279514479163941697216058505528318000845584": "683148005486050505256066667800790466146824582291"
    }

    builder = ocsp.OCSPResponseBuilder()
    
    try:
        issuer_serial = cert_db[target_serial]["issuer"]
        ocsp_serial = ocsp_db[issuer_serial]
        target_cert = await utils.load_cert(target_serial)
        issuer_cert = await utils.load_cert(issuer_serial)
        responder_cert, responder_key = await utils.load_cert_and_key(ocsp_serial)
        
        builder = builder.add_response(
            cert=target_cert, issuer=issuer_cert, algorithm=req.hash_algorithm,
            cert_status=cert_db[target_serial]["status"],
            this_update=datetime.datetime.now(),
            next_update=datetime.datetime.now() + datetime.timedelta(1,0,0),
            revocation_time=None, revocation_reason=None
        ).certificates(
            certs = [responder_cert]
        ).responder_id(
            ocsp.OCSPResponderEncoding.HASH, responder_cert
        )
        response = builder.sign(responder_key, hashes.SHA256())
    except (FileNotFoundError, KeyError):
        response = builder.build_unsuccessful(
            response_status=OCSPResponseStatus.UNAUTHORIZED
        )
    except Exception as err:
        print(f"{type(err).__name__}: {err.args}")
        response = builder.build_unsuccessful(
            response_status=OCSPResponseStatus.INTERNAL_ERROR
        )
    finally:
        res = response.public_bytes(encoding=serialization.Encoding.DER)
        return res