from fastapi import APIRouter, Depends, Response, status

import app.ca_server.utils as utils
import app.models.models as models
from app.ca_server.auth import api_key_auth

router = APIRouter()

@router.post("/test/cert", summary="Create test certificates bypassing best practices", tags=["Test certificates"])
async def create_test_cert(data: models.TestCert, response: Response, role: str = Depends(api_key_auth)):
    if role == "full":
        try:
            certificate, private_key = await utils.build_test_cert(data=data)
            if data.issuer_serial:
                issuer_serial = int(data.issuer_serial)
            else:
                issuer_serial=certificate.serial_number
            profile = models.Profile(crypto_profile_name=data.key_algorithm+"_"+data.signature_hash, entity_profile_name="malformed_cert")
            await utils.save_cert_and_key(cert=certificate, key=private_key, issuer_serial=issuer_serial, profile=profile)
            await utils.build_crl([], issuer_cert=certificate, issuer_priv_key=private_key)
            return {"serial": str(certificate.serial_number)}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"error": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
