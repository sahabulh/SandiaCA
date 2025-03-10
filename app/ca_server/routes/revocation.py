import datetime

from fastapi import APIRouter, Depends, Response, status

import app.ca_server.utils as utils
import app.models.models as models
from app.ca_server.auth import api_key_auth

from app.database.db import update

router = APIRouter()

@router.post("/revoke/{serial}", summary="Revoke certificate by serial", tags=["Revocation"])
async def revoke_cert_by_serial(serial: str, response: Response, role: str = Depends(api_key_auth)):
    if role == "full":
        try:
            cert_info = await utils.get_cert_info(serial=serial)
            if cert_info.status != 1:
                revocation_date = datetime.datetime.now(datetime.UTC)
                revocation_time = revocation_date.isoformat()
                await update(query={"serial": serial}, value={"status": 1, "revocation_time": revocation_time}, collection_name="certs")
                await utils.add_to_crl(models.RevokedCert(serial=int(serial), revocation_date=revocation_date), issuer=cert_info.issuer)
                return {"details": "The certificate has been revoked"}
            else:
                return {"details": "The certificate is already revoked"}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"details": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}
    
@router.post("/unrevoke/{serial}", summary="Unrevoke certificate by serial", tags=["Revocation"])
async def unrevoke_cert_by_serial(serial: str, response: Response, role: str = Depends(api_key_auth)):
    if role == "full":
        try:
            cert_info = await utils.get_cert_info(serial=serial)
            if cert_info.status == 1:
                await update(query={"serial": serial}, value={"status": 0, "revocation_time": None}, collection_name="certs")
                await utils.remove_from_crl(serial=int(serial), issuer=cert_info.issuer)
                return {"details": "The certificate has been unrevoked"}
            else:
                return {"details": "The certificate is already unrevoked"}
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {"details": str(err)}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error":"This is an admin end-point. You are not authorized to use it as an user."}