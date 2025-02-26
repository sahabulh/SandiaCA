#!/usr/bin/env python
from pathlib import Path

from fastapi import FastAPI, Depends, Response, status
from fastapi.responses import FileResponse

from ca_server.auth import api_key_auth
from shared.exceptions import ResourceNotFoundError

from routes.certificates import router as cert_router
from routes.revocation import router as revoke_router
from routes.profiles import router as profile_router

from database.db import connect_and_init_db, close_db

app = FastAPI()

app.include_router(cert_router)
app.include_router(revoke_router)
app.include_router(profile_router)

app.add_event_handler("startup", connect_and_init_db)
app.add_event_handler("shutdown", close_db)
    
@app.get("/crl/{filename}", summary="Download CRL file", tags=["Downloads"])
async def download_crl(filename: str, response: Response, role: str = Depends(api_key_auth)):
    try:
        print(str(Path(__file__).absolute()))
        file = Path("../crl/" + filename)
        if file.is_file():
            return FileResponse(file)
        else:
            raise ResourceNotFoundError(path=filename)
    except ResourceNotFoundError as err:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"error": str(err)}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}