#!/usr/bin/env python
from pathlib import Path

from fastapi import FastAPI, Depends, Response, status
from fastapi.responses import FileResponse

from app.shared.exceptions import ResourceNotFoundError

from app.ca_server.routes.certificates import router as cert_router
from app.ca_server.routes.revocation import router as revoke_router
from app.ca_server.routes.profiles import router as profile_router
from app.ca_server.routes.malformed import router as test_router

from app.database.db import connect_and_init_db, close_db

app = FastAPI()

app.include_router(cert_router)
app.include_router(revoke_router)
app.include_router(profile_router)
app.include_router(test_router)

app.add_event_handler("startup", connect_and_init_db)
app.add_event_handler("shutdown", close_db)
    
@app.get("/crl/{filename}", summary="Download CRL file", tags=["Downloads"])
async def download_crl(filename: str, response: Response):
    try:
        base_path = str(Path(__file__).absolute().parent.parent)
        file = Path(base_path + "/crl/" + filename)
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