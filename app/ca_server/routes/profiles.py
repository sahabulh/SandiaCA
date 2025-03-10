from fastapi import APIRouter, Depends, Response, status

import app.ca_server.utils as utils
import app.models.models as models
from app.ca_server.auth import api_key_auth

from app.shared.exceptions import EntryNotFoundError
from app.shared.utils import get_profile

from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure

from app.database.db import insert, update

router = APIRouter()

@router.post("/profile/crypto", summary="Create a cryptographic profile", tags=["Profile"])
async def create_crypto(profile: models.CryptoProfileCreate, response: Response, role: str = Depends(api_key_auth)):
    post = {"name": profile.name, "key_algorithm": profile.key_algorithm, "signature_hash": profile.signature_hash}
    try:
        post_id = await insert(post, "crypto_profiles")
        del post["_id"]
        return {"entry_id": str(post_id), "details": post}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": "Failed to connect to MongoDB server"}

@router.get("/profile/crypto/{profile_name}", summary="Get a cryptographic profile by name", tags=["Profile"])
async def get_crypto(profile_name: str, response: Response, role: str = Depends(api_key_auth)):
    try:
        return await get_profile(type="crypto", name=profile_name)
    except EntryNotFoundError as err:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"error": str(err)}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}
    
@router.put("/profile/crypto/{profile_name}", summary="Update a cryptographic profile by name", tags=["Profile"])
async def update_crypto(profile_name: str, profile: models.CryptoProfile, response: Response, role: str = Depends(api_key_auth)):
    try:
        profile_dict = profile.model_dump(exclude_unset=True)
        updated_doc = await update(query={"name": profile_name}, value=profile_dict, collection_name="crypto_profiles")
        if updated_doc:
            return {"details": updated_doc}
        else:
            raise EntryNotFoundError(id_type="name", value=profile_name)
    except EntryNotFoundError as err:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"error": str(err)}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}
    
@router.post("/profile/entity", summary="Create an entity profile", tags=["Profile"])
async def create_entity(profile: models.EntityProfileCreate, response: Response, role: str = Depends(api_key_auth)):
    post = profile.__dict__
    try:
        post_id = await insert(post, "entity_profiles")
        del post["_id"]
        return {"entry_id": str(post_id), "details": post}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": "Failed to connect to MongoDB server"}

@router.get("/profile/entity/{profile_name}", summary="Get an entity profile by name", tags=["Profile"])
async def get_entity(profile_name: str, response: Response, role: str = Depends(api_key_auth)):
    try:
        return await get_profile(type="entity", name=profile_name)
    except EntryNotFoundError as err:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"error": str(err)}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}
    
@router.put("/profile/entity/{profile_name}", summary="Update an entity profile by name", tags=["Profile"])
async def update_entity(profile_name: str, profile: models.EntityProfile, response: Response, role: str = Depends(api_key_auth)):
    try:
        profile_dict = profile.model_dump(exclude_unset=True)
        updated_doc = await update(query={"name": profile_name}, value=profile_dict, collection_name="entity_profiles")
        if updated_doc:
            return {"details": updated_doc}
        else:
            raise EntryNotFoundError(id_type="name", value=profile_name)
    except EntryNotFoundError as err:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"error": str(err)}
    except Exception as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"error": str(err)}