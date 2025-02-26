from typing import Union, Tuple
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure

import models.models as models
from database.db import find
from shared.exceptions import DBConnectionError, EntryNotFoundError

async def get_profile(type: str, name: str) -> dict:
    query = {"name": name}
    try:
        profile = await find(query, type+"_profiles")
        if profile:
            return profile
        else:
            raise EntryNotFoundError(id_type="name", value=name)
    except (ServerSelectionTimeoutError, ConnectionFailure):
        raise DBConnectionError()
    
async def get_profiles(profile: models.Profile) -> Tuple[Union[models.CryptoProfile, None], models.EntityProfile]:
    if profile.crypto_profile_name:
        crypto_profile = await get_profile(type="crypto", name=profile.crypto_profile_name)
        crypto_profile = models.CryptoProfile(**crypto_profile)
    else:
        crypto_profile = None
    entity_profile = await get_profile(type="entity", name=profile.entity_profile_name)
    entity_profile = models.EntityProfile(**entity_profile)
    return crypto_profile, entity_profile

async def get_cert_info(serial: str) -> models.CertInfo:
    query = {"serial": serial}
    try:
        cert_info = await find(query, "certs")
        if cert_info:
            return models.CertInfo(**cert_info)
        else:
            raise EntryNotFoundError(id_type="serial", value=serial)
    except (ServerSelectionTimeoutError, ConnectionFailure):
        raise DBConnectionError()

# TODO: Add support for one SubCA case  
async def get_chain_serial_for_leaf(leaf_serial: str) -> dict:
    leaf_cert_info = await get_cert_info(leaf_serial)
    subca2_cert_info = await get_cert_info(leaf_cert_info.issuer)
    subca1_cert_info = await get_cert_info(subca2_cert_info.issuer)
    root_cert_info = await get_cert_info(subca1_cert_info.issuer)
    return {
        "ROOT": root_cert_info.serial,
        "SUBCA1": subca1_cert_info.serial,
        "SUBCA2": subca2_cert_info.serial,
        "LEAF": leaf_serial
    }