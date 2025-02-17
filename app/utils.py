import os, datetime

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from typing import Union, Tuple, List

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent)

from pymongo import ReturnDocument
from pymongo.database import Database
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure

import models.models as models
from exceptions import DBConnectionError, EntryNotFoundError, IssuerInvalidError

# Define the database variable
sandia_ca = None

def get_name(name: str, domain: str) -> x509.Name:
    return x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, domain),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Sandia National Labs'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Electric Vehicles'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'New Mexico'),
        ])

async def save_cert_and_key(cert: x509.Certificate, key: Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey], issuer_serial: int, profile: models.Profile):
    if not os.path.exists(abs_path+"/vault/"):
        os.makedirs(abs_path+"/vault/", exist_ok=True)
    cert_data = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
    with open(abs_path+"/vault/"+str(cert.serial_number)+".pem","w") as file:
        file.write(cert_data)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key_data = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
    else:
        key_data = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
    cert_info = models.CertInfo(serial=str(cert.serial_number), key=key_data, issuer=str(issuer_serial), status=0, profile=profile)
    certs = sandia_ca.certs
    post = cert_info.__dict__
    post["profile"] = post["profile"].__dict__
    try:
        post_id = certs.insert_one(post).inserted_id
        del post["_id"]
        return {"entry_id": str(post_id), "details": post}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        raise DBConnectionError()

def load_cert_and_key(serial: str) -> Tuple[x509.Certificate, Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]]:
    cert = load_cert(serial)
    key = load_key(serial)
    return cert, key

def load_cert(serial: str) -> x509.Certificate:
    cert_data = load_cert_as_string(serial).encode()
    cert = load_pem_x509_certificate(cert_data)
    return cert

def load_key(serial: str) -> Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]:
    key_data = load_key_as_string(serial).encode()
    key = load_pem_private_key(key_data, password=None)
    return key

def load_cert_as_string(serial: str) -> str:
    with open(abs_path+"/vault/"+serial+".pem","r") as file:
        cert = file.read()
    return cert

def load_key_as_string(serial: str) -> str:
    certs = sandia_ca.certs
    query = {"serial": serial}
    try:
        cert_info = certs.find_one(query)
        if cert_info:
            key = cert_info["key"]
        else:
            raise EntryNotFoundError(id_type="serial", value=serial)
    except (ServerSelectionTimeoutError, ConnectionFailure):
        raise DBConnectionError()
    return key

async def get_profile(type: str, name: str) -> dict:
    if type == "crypto":
        profiles = sandia_ca.crypto_profiles
    elif type == "entity":
        profiles = sandia_ca.entity_profiles
    query = {"name": name}
    try:
        profile = profiles.find_one(query, projection={'_id': False})
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
    certs = sandia_ca.certs
    query = {"serial": serial}
    try:
        cert_info = certs.find_one(query, projection={'_id': False})
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
    
async def update(query: dict, value: dict, collection_name: str):
    collection = sandia_ca[collection_name]
    return collection.find_one_and_update(query, {'$set': value}, projection={'_id': False}, return_document = ReturnDocument.AFTER)

async def generate_private_key(key_algorithm: str) -> Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]:
    if key_algorithm == "secp256r1":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif key_algorithm == "secp521r1":
        private_key = ec.generate_private_key(ec.SECP521R1())
    elif key_algorithm == "Ed448":
        private_key = ed448.Ed448PrivateKey.generate()
    else:
        raise NotImplementedError("Key algorithms except secp256r1, secp512r1 and Ed448 are not yet supported.")
    return private_key

async def build_cert(data: models.Cert) -> Tuple[x509.Certificate, Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]]:
    if not isinstance(data, models.RootCert):
        issuer_cert = load_cert(data.issuer_serial)
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        issuer_cert_info = await get_cert_info(serial=data.issuer_serial)
        issuer_key = load_pem_private_key(issuer_cert_info.key.encode(), password=None)
        if issuer_cert_info.status != 0:
            raise IssuerInvalidError("The issuer certificate is revoked and can't be used to issue new certificates.")
    
    if not data.profile.crypto_profile_name:
        data.profile.crypto_profile_name = issuer_cert_info.profile.crypto_profile_name
    
    crypto_profile, entity_profile = await get_profiles(data.profile)
    private_key = await generate_private_key(crypto_profile.key_algorithm)
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()

    if isinstance(data, models.RootCert):
        issuer_key = private_key
        builder = builder.subject_name(get_name(data.domain+' ROOT CA', data.domain))
        builder = builder.issuer_name(get_name(data.domain+' ROOT CA', data.domain))
    else:
        if isinstance(data, models.SubCACert):
            builder = builder.subject_name(get_name(name=data.domain+' SubCA '+str(data.tier), domain=data.domain))
        elif isinstance(data, models.OCSPCert):
            issuer_name = issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            builder = builder.subject_name(get_name(name='OCSP '+issuer_name, domain=data.domain))
        elif isinstance(data, models.LeafCert):
            builder = builder.subject_name(get_name(name=data.name, domain=data.domain))
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value), critical=False)
        builder = builder.add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://localhost:8000/crl/"+data.issuer_serial+".crl")],
                relative_name=None, reasons=None, crl_issuer=None
            )]), critical=False)

    extended_key_usage = []
    if entity_profile.extended_key_usage:
        if "ocsp_signing" in entity_profile.extended_key_usage:
            extended_key_usage.append(ExtendedKeyUsageOID.OCSP_SIGNING)
        if "server_auth" in entity_profile.extended_key_usage:
            extended_key_usage.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if "client_auth" in entity_profile.extended_key_usage:
            extended_key_usage.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if extended_key_usage:
        builder = builder.add_extension(x509.ExtendedKeyUsage(extended_key_usage), critical=True)

    if entity_profile.ocsp_url:
        builder = builder.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(entity_profile.ocsp_url)
            )
        ]), critical=False)
    
    now = datetime.datetime.now(datetime.UTC)
    new_year = now.year + entity_profile.validity.years
    validity = now.replace(year = new_year)
    if (validity.month + entity_profile.validity.months) % 12 == 0:
        new_month = 12
        new_year = validity.year + (validity.month + entity_profile.validity.months) // 12 - 1
    else:
        new_month = (validity.month + entity_profile.validity.months) % 12
        new_year = validity.year + (validity.month + entity_profile.validity.months) // 12
    validity = validity.replace(year = new_year, month = new_month)
    validity += datetime.timedelta(days=entity_profile.validity.days)

    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(validity)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.BasicConstraints(
        ca=entity_profile.basic_constraints.ca,
        path_length=entity_profile.basic_constraints.pathLength
    ), critical=True)
    builder = builder.add_extension(x509.KeyUsage(
        entity_profile.key_usage.digitalSignature,
        entity_profile.key_usage.nonRepudiation,
        entity_profile.key_usage.keyEncipherment,
        entity_profile.key_usage.dataEncipherment,
        entity_profile.key_usage.keyAgreement,
        entity_profile.key_usage.keyCertSign,
        entity_profile.key_usage.cRLSign,
        entity_profile.key_usage.encipherOnly,
        entity_profile.key_usage.decipherOnly
    ), critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key=public_key), critical=False)
    if crypto_profile.key_algorithm == "Ed448":
        certificate = builder.sign(private_key=issuer_key, algorithm=None)
    else:
        if crypto_profile.signature_hash == "sha256":
            certificate = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
        elif crypto_profile.signature_hash == "sha512":
            certificate = builder.sign(private_key=issuer_key, algorithm=hashes.SHA512())
    return certificate, private_key

async def build_crl(revocation_list: List[models.RevokedCert],
                    issuer_cert: x509.Certificate,
                    issuer_priv_key: Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]):
    now = datetime.datetime.now(datetime.UTC)
    one_day = datetime.timedelta(1, 0, 0)
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + one_day)

    for revoked_cert_info in revocation_list:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            revoked_cert_info.serial
        ).revocation_date(
            revoked_cert_info.revocation_date
        ).build()
        builder = builder.add_revoked_certificate(revoked_cert)
    
    #TODO: Get hash from private key and use the same hash for signing CRL
    if isinstance(issuer_priv_key, ed448.Ed448PrivateKey):
        crl = builder.sign(private_key=issuer_priv_key, algorithm=None)
    else:
        crl = builder.sign(private_key=issuer_priv_key, algorithm=hashes.SHA256())

    if not os.path.exists(abs_path+"/crl/"):
        os.makedirs(abs_path+"/crl/", exist_ok=True)

    crl_data = crl.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
    with open(abs_path+"/crl/"+str(issuer_cert.serial_number)+".crl","w") as file:
        file.write(crl_data)

async def add_to_crl(revoked_cert: models.RevokedCert, issuer: str):
    with open(abs_path+"/crl/"+str(issuer)+".crl","r") as file:
        crl_data = file.read().encode()
        crl = x509.load_pem_x509_crl(crl_data)
    
    revocation_list = []
    for old_revoked_cert in crl:
        revocation_list.append(models.RevokedCert(serial=old_revoked_cert.serial_number,
                                                  revocation_date=old_revoked_cert.revocation_date_utc))
    
    revocation_list.append(revoked_cert)

    issuer_cert, issuer_priv_key = load_cert_and_key(serial=issuer)

    await build_crl(revocation_list, issuer_cert, issuer_priv_key)

async def remove_from_crl(serial: int, issuer: str):
    with open(abs_path+"/crl/"+str(issuer)+".crl","r") as file:
        crl_data = file.read().encode()
        crl = x509.load_pem_x509_crl(crl_data)
    
    revocation_list = []
    for old_revoked_cert in crl:
        print(old_revoked_cert.serial_number, end = " ")
        print(serial, end = " ")
        print(old_revoked_cert.serial_number == serial)
        if old_revoked_cert.serial_number != serial:
            revocation_list.append(models.RevokedCert(serial=old_revoked_cert.serial_number,
                                                      revocation_date=old_revoked_cert.revocation_date_utc))

    issuer_cert, issuer_priv_key = load_cert_and_key(serial=issuer)

    await build_crl(revocation_list, issuer_cert, issuer_priv_key)

async def load_db(db: Database):
    global sandia_ca
    sandia_ca = db

async def unload_db(db: Database):
    global sandia_ca
    sandia_ca = None