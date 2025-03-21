import os, datetime

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from typing import Union, Tuple, List

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent.parent)

from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure

from app.database.db import insert, find

import app.models.models as models
from app.models.enums import ValidityStart
from app.shared.utils import get_cert_info, get_profiles
from app.shared.exceptions import DBConnectionError, EntryNotFoundError

from .config import Config

def get_name(name: str, domain: str) -> x509.Name:
    config = Config()
    config = config.load()
    if not domain or domain == "":
        return x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, name),
                x509.NameAttribute(NameOID.COUNTRY_NAME, config.country_code),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.organization_name),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.organizational_unit_name),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.state_or_province_name),
            ])
    else:
        return x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, name),
                x509.NameAttribute(NameOID.COUNTRY_NAME, config.country_code),
                x509.NameAttribute(NameOID.DOMAIN_COMPONENT, domain),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.organization_name),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.organizational_unit_name),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.state_or_province_name),
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
    post = cert_info.__dict__
    post["profile"] = post["profile"].__dict__
    try:
        post_id = await insert(post, "certs")
        del post["_id"]
        return {"entry_id": str(post_id), "details": post}
    except (ServerSelectionTimeoutError, ConnectionFailure):
        raise DBConnectionError()

async def load_cert_and_key(serial: str) -> Tuple[x509.Certificate, Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]]:
    cert = load_cert(serial)
    key = await load_key(serial)
    return cert, key

def load_cert(serial: str) -> x509.Certificate:
    cert_data = load_cert_as_string(serial).encode()
    cert = load_pem_x509_certificate(cert_data)
    return cert

async def load_key(serial: str) -> Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]:
    key_data = await load_key_as_string(serial)
    key = load_pem_private_key(key_data.encode(), password=None)
    return key

def load_cert_as_string(serial: str) -> str:
    with open(abs_path+"/vault/"+serial+".pem","r") as file:
        cert = file.read()
    return cert

async def load_key_as_string(serial: str) -> str:
    query = {"serial": serial}
    try:
        cert_info = await find(query, "certs")
        if cert_info:
            key = cert_info["key"]
        else:
            raise EntryNotFoundError(id_type="serial", value=serial)
    except (ServerSelectionTimeoutError, ConnectionFailure):
        raise DBConnectionError()
    return key

async def generate_private_key(key_algorithm: str) -> Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]:
    if key_algorithm == "secp256r1":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif key_algorithm == "secp521r1":
        private_key = ec.generate_private_key(ec.SECP521R1())
    elif key_algorithm == "Ed448":
        private_key = ed448.Ed448PrivateKey.generate()
    else:
        raise NotImplementedError(f"Key algorithm {key_algorithm} is not supported.")
    return private_key

async def generate_test_private_key(key_algorithm: str) -> Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]:
    if key_algorithm == "secp256r1":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif key_algorithm == "secp521r1":
        private_key = ec.generate_private_key(ec.SECP521R1())
    elif key_algorithm == "secp192r1":
        private_key = ec.generate_private_key(ec.SECP192R1())
    elif key_algorithm == "Ed448":
        private_key = ed448.Ed448PrivateKey.generate()
    else:
        raise NotImplementedError(f"Key algorithm {key_algorithm} is not supported.")
    return private_key

async def build_cert(data: models.Cert) -> Tuple[x509.Certificate, Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]]:
    if not isinstance(data, models.RootCert):
        issuer_cert = load_cert(data.issuer_serial)
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        issuer_cert_info = await get_cert_info(serial=data.issuer_serial)
        issuer_key = load_pem_private_key(issuer_cert_info.key.encode(), password=None)
        if issuer_cert_info.status != 0:
            # As we want to bypass best practices and strict requirements to generate bad certificates for tests, errors are replaced with warnings
            # raise IssuerInvalidError("The issuer certificate is revoked and can not be used to issue new certificates.")
            print("WARNING: The issuer certificate is revoked and should not be used to issue new certificates.")
    
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

    if entity_profile.crl_url:
        builder = builder.add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(entity_profile.crl_url+"/crl/"+data.issuer_serial+".crl")],
                relative_name=None, reasons=None, crl_issuer=None
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
        else:
            raise NotImplementedError(f"Signature hash {crypto_profile.signature_hash} is not supported")
    return certificate, private_key

async def build_test_cert(data: models.TestCert) -> Tuple[x509.Certificate, Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]]:
    private_key = await generate_test_private_key(data.key_algorithm)
    public_key = private_key.public_key()
    serial = x509.random_serial_number()

    builder = x509.CertificateBuilder()
    builder = builder.serial_number(serial)
    builder = builder.public_key(public_key)
    builder = builder.subject_name(get_name(data.name, data.domain))

    if data.subject_key_identifier:
        if data.subject_key_identifier.value:
            builder = builder.add_extension(x509.SubjectKeyIdentifier(digest=bytes.fromhex(data.subject_key_identifier.value)), critical=data.subject_key_identifier.critical)
        else:
            builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key=public_key), critical=data.subject_key_identifier.critical)

    issuer_ski = None
    if not data.issuer_serial:
        data.issuer_serial = str(serial)
        issuer_key = private_key
        builder = builder.issuer_name(get_name(data.name, data.domain))
        if data.authority_key_identifier:
            if data.authority_key_identifier.value:
                issuer_ski = x509.SubjectKeyIdentifier(digest=bytes.fromhex(data.authority_key_identifier.value))
            else:
                issuer_ski = x509.SubjectKeyIdentifier.from_public_key(public_key=public_key)
    else:
        issuer_cert = load_cert(data.issuer_serial)
        issuer_cert_info = await get_cert_info(serial=data.issuer_serial)
        issuer_key = load_pem_private_key(issuer_cert_info.key.encode(), password=None)
        builder = builder.issuer_name(issuer_cert.subject)
        if data.authority_key_identifier:
            if data.authority_key_identifier.value:
                issuer_ski = x509.SubjectKeyIdentifier(digest=bytes.fromhex(data.authority_key_identifier.value))
            else:
                issuer_ski = x509.SubjectKeyIdentifier.from_public_key(public_key=issuer_key.public_key())
    
    if issuer_ski:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski), critical=data.authority_key_identifier.critical)
    
    now = datetime.datetime.now(datetime.UTC)
    if data.dates:
        if data.dates.start == ValidityStart.FUTURE:
            before = now.replace(year = now.year + 1)
        elif data.dates.start == ValidityStart.PAST:
            before = now.replace(year = now.year - 1)
        else:
            before = now
        duration = data.dates.duration
    else:
        before = now
        duration = models.Validity()
    new_year = before.year + duration.years
    after = now.replace(year = new_year)
    if (after.month + duration.months) % 12 == 0:
        new_month = 12
        new_year = after.year + (after.month + duration.months) // 12 - 1
    else:
        new_month = (after.month + duration.months) % 12
        new_year = after.year + (after.month + duration.months) // 12
    after = after.replace(year = new_year, month = new_month)
    after += datetime.timedelta(days=duration.days)
    builder = builder.not_valid_before(before)
    builder = builder.not_valid_after(after)

    extended_key_usage = []
    if data.extended_key_usage:
        if data.extended_key_usage.value == "ocsp_signing":
            extended_key_usage.append(ExtendedKeyUsageOID.OCSP_SIGNING)
        if data.extended_key_usage.value == "server_auth":
            extended_key_usage.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if data.extended_key_usage.value == "client_auth":
            extended_key_usage.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if extended_key_usage:
        builder = builder.add_extension(x509.ExtendedKeyUsage(extended_key_usage), critical=data.extended_key_usage.critical)

    if data.ocsp_url:
        builder = builder.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(data.ocsp_url.value)
            )
        ]), critical=data.ocsp_url.critical)

    if data.crl_url:
        builder = builder.add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(data.crl_url.value+"/crl/"+data.issuer_serial+".crl")],
                relative_name=None, reasons=None, crl_issuer=None
            )
        ]), critical=data.crl_url.critical)
    
    if data.basic_constraints:
        builder = builder.add_extension(x509.BasicConstraints(
            ca=data.basic_constraints.value.ca,
            path_length=data.basic_constraints.value.pathLength
        ), critical=data.basic_constraints.critical)

    if data.key_usage:
        builder = builder.add_extension(x509.KeyUsage(
            data.key_usage.value.digitalSignature,
            data.key_usage.value.nonRepudiation,
            data.key_usage.value.keyEncipherment,
            data.key_usage.value.dataEncipherment,
            data.key_usage.value.keyAgreement,
            data.key_usage.value.keyCertSign,
            data.key_usage.value.cRLSign,
            data.key_usage.value.encipherOnly,
            data.key_usage.value.decipherOnly
        ), critical=data.key_usage.critical)

    if data.key_algorithm == "Ed448":
        certificate = builder.sign(private_key=issuer_key, algorithm=None)
    else:
        if data.signature_hash == "sha256":
            certificate = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
        elif data.signature_hash == "sha512":
            certificate = builder.sign(private_key=issuer_key, algorithm=hashes.SHA512())
        else:
            raise NotImplementedError(f"Signature hash {data.signature_hash} is not supported")
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

    issuer_cert, issuer_priv_key = await load_cert_and_key(serial=issuer)

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

    issuer_cert, issuer_priv_key = await load_cert_and_key(serial=issuer)

    await build_crl(revocation_list, issuer_cert, issuer_priv_key)