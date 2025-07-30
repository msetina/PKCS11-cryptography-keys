from enum import Enum
from logging import getLogger

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.x509 import (
    Certificate,
    DirectoryName,
    DNSName,
    ExtendedKeyUsage,
    ExtensionNotFound,
    IPAddress,
    KeyUsage,
    OtherName,
    RegisteredID,
    RFC822Name,
    SubjectAlternativeName,
    UniformResourceIdentifier,
    load_der_x509_certificate,
)
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    ObjectIdentifier,
    PublicKeyAlgorithmOID,
)
from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_LABEL,
    CKA_VALUE,
    CKF_SERIAL_SESSION,
    CKO_CERTIFICATE,
    PyKCS11Lib,
)

from ..card_token.PKCS11_key_definition import (
    KeyTypes,
    PKCS11KeyUsage,
    PKCS11KeyUsageAll,
)


class X509ExtendedKeyUsage(ExtendedKeyUsageOID, Enum):
    client_auth = ExtendedKeyUsageOID.CLIENT_AUTH
    server_auth = ExtendedKeyUsageOID.SERVER_AUTH
    code_sign = ExtendedKeyUsageOID.CODE_SIGNING
    ocsp_sign = ExtendedKeyUsageOID.OCSP_SIGNING
    email_protect = ExtendedKeyUsageOID.EMAIL_PROTECTION
    sc_logon = ExtendedKeyUsageOID.SMARTCARD_LOGON
    ipsec_ike = ExtendedKeyUsageOID.IPSEC_IKE
    certificate_transparency = ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY
    kerberos_pkinit_kdc = ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC
    time_stamping = ExtendedKeyUsageOID.TIME_STAMPING
    any = ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE


class X506KeyUsage(str, Enum):
    digital_signature = "digital_signature"
    content_commitment = "content_commitment"
    crl_sign = "crl_sign"
    key_cert_sign = "key_cert_sign"
    data_encipherment = "data_encipherment"
    key_agreement = "key_agreement"
    key_encipherment = "key_encipherment"


class X506KeyAgreementKeyUsage(str, Enum):
    encipher_only = "encipher_only"
    decipher_only = "decipher_only"


# class CertificateSubjectAltNames(Type, Enum):
#     dns_name = DNSName
#     directory_name = DirectoryName
#     IP_address = IPAddress
#     other_name = OtherName
#     RFC822_name = RFC822Name
#     register_ID = RegisteredID
#     URI = UniformResourceIdentifier

_key_algos: dict[ObjectIdentifier, dict] = {
    PublicKeyAlgorithmOID.DSA: {"name": "DSA key"},
    PublicKeyAlgorithmOID.EC_PUBLIC_KEY: {
        "name": "EC key",
        "key_type": KeyTypes.EC,
    },
    PublicKeyAlgorithmOID.ED25519: {"name": "ED25519 key"},
    PublicKeyAlgorithmOID.ED448: {"name": "ED448 key"},
    PublicKeyAlgorithmOID.RSASSA_PSS: {
        "name": "RSA key with PSS padding",
        "key_type": KeyTypes.RSA,
    },
    PublicKeyAlgorithmOID.X25519: {"name": "X25519 key"},
    PublicKeyAlgorithmOID.X448: {"name": "X448 key"},
    PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5: {
        "name": "RSA key with PKCS1v15 padding",
        "key_type": KeyTypes.RSA,
    },
}


def get_algo(key_algo: ObjectIdentifier) -> dict:
    if key_algo in _key_algos:
        return _key_algos[key_algo]
    else:
        return {"name": "Unknown key algorithm"}


class CertificateSubjectAltNames:
    dns_name = DNSName
    directory_name = DirectoryName
    IP_address = IPAddress
    other_name = OtherName
    RFC822_name = RFC822Name
    register_ID = RegisteredID
    URI = UniformResourceIdentifier


class CertificateSubjectProperties(NameOID, Enum):
    common_name = NameOID.COMMON_NAME
    surname = NameOID.SURNAME
    given_name = NameOID.GIVEN_NAME
    email = NameOID.EMAIL_ADDRESS
    street_address = NameOID.STREET_ADDRESS
    post_address = NameOID.POSTAL_ADDRESS
    post = NameOID.POSTAL_CODE
    state = NameOID.STATE_OR_PROVINCE_NAME
    country = NameOID.COUNTRY_NAME
    organization = NameOID.ORGANIZATION_NAME
    organizational_unit = NameOID.ORGANIZATIONAL_UNIT_NAME
    cert_title = NameOID.TITLE
    user_id = NameOID.USER_ID
    locality_name = NameOID.LOCALITY_NAME
    organisation_identifier = NameOID.ORGANIZATION_IDENTIFIER
    serial_number = NameOID.SERIAL_NUMBER
    initials = NameOID.INITIALS
    generation_qualifier = NameOID.GENERATION_QUALIFIER
    X500_unique_identifier = NameOID.X500_UNIQUE_IDENTIFIER
    DN_qualifier = NameOID.DN_QUALIFIER
    pseudonim = NameOID.PSEUDONYM
    domain_component = NameOID.DOMAIN_COMPONENT
    juristiction_country_name = NameOID.JURISDICTION_COUNTRY_NAME
    juristiction_locality_name = NameOID.JURISDICTION_LOCALITY_NAME
    juristiction_state_or_provice_name = (
        NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME
    )
    business_category = NameOID.BUSINESS_CATEGORY
    unstructured_name = NameOID.UNSTRUCTURED_NAME


class CertificateIssuerProperties(NameOID, Enum):
    issuer_common_name = NameOID.COMMON_NAME
    issuer_surname = NameOID.SURNAME
    issuer_given_name = NameOID.GIVEN_NAME
    issuer_email = NameOID.EMAIL_ADDRESS
    issuer_street_address = NameOID.STREET_ADDRESS
    issuer_post_address = NameOID.POSTAL_ADDRESS
    issuer_post = NameOID.POSTAL_CODE
    issuer_state = NameOID.STATE_OR_PROVINCE_NAME
    issuer_country = NameOID.COUNTRY_NAME
    issuer_organization = NameOID.ORGANIZATION_NAME
    issuer_organizational_unit = NameOID.ORGANIZATIONAL_UNIT_NAME
    issuer_cert_title = NameOID.TITLE
    issuer_user_id = NameOID.USER_ID
    issuer_locality_name = NameOID.LOCALITY_NAME
    issuer_organisation_identifier = NameOID.ORGANIZATION_IDENTIFIER
    issuer_serial_number = NameOID.SERIAL_NUMBER
    issuer_initials = NameOID.INITIALS
    issuer_generation_qualifier = NameOID.GENERATION_QUALIFIER
    issuer_X500_unique_identifier = NameOID.X500_UNIQUE_IDENTIFIER
    issuer_DN_qualifier = NameOID.DN_QUALIFIER
    issuer_pseudonim = NameOID.PSEUDONYM
    issuer_domain_component = NameOID.DOMAIN_COMPONENT
    issuer_juristiction_country_name = NameOID.JURISDICTION_COUNTRY_NAME
    issuer_juristiction_locality_name = NameOID.JURISDICTION_LOCALITY_NAME
    issuer_juristiction_state_or_provice_name = (
        NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME
    )
    issuer_business_category = NameOID.BUSINESS_CATEGORY
    issuer_unstructured_name = NameOID.UNSTRUCTURED_NAME


class CertificateProperties(object):
    def __init__(self, certificate: Certificate, logger=None):
        self._certificate = certificate
        self._logger = (
            logger
            if logger is not None
            else getLogger("Certificate properties")
        )

    def get_certificate(self) -> Certificate:
        return self._certificate

    def get_basic_data(self):
        data: dict = {}
        if self._certificate is not None:
            data["version"] = self._certificate.version
            data["serial_number"] = self._certificate.serial_number
            data["singature_algorithm"] = (
                self._certificate.signature_algorithm_oid
            )
            data["not_valid_before"] = self._certificate.not_valid_before_utc
            data["not_valid_after"] = self._certificate.not_valid_after_utc
        return data

    def get_key_type(self) -> dict:
        ret = {"name": "Unknown key algorithm"}
        if self._certificate is not None:
            k_tp_oid = self._certificate.public_key_algorithm_oid
            ret = get_algo(k_tp_oid)
        return ret

    def get_subject_alt_names_from_certificate(self) -> dict:
        data = dict()
        if self._certificate is not None:
            try:
                san = self._certificate.extensions.get_extension_for_class(
                    SubjectAlternativeName
                )
                if san is not None:
                    certAltNms = CertificateSubjectAltNames()
                    for attr in dir(certAltNms):
                        attr_o = getattr(certAltNms, attr)
                        if not attr.startswith("__"):
                            vals = san.value.get_values_for_type(attr_o)
                            if len(vals) > 0:
                                data[attr] = " ,".join(vals)
            except ExtensionNotFound:
                self._logger.info(
                    "Certificate does not have alternative names."
                )
            return data

    def get_subject_data_from_certificate(self) -> dict:
        if self._certificate is not None:
            data = {}
            for pers_oid in CertificateSubjectProperties:
                attrs = self._certificate.subject.get_attributes_for_oid(
                    pers_oid.value
                )
                if len(attrs) > 0:
                    data[pers_oid.name] = attrs[0].value
            return data

    def get_issuer_data_from_certificate(self) -> dict:
        if self._certificate is not None:
            data = {}
            for pers_oid in CertificateIssuerProperties:
                attrs = self._certificate.issuer.get_attributes_for_oid(
                    pers_oid.value
                )
                if len(attrs) > 0:
                    data[pers_oid.name] = attrs[0].value
            return data

    def get_certificate_fingerprint(self, hash: HashAlgorithm) -> bytes | None:
        if self._certificate is not None:
            return self._certificate.fingerprint(hash)
        else:
            None

    def get_X509_key_usages_from_certificate(self) -> dict:
        ext_lst = dict()
        if self._certificate is not None:
            try:
                ext_ku = self._certificate.extensions.get_extension_for_class(
                    KeyUsage
                )
                ext = ext_ku.value
                for ku in X506KeyUsage:
                    if hasattr(ext, ku.name):
                        attr = getattr(ext, ku.name)
                        ext_lst[ku.name] = attr
                        if ku == X506KeyUsage.key_agreement and attr:
                            for ka_ku in X506KeyAgreementKeyUsage:
                                ka_attr = getattr(ext, ka_ku.name)
                                ext_lst[ka_ku.name] = ka_attr

            except ExtensionNotFound:
                self._logger.info("Certificate does not have key usage.")
        return ext_lst

    def get_X509_extended_key_usages_from_certificate(self):
        ext_lst: dict = dict()
        if self._certificate is not None:
            try:
                ext_ku = self._certificate.extensions.get_extension_for_class(
                    ExtendedKeyUsage
                )
                ext = ext_ku.value
                for e_k_u in X509ExtendedKeyUsage:
                    if e_k_u in ext:
                        ext_lst[e_k_u.name] = True
                    else:
                        ext_lst[e_k_u.name] = False
            except ExtensionNotFound:
                self._logger.info(
                    "Certificate does not have extended key usage."
                )
        return ext_lst

    def get_key_usage_from_certificate(self) -> PKCS11KeyUsage:
        if self._certificate is not None:
            try:
                ext = self._certificate.extensions.get_extension_for_class(
                    KeyUsage
                )
                return PKCS11KeyUsage.from_X509_KeyUsage(ext.value)
            except ExtensionNotFound:
                self._logger.info(
                    "Certificate does not have key usage, so you get all usages."
                )
            return PKCS11KeyUsageAll()

    async def has_conformant_key_usage(self, filter: dict) -> bool:
        kus = self.get_X509_key_usages_from_certificate()
        ret = False
        for f_nm, f_v in filter.items():
            if f_nm in kus:
                if f_v == kus[f_nm]:
                    ret = True
                else:
                    ret = False
                    break
            else:
                ret = False
                break
        return ret

    def get_certificate_data(self, add_certificate: bool = False):
        if self._certificate is not None:
            data: dict = self.get_basic_data()
            data["key_algorithm"] = self.get_key_type()
            subs = self.get_subject_data_from_certificate()
            if subs is not None:
                data["subject"] = subs
                s_ext = self.get_subject_alt_names_from_certificate()
                if s_ext is not None:
                    data["subject"].update(s_ext)
            issu = self.get_issuer_data_from_certificate()
            if issu is not None:
                data["issuer"] = issu
            k_u = self.get_X509_key_usages_from_certificate()
            if k_u is not None:
                data["key_usage"] = k_u
                e_k_u = self.get_X509_extended_key_usages_from_certificate()
                data["key_usage"].update(e_k_u)
            if add_certificate:
                data["certificate_object"] = self.get_certificate()
            return data
        else:
            return None


class MultiCertificateContainer(object):
    def __init__(self, certificates: dict[bytes, dict]):
        self._certificates = certificates

    @classmethod
    async def read_slot(
        cls,
        library: PyKCS11Lib,
        slot,
        login_required: bool,
        pin: str | None = None,
    ):
        certificates: dict[bytes, dict[str, Certificate | str]] = dict()
        template = []
        template.append((CKA_CLASS, CKO_CERTIFICATE))
        session = library.openSession(slot, CKF_SERIAL_SESSION)
        logged_in: bool = False
        try:
            if login_required and pin is not None:
                session.login(pin)
                logged_in = True
            keys = session.findObjects(template)
            for key in keys:
                attrs = session.getAttributeValue(
                    key, [CKA_LABEL, CKA_ID, CKA_VALUE]
                )
                label = attrs[0]
                key_id = bytes(attrs[1])
                cryptoCert = load_der_x509_certificate(
                    bytes(attrs[2]), backend=default_backend()
                )
                certificates[key_id] = {
                    "label": label,
                    "certificate": cryptoCert,
                }
        finally:
            if logged_in:
                session.logout()
            session.closeSession()
        if len(certificates) > 0:
            return cls(certificates)
        else:
            return None

    def get_certificate_properties(
        self, key_id: bytes
    ) -> CertificateProperties | None:
        if key_id in self._certificates:
            return CertificateProperties(
                self._certificates[key_id]["certificate"]
            )
        else:
            return None

    async def gen_certificates_for_token(self):
        for key_id, cc in self._certificates.items():
            label = cc["label"]
            cert_p = CertificateProperties(cc["certificate"])
            yield key_id, label, cert_p
