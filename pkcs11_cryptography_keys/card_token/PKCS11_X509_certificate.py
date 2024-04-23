import PyKCS11
from asn1crypto.core import UTF8String
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate

from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
    KeyObjectTypes,
    PKCS11KeyIdent,
    _key_head,
)


class PKCS11X509Certificate(PKCS11KeyIdent):
    def __init__(
        self,
        key_id: bytes,
        label: str | None = None,
    ):
        PKCS11KeyIdent.__init__(self, key_id, label)

    def get_certificate_template(self, certificate: Certificate) -> list:
        template = []
        if KeyObjectTypes.certificate in _key_head:
            subject = certificate.subject
            sub = UTF8String(subject.rfc4514_string())
            cert = certificate.public_bytes(Encoding.DER)
            template.extend(_key_head[KeyObjectTypes.certificate])
            template.append((PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE))
            template.append((PyKCS11.CKA_MODIFIABLE, PyKCS11.CK_TRUE))
            # X509
            template.append((PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509))
            template.append((PyKCS11.CKA_VALUE, cert))
            template.append(
                (
                    PyKCS11.CKA_SUBJECT,
                    bytes(sub),
                )
            )  # must be set and DER, see Table 24, X.509 Certificate Object Attributes
            self._prep_key_idents(template)
        return template
