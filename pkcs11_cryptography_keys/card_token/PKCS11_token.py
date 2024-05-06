from typing import Dict

import PyKCS11
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
    read_key_usage_from_key,
)


# Token representation
class PKCS11Token:
    def __init__(self, session, keyid: bytes, pk_ref):
        # session for interacton with the card
        self._session = session
        # id of key read from private key
        self._keyid = keyid
        # private key reference
        self._private_key = pk_ref
        # operations supported by the card
        # they are separated in method groups (DIGEST,VERIFY,SIGN,ENCRYPT,DECRYPT)
        self._operations: Dict[str, Dict] = {}

    # API to init card allowed operations
    def _get_mechanism_translation(self, method, PKCS11_mechanism):
        raise NotImplementedError("Just a stub!")

    def read_key_usage(self):
        return read_key_usage_from_key(self._session, self._private_key)

    # At the init time the call to fill_operations will translate method
    # and mechanism to parameters form cryptography API calls
    def fill_operations(self, PKCS11_mechanism, method: str) -> None:
        mm = None
        try:
            if method in [
                "DIGEST",
                "SIGN",
                "VERIFY",
                "ENCRYPT",
                "DECRYPT",
                "DERIVE",
            ]:
                mm = self._get_mechanism_translation(method, PKCS11_mechanism)
        except Exception as e:
            pass
        if mm:
            l = len(mm)
            if method not in self._operations:
                self._operations[method] = {}
            p = self._operations[method]
            for idx, k in enumerate(mm, start=1):
                if idx == l:
                    p[k] = PyKCS11.CKM[PKCS11_mechanism]
                else:
                    if k in p:
                        p = p[k]
                    else:
                        p[k] = {}
                        p = p[k]

    # sign data on the card using provided PK_me which is cards mechanism transalted from cryptography call
    def _sign(self, data: bytes, PK_me):
        if self._session is not None and self._private_key is not None:
            if PK_me is None:
                raise UnsupportedAlgorithm("Signing algorithm not supported.")
            else:
                sig = self._session.sign(self._private_key, data, PK_me)
            return sig
        else:
            return None

    # extension to cryptography API to allow simple access to certificates written on the cards

    # Certificate linked to private key on the card
    def certificate(self):
        if self._session is not None:
            pk11objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            all_attributes = [
                PyKCS11.CKA_VALUE,
            ]
            certificate = None
            for pk11object in pk11objects:
                try:
                    attributes = self._session.getAttributeValue(
                        pk11object, all_attributes
                    )
                except PyKCS11.PyKCS11Error as e:
                    continue

                attr_dict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attr_dict[PyKCS11.CKA_VALUE])
                cert = x509.load_der_x509_certificate(
                    cert, backend=default_backend()
                )
                certificate = cert.public_bytes(
                    encoding=serialization.Encoding.PEM
                )
            return certificate

    # A list of Certificates from the card
    # Some cards have the CA chain written on the card
    def certificate_with_ca_chain(self):
        if self._session is not None:
            pk11objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                ]
            )
            ca_chain = []
            for pk11object in pk11objects:
                try:
                    attributes = self._session.getAttributeValue(
                        pk11object, [PyKCS11.CKA_VALUE]
                    )
                except PyKCS11.PyKCS11Error as e:
                    continue

                cert = bytes(attributes[0])
                cert = x509.load_der_x509_certificate(
                    cert, backend=default_backend()
                )
                ca_chain.append(
                    cert.public_bytes(encoding=serialization.Encoding.PEM)
                )
            return b"".join(ca_chain)

    # Get id and label for the Private key
    def get_id_and_label(self) -> tuple:
        if self._session is not None and self._private_key is not None:
            attributes = self._session.getAttributeValue(
                self._private_key, [PyKCS11.CKA_ID, PyKCS11.CKA_LABEL]
            )
            return bytes(attributes[0]), attributes[1].strip().strip("\x00")
        return None, None
