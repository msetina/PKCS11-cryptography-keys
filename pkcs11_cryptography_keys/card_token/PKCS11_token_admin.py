from importlib import import_module

import PyKCS11
from cryptography.x509 import Certificate, Name

from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
    KeyObjectTypes,
    PKCS11KeyUsage,
)
from pkcs11_cryptography_keys.card_token.PKCS11_keypair import PKCS11KeyPair
from pkcs11_cryptography_keys.card_token.PKCS11_X509_certificate import (
    PKCS11X509Certificate,
)
from pkcs11_cryptography_keys.keys.ec import EllipticCurvePrivateKeyPKCS11
from pkcs11_cryptography_keys.keys.rsa import RSAPrivateKeyPKCS11


# Token representation
class PKCS11TokenAdmin:
    def __init__(self, session, keyid: bytes, label: str):
        # session for interacton with the card
        self._session = session
        # id of key read from private key
        self._keyid = keyid
        # label of the key
        self._label = label

    # Delete keypair from the card
    def delete_key_pair(self) -> bool:
        ret = False
        if self._session is not None:
            public_objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            for pub_o in public_objects:
                self._session.destroyObject(pub_o)
            private_objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            for priv_o in private_objects:
                self._session.destroyObject(priv_o)
                ret = True
        return ret

    # Delete certificate from the card
    def delete_certificate(self) -> bool:
        ret = False
        if self._session is not None:
            cert_objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            for co in cert_objects:
                self._session.destroyObject(co)
                ret = True
        return ret

    # Create keypair on the card
    def create_key_pair(
        self, key_usage: PKCS11KeyUsage, **kwargs
    ) -> RSAPrivateKeyPKCS11 | EllipticCurvePrivateKeyPKCS11 | None:
        ret = None
        if self._session is not None:
            kp_def = PKCS11KeyPair(key_usage, self._keyid, self._label)
            definition = kp_def.get_keypair_templates(**kwargs)
            if definition is not None:
                (pub_key, priv_key) = self._session.generateKeyPair(
                    definition.get_template(KeyObjectTypes.public),
                    definition.get_template(KeyObjectTypes.private),
                    mecha=definition.get_generation_mechanism(),
                )
                key_module = definition.get_module_name()
                module = import_module(key_module)
                if module != None:
                    ret = module.get_key(self._session, self._keyid, priv_key)
                else:
                    raise Exception(
                        "Could not find module for {0}".format(key_module)
                    )
        return ret

    # Write certificate to the card
    def write_certificate(
        self, subject: Name, certificate: Certificate
    ) -> bool:
        ret = False
        if self._session is not None:
            cert = PKCS11X509Certificate(self._keyid, self._label)
            cert_template = cert.get_certificate_template(subject, certificate)
            # create the certificate object
            self._session.createObject(cert_template)
            ret = True
        return ret
