from importlib import import_module
from logging import Logger, getLogger

import PyKCS11
from cryptography.x509 import Certificate

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
    def __init__(self, session, keyid: bytes, label: str, logger: Logger):
        # session for interacton with the card
        self._session = session
        # id of key read from private key
        self._keyid = keyid
        # label of the key
        self._label = label
        self._logger = (
            logger if logger is not None else getLogger("PKCS11TokenAdmin")
        )

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
                self._logger.info("Public key deleted")
            private_objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            for priv_o in private_objects:
                self._session.destroyObject(priv_o)
                self._logger.info("Private key deleted")
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
                self._logger.info("Certificate deleted")
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
                if definition.is_loaded():
                    self._session.createObject(
                        definition.get_template(KeyObjectTypes.private)
                    )
                    self._logger.info("Private key created")
                    self._session.createObject(
                        definition.get_template(KeyObjectTypes.public)
                    )
                    self._logger.info("Public key created")
                    private_objects = self._session.findObjects(
                        [
                            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                            (PyKCS11.CKA_ID, self._keyid),
                        ]
                    )
                    for priv_o in private_objects:
                        priv_key = priv_o
                else:
                    (pub_key, priv_key) = self._session.generateKeyPair(
                        definition.get_template(KeyObjectTypes.public),
                        definition.get_template(KeyObjectTypes.private),
                        mecha=definition.get_generation_mechanism(),
                    )
                if priv_key is not None:
                    self._logger.info("Keypair generated")
                    key_module = definition.get_module_name()
                    module = import_module(key_module)
                    if module != None:
                        ret = module.get_key(
                            self._session, self._keyid, priv_key
                        )
                    else:
                        raise Exception(
                            "Could not find module for {0}".format(key_module)
                        )
            else:
                self._logger.info("Keypair definition missing")
        else:
            self._logger.info("PKCS11 session not present")
        return ret

    # Write certificate to the card
    def write_certificate(
        self,
        certificate: Certificate,
        keyid: bytes | None = None,
        label: str | None = None,
    ) -> bool:
        ret = False
        if self._session is not None:
            if keyid is not None and label is not None:
                cert = PKCS11X509Certificate(keyid, label)
            else:
                cert = PKCS11X509Certificate(self._keyid, self._label)
            cert_template = cert.get_certificate_template(certificate)
            # create the certificate object
            self._session.createObject(cert_template)
            self._logger.info("Certificate written")
            ret = True
        else:
            self._logger.info("PKCS11 session not present")
        return ret
