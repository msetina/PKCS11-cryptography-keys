from importlib import import_module

import PyKCS11
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve

from pkcs11_cryptography_keys.card_token.PKSC11_key_template import (
    get_keypair_templates,
    get_certificate_template,
)


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
    def delete_key_pair(self):
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
    def delete_certificate(self):
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
        self, settings: dict[str, str | EllipticCurve | int | dict | bytes]
    ):
        ret = None
        if self._session is not None:
            settings.update({"label": self._label, "id": self._keyid})
            templates = get_keypair_templates(settings)
            (pub_key, priv_key) = self._session.generateKeyPair(
                templates["public"],
                templates["private"],
                mecha=templates["mechanism"],
            )
            key_module = str(templates["key_module"])
            module = import_module(key_module)
            if module != None:
                ret = module.get_key(self._session, self._keyid, priv_key)
            else:
                raise Exception(
                    "Could not find module for {0}".format(key_module)
                )
        return ret

    # Write certificate to the card
    def write_certificate(self, settings):
        ret = False
        if self._session is not None:
            settings.update({"label": self._label, "id": self._keyid})
            cert_template = get_certificate_template(settings)
            # create the certificate object
            self._session.createObject(cert_template)
            ret = True
        return ret
