from importlib import import_module
from logging import Logger

from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKF_LOGIN_REQUIRED,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_ECDSA,
    CKK_RSA,
    CKO_PRIVATE_KEY,
    PyKCS11Lib,
    Session,
)

from pkcs11_cryptography_keys.keys.ec import EllipticCurvePrivateKeyPKCS11
from pkcs11_cryptography_keys.keys.rsa import RSAPrivateKeyPKCS11
from pkcs11_cryptography_keys.pkcs11_URI.pkcs11_URI import PKCS11URI
from pkcs11_cryptography_keys.utils.pin_4_token import Pin4Token

from .PKCS11_session import PKCS11Session

_key_modules = {
    CKK_ECDSA: "pkcs11_cryptography_keys.keys.ec",
    CKK_RSA: "pkcs11_cryptography_keys.keys.rsa",
}


# contextmanager to facilitate connecting to source
class PKCS11URIKeySession(PKCS11Session):
    def __init__(
        self,
        uri: str,
        pin_getter: Pin4Token | None = None,
        logger: Logger | None = None,
    ):
        super().__init__(logger)
        self._uri = uri
        self._pin_getter = pin_getter

    # get private key reference and get key type and keyid for it
    # def _get_private_key(self, key_label: str | None = None) -> tuple:
    #     if self._session is not None:
    #         if key_label is None:
    #             private_key = self._session.findObjects(
    #                 [
    #                     (CKA_CLASS, CKO_PRIVATE_KEY),
    #                 ]
    #             )[0]
    #         else:
    #             private_key = self._session.findObjects(
    #                 [
    #                     (CKA_CLASS, CKO_PRIVATE_KEY),
    #                     (CKA_LABEL, key_label),
    #                 ]
    #             )[0]
    #         attrs = self._session.getAttributeValue(
    #             private_key, [CKA_KEY_TYPE, CKA_ID]
    #         )
    #         key_type = attrs[0]
    #         keyid = bytes(attrs[1])
    #         return keyid, key_type, private_key
    #     return None, None, None

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(
        self,
    ) -> EllipticCurvePrivateKeyPKCS11 | RSAPrivateKeyPKCS11 | None:
        private_key = None
        pkcs11_uri = PKCS11URI.parse(self._uri, self._logger)
        self._login_required = False
        self._session = pkcs11_uri.get_session(pin_getter=self._pin_getter)
        if self._session is not None:
            keyid, label, key_type, pk_ref = pkcs11_uri.get_private_key(
                self._session
            )
            module = None
            module_name = _key_modules.get(key_type, None)
            if module_name is not None:
                module = import_module(module_name)
            else:
                self._logger.info(
                    "Module for key type {0} is not setup".format(key_type)
                )
            if module is not None:
                private_key = module.get_key(
                    self._session,
                    keyid,
                    pk_ref,
                )
                for m, op in pkcs11_uri.gen_operations():
                    private_key.fill_operations(m, op)
        else:
            self._logger.info("PKCS11 session is not present")
        return private_key

    # context manager API
    def __enter__(
        self,
    ) -> EllipticCurvePrivateKeyPKCS11 | RSAPrivateKeyPKCS11 | None:
        ret = self.open()
        return ret

    async def __aenter__(
        self,
    ) -> EllipticCurvePrivateKeyPKCS11 | RSAPrivateKeyPKCS11 | None:
        ret = self.open()
        return ret
