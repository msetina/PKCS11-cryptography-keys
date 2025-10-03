from importlib import import_module
from logging import Logger

from PyKCS11 import CKK_ECDSA, CKK_RSA

from ..keys.ec import EllipticCurvePrivateKeyPKCS11
from ..keys.rsa import RSAPrivateKeyPKCS11
from ..pkcs11_URI.pkcs11_URI import PKCS11URI
from ..utils.pin_4_token import Pin4Token
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

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(
        self,
    ) -> EllipticCurvePrivateKeyPKCS11 | RSAPrivateKeyPKCS11 | None:
        private_key = None
        pkcs11_uri = PKCS11URI.parse(self._uri, self._logger)
        self._login_required = False
        self._session, tp = pkcs11_uri.get_session(pin_getter=self._pin_getter)
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
                for m, op, properties in pkcs11_uri.gen_operations():
                    private_key.fill_operations(m, op, properties)
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
