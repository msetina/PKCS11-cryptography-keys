from importlib import import_module
from logging import Logger

from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_ECDSA,
    CKK_RSA,
    CKO_PRIVATE_KEY,
    PyKCS11Lib,
)

from ..keys.ec import EllipticCurvePrivateKeyPKCS11
from ..keys.rsa import RSAPrivateKeyPKCS11
from ..utils.token_properties import TokenProperties
from .PKCS11_session import PKCS11Session

_key_modules = {
    CKK_ECDSA: "pkcs11_cryptography_keys.keys.ec",
    CKK_RSA: "pkcs11_cryptography_keys.keys.rsa",
}


# contextmanager to facilitate connecting to source
class PKCS11KeySession(PKCS11Session):
    def __init__(
        self,
        token_label: str,
        pin: str,
        key_label: str | None = None,
        key_id: bytes | None = None,
        pksc11_lib: str | None = None,
        logger: Logger | None = None,
    ):
        super().__init__(logger)
        self._key_label = key_label
        self._key_id = key_id
        self._pksc11_lib = pksc11_lib
        self._token_label = token_label
        self._pin = pin

    # get private key reference and get key type and keyid for it
    def _get_private_key(
        self, key_label: str | None = None, key_id: str | None = None
    ) -> tuple:
        if self._session is not None:
            private_key = None
            if key_label is None and key_id is None:
                private_keys = self._session.findObjects(
                    [
                        (CKA_CLASS, CKO_PRIVATE_KEY),
                    ]
                )
                if len(private_keys) > 0:
                    private_key = private_keys[0]
            elif key_id is not None:
                private_keys = self._session.findObjects(
                    [
                        (CKA_CLASS, CKO_PRIVATE_KEY),
                        (CKA_ID, key_id),
                    ]
                )
                if len(private_keys) > 0:
                    private_key = private_keys[0]
            else:
                private_keys = self._session.findObjects(
                    [
                        (CKA_CLASS, CKO_PRIVATE_KEY),
                        (CKA_LABEL, key_label),
                    ]
                )
                if len(private_keys) > 0:
                    private_key = private_keys[0]
            if private_key is not None:
                attrs = self._session.getAttributeValue(
                    private_key, [CKA_KEY_TYPE, CKA_ID]
                )
                key_type = attrs[0]
                keyid = bytes(attrs[1])
                return keyid, key_type, private_key
        else:
            self._logger.info("PKCS11 session is not present")
        return None, None, None

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(
        self,
    ) -> EllipticCurvePrivateKeyPKCS11 | RSAPrivateKeyPKCS11 | None:
        private_key = None
        library = PyKCS11Lib()
        if self._pksc11_lib is not None:
            library.load(self._pksc11_lib)
        else:
            library.load()
        slots = library.getSlotList(tokenPresent=True)
        slot = None
        self._login_required = False
        tp = None
        for sl in slots:
            tp = TokenProperties.read_from_slot(library, sl)
            if self._token_label is None:
                slot = sl
                break
            lbl = tp.get_label()
            if lbl == self._token_label:
                slot = sl
                break
        if slot is not None and tp is not None:
            if tp.is_login_required():
                self._login_required = True
            self._session = library.openSession(
                slot, CKF_SERIAL_SESSION | CKF_RW_SESSION
            )
            if self._session is not None:
                if self._login_required:
                    self._session.login(self._pin)
                keyid, key_type, pk_ref = self._get_private_key(
                    self._key_label, self._key_id
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
                    mechanisms = library.getMechanismList(slot)
                    for m in mechanisms:
                        mi = library.getMechanismInfo(slot, m)
                        properties = {}
                        for property, value in mi.to_dict().items():
                            if isinstance(value, str):
                                properties[property] = value.strip()
                            else:
                                properties[property] = value
                        for mf in mi.flags_dict:
                            if mi.flags & mf != 0:
                                op = mi.flags_dict[mf].replace("CKF_", "")
                                private_key.fill_operations(m, op, properties)
            else:
                self._logger.info("PKCS11 session could not be opened")
        else:
            self._logger.info("Slot could not be found")
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
