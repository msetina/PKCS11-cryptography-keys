from importlib import import_module

import PyKCS11

from pkcs11_cryptography_keys.keys.ec import EllipticCurvePrivateKeyPKCS11
from pkcs11_cryptography_keys.keys.rsa import RSAPrivateKeyPKCS11

from .PKCS11_session import PKCS11Session

_key_modules = {
    PyKCS11.CKK_ECDSA: "pkcs11_cryptography_keys.keys.ec",
    PyKCS11.CKK_RSA: "pkcs11_cryptography_keys.keys.rsa",
}


# contextmanager to facilitate connecting to source
class PKCS11KeySession(PKCS11Session):
    def __init__(
        self,
        pksc11_lib: str,
        token_label: str,
        pin: str,
        key_label: str | None = None,
    ):
        super().__init__()
        self._key_label = key_label
        self._pksc11_lib = pksc11_lib
        self._token_label = token_label
        self._pin = pin

    # get private key reference and get key type and keyid for it
    def _get_private_key(self, key_label: str | None = None) -> tuple:
        if self._session is not None:
            if key_label is None:
                private_key = self._session.findObjects(
                    [
                        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    ]
                )[0]
            else:
                private_key = self._session.findObjects(
                    [
                        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                        (PyKCS11.CKA_LABEL, key_label),
                    ]
                )[0]
            attrs = self._session.getAttributeValue(
                private_key, [PyKCS11.CKA_KEY_TYPE, PyKCS11.CKA_ID]
            )
            key_type = attrs[0]
            keyid = bytes(attrs[1])
            return keyid, key_type, private_key
        return None, None, None

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(
        self,
    ) -> EllipticCurvePrivateKeyPKCS11 | RSAPrivateKeyPKCS11 | None:
        private_key = None
        library = PyKCS11.PyKCS11Lib()
        library.load(self._pksc11_lib)
        slots = library.getSlotList(tokenPresent=True)
        slot = None
        self._login_required = False
        for sl in slots:
            ti = library.getTokenInfo(sl)
            if ti.flags & PyKCS11.CKF_LOGIN_REQUIRED != 0:
                self._login_required = True
            if self._token_label is None:
                slot = sl
            if ti.label.strip() == self._token_label:
                slot = sl
                break
        if slot is not None:
            self._session = library.openSession(
                slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
            )
            if self._session is not None:
                if self._login_required:
                    self._session.login(self._pin)
                keyid, key_type, pk_ref = self._get_private_key(self._key_label)
                module = None
                module_name = _key_modules.get(key_type, None)
                if module_name is not None:
                    module = import_module(module_name)
                if module is not None:
                    private_key = module.get_key(
                        self._session,
                        keyid,
                        pk_ref,
                    )
                    mechanisms = library.getMechanismList(slot)
                    for m in mechanisms:
                        mi = library.getMechanismInfo(slot, m)
                        for mf in mi.flags_dict:
                            if mi.flags & mf != 0:
                                op = mi.flags_dict[mf].replace("CKF_", "")
                                private_key.fill_operations(m, op)

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
