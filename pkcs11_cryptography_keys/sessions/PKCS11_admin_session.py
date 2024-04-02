import PyKCS11

from pkcs11_cryptography_keys.card_token.PKCS11_token_admin import (
    PKCS11TokenAdmin,
)

from .PKCS11_key_session import PKCS11KeySession


# contextmanager to facilitate connecting to source
class PKCS11AdminSession(PKCS11KeySession):
    def __init__(
        self,
        pksc11_lib: str,
        token_label: str,
        pin: str,
        key_label: str = None,
        key_id: bytes = None,
    ):
        super().__init__(pksc11_lib, token_label, pin, key_label)
        self._key_id = key_id

    # get private key id and label
    def _get_private_key_info(self, key_label: str = None):
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
            if private_key is not None:
                attrs = self._session.getAttributeValue(
                    private_key,
                    [PyKCS11.CKA_ID, PyKCS11.CKA_LABEL],
                )
                keyid = bytes(attrs[0])
                label = attrs[1]
                return keyid, label

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(self):
        library = PyKCS11.PyKCS11Lib()
        library.load(self._pksc11_lib)
        slots = library.getSlotList(tokenPresent=True)
        slot = None

        for idx, sl in enumerate(slots):
            ti = library.getTokenInfo(idx)
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
                    self._session.login(self._pin, PyKCS11.CKU_SO)
                pk_info = self._get_private_key_info(self._key_label)
                if pk_info is not None:
                    keyid, label = pk_info
                    return PKCS11TokenAdmin(self._session, keyid, label)
                else:
                    if self._key_id is None:
                        self._key_id = self._key_label.encode()
                    return PKCS11TokenAdmin(
                        self._session, self._key_id, self._key_label
                    )
