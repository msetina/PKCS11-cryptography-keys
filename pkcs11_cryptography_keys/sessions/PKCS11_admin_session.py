import PyKCS11

from pkcs11_cryptography_keys.card_token.PKCS11_token_admin import (
    PKCS11TokenAdmin,
)

from .PKCS11_session import PKCS11Session


# contextmanager to facilitate connecting to source
class PKCS11AdminSession(PKCS11Session):
    def __init__(
        self,
        pksc11_lib: str,
        token_label: str,
        pin: str,
        norm_user: bool = False,
        key_label: str | None = None,
        key_id: bytes | None = None,
    ):
        super().__init__()
        self._key_id = key_id
        self._norm_user = norm_user
        self._pksc11_lib = pksc11_lib
        self._token_label = token_label
        self._pin = pin
        self._key_label = key_label

    # get private key id and label
    def _get_private_key_info(self, key_label: str | None = None) -> tuple:
        if self._session is not None:
            private_key = None
            if key_label is None:
                private_key_s = self._session.findObjects(
                    [
                        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    ]
                )
                if len(private_key_s) > 0:
                    private_key = private_key_s[0]
            else:
                private_key_s = self._session.findObjects(
                    [
                        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                        (PyKCS11.CKA_LABEL, key_label),
                    ]
                )
                if len(private_key_s) > 0:
                    private_key = private_key_s[0]
            if private_key is not None:
                attrs = self._session.getAttributeValue(
                    private_key,
                    [PyKCS11.CKA_ID, PyKCS11.CKA_LABEL],
                )
                keyid = bytes(attrs[0])
                label = attrs[1]
                return keyid, label
        return None, None

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(self) -> PKCS11TokenAdmin | None:
        library = PyKCS11.PyKCS11Lib()
        library.load(self._pksc11_lib)
        slots = library.getSlotList(tokenPresent=True)
        slot = None

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
                    if self._norm_user:
                        self._session.login(self._pin)
                    else:
                        self._session.login(self._pin, PyKCS11.CKU_SO)
                pk_info = self._get_private_key_info(self._key_label)
                if pk_info is not None:
                    keyid, label = pk_info
                    if keyid is None:
                        if self._key_id is None:
                            if self._key_label is None:
                                keyid = b"01"
                            else:
                                self._key_label.encode()
                        else:
                            keyid = self._key_id
                    if label is None:
                        if self._key_label is None:
                            label = "default"
                        else:
                            label = self._key_label
                    return PKCS11TokenAdmin(self._session, keyid, label)
                else:
                    if self._key_label is None:
                        self._key_label = b"01"
                    if self._key_id is None:
                        self._key_id = self._key_label.encode()
                    return PKCS11TokenAdmin(
                        self._session, self._key_id, self._key_label
                    )
        return None

    # context manager API
    def __enter__(self) -> PKCS11TokenAdmin | None:
        ret = self.open()
        return ret

    async def __aenter__(self) -> PKCS11TokenAdmin | None:
        ret = self.open()
        return ret
