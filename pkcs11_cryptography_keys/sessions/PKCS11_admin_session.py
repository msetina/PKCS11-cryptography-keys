from logging import Logger

from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_LABEL,
    CKF_LOGIN_REQUIRED,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKO_PRIVATE_KEY,
    CKU_SO,
    PyKCS11Lib,
    Session,
)

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
        logger: Logger | None = None,
    ):
        super().__init__(logger)
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
                        (CKA_CLASS, CKO_PRIVATE_KEY),
                    ]
                )
                if len(private_key_s) > 0:
                    private_key = private_key_s[0]
            else:
                private_key_s = self._session.findObjects(
                    [
                        (CKA_CLASS, CKO_PRIVATE_KEY),
                        (CKA_LABEL, key_label),
                    ]
                )
                if len(private_key_s) > 0:
                    private_key = private_key_s[0]
            if private_key is not None:
                attrs = self._session.getAttributeValue(
                    private_key,
                    [CKA_ID, CKA_LABEL],
                )
                keyid = bytes(attrs[0])
                label = attrs[1].strip().strip("\x00")
                return keyid, label
            else:
                self._logger.info("Private key not found")
        else:
            self._logger.info("PKCS11 session not present")
        return None, None

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(self) -> PKCS11TokenAdmin | None:
        library = PyKCS11Lib()
        library.load(self._pksc11_lib)
        slots = library.getSlotList(tokenPresent=True)
        slot = None

        for sl in slots:
            ti = library.getTokenInfo(sl)
            if ti.flags & CKF_LOGIN_REQUIRED != 0:
                self._login_required = True
            if self._token_label is None:
                slot = sl
            if ti.label.strip() == self._token_label:
                slot = sl
                break
        if slot is not None:
            self._session = library.openSession(
                slot, CKF_SERIAL_SESSION | CKF_RW_SESSION
            )
            if self._session is not None:
                if self._login_required:
                    if self._norm_user:
                        self._session.login(self._pin)
                    else:
                        self._session.login(self._pin, CKU_SO)
                pk_info = self._get_private_key_info(self._key_label)
                if pk_info is not None:
                    keyid, label = pk_info
                    if keyid is None:
                        if self._key_id is None:
                            if self._key_label is None:
                                keyid = b"\x01"
                            else:
                                self._key_label.encode()
                        else:
                            keyid = self._key_id
                    if label is None:
                        if self._key_label is None:
                            label = "default"
                        else:
                            label = self._key_label
                    return PKCS11TokenAdmin(
                        self._session, keyid, label, self._logger
                    )
                else:
                    if self._key_label is None:
                        self._key_label = b"\x01"
                    if self._key_id is None:
                        self._key_id = self._key_label.encode()
                    return PKCS11TokenAdmin(
                        self._session,
                        self._key_id,
                        self._key_label,
                        self._logger,
                    )
            else:
                self._logger.info("PKCS11 session could not be opened")
        else:
            self._logger.info("Slot could not be found")
        return None

    # context manager API
    def __enter__(self) -> PKCS11TokenAdmin | None:
        ret = self.open()
        return ret

    async def __aenter__(self) -> PKCS11TokenAdmin | None:
        ret = self.open()
        return ret
