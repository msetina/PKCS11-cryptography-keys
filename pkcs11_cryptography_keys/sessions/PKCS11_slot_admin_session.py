from logging import Logger

from PyKCS11 import (
    CKF_LOGIN_REQUIRED,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKU_SO,
    PyKCS11Lib,
    Session,
)

from pkcs11_cryptography_keys.card_slot.PKCS11_slot_admin import PKCS11SlotAdmin

from .PKCS11_session import PKCS11Session


# contextmanager to facilitate connecting to source
class PKCS11SlotAdminSession(PKCS11Session):
    def __init__(
        self,
        pksc11_lib: str,
        token_label: str | None = None,
        pin: str | None = None,
        norm_user: bool = False,
        logger: Logger | None = None,
    ):
        super().__init__(logger)
        self._pksc11_lib = pksc11_lib
        self._token_label = token_label
        self._pin = pin
        self._norm_user = norm_user

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(self) -> PKCS11SlotAdmin | None:
        library = PyKCS11Lib()
        library.load(self._pksc11_lib)
        slots = library.getSlotList(tokenPresent=True)
        slot = None
        self._login_required = False
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
                return PKCS11SlotAdmin(self._session)
            else:
                self._logger.info("PKCS11 sessin could not be opened")
        else:
            self._logger.info("Slot could not be found")
        return None

    # context manager API
    def __enter__(self) -> PKCS11SlotAdmin | None:
        ret = self.open()
        return ret

    async def __aenter__(self) -> PKCS11SlotAdmin | None:
        ret = self.open()
        return ret
