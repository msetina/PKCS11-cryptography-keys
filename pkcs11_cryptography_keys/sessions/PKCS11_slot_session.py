from logging import Logger

from PyKCS11 import (
    CKF_LOGIN_REQUIRED,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    PyKCS11Lib,
    Session,
)

from pkcs11_cryptography_keys.card_slot.PKCS11_slot import PKCS11Slot

from .PKCS11_session import PKCS11Session


# contextmanager to facilitate connecting to source
class PKCS11SlotSession(PKCS11Session):
    def __init__(
        self,
        pksc11_lib: str,
        token_label: str,
        pin: str,
        logger: Logger | None = None,
    ):
        super().__init__(logger)
        self._pksc11_lib = pksc11_lib
        self._token_label = token_label
        self._pin = pin

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(self) -> PKCS11Slot | None:
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
                    self._session.login(self._pin)
                return PKCS11Slot(self._session)
            else:
                self._logger.info("PKCS11 sessin could not be opened")
        else:
            self._logger.info("Slot could not be found")

        return None

    # context manager API
    def __enter__(self) -> PKCS11Slot | None:
        ret = self.open()
        return ret

    async def __aenter__(self) -> PKCS11Slot | None:
        ret = self.open()
        return ret
