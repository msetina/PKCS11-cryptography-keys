from logging import Logger

from PyKCS11 import CKF_RW_SESSION, CKF_SERIAL_SESSION, PyKCS11Lib

from pkcs11_cryptography_keys.card_slot.PKCS11_slot import PKCS11Slot
from pkcs11_cryptography_keys.utils.token_properties import TokenProperties

from .PKCS11_session import PKCS11Session


# contextmanager to facilitate connecting to source
class PKCS11SlotSession(PKCS11Session):
    def __init__(
        self,
        token_label: str,
        pin: str,
        pksc11_lib: str | None = None,
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
