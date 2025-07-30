from logging import Logger

from ..card_slot.PKCS11_slot import PKCS11Slot
from ..pkcs11_URI.pkcs11_URI import PKCS11URI
from ..utils.pin_4_token import Pin4Token
from .PKCS11_session import PKCS11Session


# contextmanager to facilitate connecting to source
class PKCS11URISlotSession(PKCS11Session):
    def __init__(
        self,
        uri: str,
        norm_user: bool = False,
        pin_getter: Pin4Token | None = None,
        logger: Logger | None = None,
    ):
        super().__init__(logger)
        self._norm_user = norm_user
        self._uri = uri
        self._pin_getter = pin_getter

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(self) -> PKCS11Slot | None:
        pkcs11_uri = PKCS11URI.parse(self._uri, self._logger)
        self._login_required = False
        self._session, tp = pkcs11_uri.get_session(
            self._norm_user, self._pin_getter
        )
        if self._session is not None:
            return PKCS11Slot(self._session, self._logger)
        else:
            self._logger.info("PKCS11 session is not present")
        return None

    # context manager API
    def __enter__(self) -> PKCS11Slot | None:
        ret = self.open()
        return ret

    async def __aenter__(self) -> PKCS11Slot | None:
        ret = self.open()
        return ret
