from logging import Logger

from PyKCS11 import CKA_CLASS, CKA_ID, CKA_LABEL, CKO_PRIVATE_KEY

from ..card_token.PKCS11_token_admin import PKCS11TokenAdmin
from ..pkcs11_URI.pkcs11_URI import PKCS11URI
from ..utils.pin_4_token import Pin4Token
from .PKCS11_session import PKCS11Session


# contextmanager to facilitate connecting to source
class PKCS11URIAdminSession(PKCS11Session):
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
    def open(self) -> PKCS11TokenAdmin | None:
        pkcs11_uri = PKCS11URI.parse(self._uri, self._logger)
        self._login_required = False
        self._session, tp = pkcs11_uri.get_session(
            self._norm_user, self._pin_getter
        )
        if self._session is not None:
            keyid, label, _, _ = pkcs11_uri.get_private_key(self._session)
            if keyid is None:
                if label is None:
                    keyid = b"\x01"
                else:
                    label.encode()
            if label is None:
                label = "default"
            if keyid is not None:
                return PKCS11TokenAdmin(
                    self._session, keyid, label, self._logger
                )
        else:
            self._logger.info("PKCS11 session is not present")
        return None

    # context manager API
    def __enter__(self) -> PKCS11TokenAdmin | None:
        ret = self.open()
        return ret

    async def __aenter__(self) -> PKCS11TokenAdmin | None:
        ret = self.open()
        return ret
