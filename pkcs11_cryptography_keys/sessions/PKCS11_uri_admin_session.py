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
from pkcs11_cryptography_keys.pkcs11_URI.pkcs11_URI import PKCS11URI

from .PKCS11_session import PKCS11Session


# contextmanager to facilitate connecting to source
class PKCS11URIAdminSession(PKCS11Session):
    def __init__(
        self,
        uri: str,
        norm_user: bool = False,
    ):
        super().__init__()
        self._norm_user = norm_user
        self._uri = uri

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
                label = attrs[1]
                return keyid, label
        return None, None

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(self) -> PKCS11TokenAdmin | None:
        pkcs11_uri = PKCS11URI.parse(self._uri)
        self._login_required = False
        self._session = pkcs11_uri.get_session(self._norm_user)
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
                return PKCS11TokenAdmin(self._session, keyid, label)
        return None

    # context manager API
    def __enter__(self) -> PKCS11TokenAdmin | None:
        ret = self.open()
        return ret

    async def __aenter__(self) -> PKCS11TokenAdmin | None:
        ret = self.open()
        return ret
