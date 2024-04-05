import PyKCS11

from pkcs11_cryptography_keys.card_slot.PKCS11_slot_admin import PKCS11SlotAdmin

from .PKCS11_slot_session import PKCS11SlotSession


# contextmanager to facilitate connecting to source
class PKCS11SlotAdminSession(PKCS11SlotSession):
    def __init__(
        self,
        pksc11_lib: str,
        token_label: str,
        pin: str,
        norm_user: bool = False,
    ):
        super().__init__(pksc11_lib, token_label, pin)
        self._norm_user = norm_user

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(self):
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
                    if self._norm_user:
                        self._session.login(self._pin)
                    else:
                        self._session.login(self._pin, PyKCS11.CKU_SO)
                return PKCS11SlotAdmin(self._session)
