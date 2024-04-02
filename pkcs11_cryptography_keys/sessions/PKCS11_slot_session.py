import PyKCS11

from pkcs11_cryptography_keys.card_slot.PKCS11_slot import PKCS11Slot

from .PKCS11_session import PKCS11Session


# contextmanager to facilitate connecting to source
class PKCS11SlotSession(PKCS11Session):
    def __init__(self, pksc11_lib, token_label, pin):
        super().__init__()
        self._pksc11_lib = pksc11_lib
        self._token_label = token_label
        self._pin = pin

    # Open session with the card
    # Uses pin if needed, reads permited operations(mechanisms)
    def open(self):
        library = PyKCS11.PyKCS11Lib()
        library.load(self._pksc11_lib)
        slots = library.getSlotList(tokenPresent=True)
        slot = None
        self._login_required = False
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
                    self._session.login(self._pin)
                return PKCS11Slot(self._session)
