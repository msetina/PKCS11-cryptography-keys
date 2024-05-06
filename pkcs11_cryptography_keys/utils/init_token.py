from PyKCS11 import (
    CKF_LOGIN_REQUIRED,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKU_SO,
    PyKCS11Lib,
)


def create_token(pkcs11lib: str, soPin: str, label: str, userPin: str):
    lib = PyKCS11Lib()
    lib.load(pkcs11lib)
    login_required = False
    try:
        slots = lib.getSlotList(tokenPresent=False)
        for slot in slots:
            lib.initToken(slot, soPin, label)
            session = lib.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
            ti = lib.getTokenInfo(slot)
            if ti.flags & CKF_LOGIN_REQUIRED != 0:
                login_required = True
                session.login(soPin, CKU_SO)
            try:
                session.initPin(userPin)
            finally:
                if login_required:
                    session.logout()
                session.closeSession()
    finally:
        del lib
