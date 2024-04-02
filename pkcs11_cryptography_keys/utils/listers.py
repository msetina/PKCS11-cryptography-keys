import PyKCS11

from pkcs11_cryptography_keys.sessions.PKCS11_admin_session import (
    PKCS11AdminSession,
)


# Supoort function to list admin sessions
def list_token_admins(pksc11_lib, pin):
    library = PyKCS11.PyKCS11Lib()
    library.load(pksc11_lib)
    slots = library.getSlotList(tokenPresent=True)
    for idx, sl in enumerate(slots):
        ti = library.getTokenInfo(idx)
        yield PKCS11AdminSession(pksc11_lib, ti.label.strip(), pin)
