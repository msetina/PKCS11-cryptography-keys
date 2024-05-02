from logging import Logger

import PyKCS11

from pkcs11_cryptography_keys.sessions.PKCS11_admin_session import (
    PKCS11AdminSession,
)


# Support function to list admin sessions
def list_token_admins(
    pksc11_lib: str,
    pin: str,
    norm_user: bool = False,
    logger: Logger | None = None,
):
    library = PyKCS11.PyKCS11Lib()
    library.load(pksc11_lib)
    slots = library.getSlotList(tokenPresent=True)
    for sl in slots:
        ti = library.getTokenInfo(sl)
        if ti.flags & PyKCS11.CKF_TOKEN_INITIALIZED != 0:
            yield PKCS11AdminSession(
                pksc11_lib, ti.label.strip(), pin, norm_user, logger=logger
            )


# Support function to list token labels
def list_token_labels(pksc11_lib: str):
    library = PyKCS11.PyKCS11Lib()
    library.load(pksc11_lib)
    slots = library.getSlotList(tokenPresent=True)
    for sl in slots:
        ti = library.getTokenInfo(sl)
        if ti.flags & PyKCS11.CKF_TOKEN_INITIALIZED != 0:
            yield ti.label.strip()
