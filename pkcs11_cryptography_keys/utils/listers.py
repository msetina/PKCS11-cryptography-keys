from logging import Logger

from PyKCS11 import CKF_TOKEN_INITIALIZED, PyKCS11Lib

from ..sessions.PKCS11_admin_session import PKCS11AdminSession
from ..utils.token_properties import TokenProperties


# Support function to list admin sessions
def list_token_admins(
    pin: str,
    pksc11_lib: str | None = None,
    norm_user: bool = False,
    logger: Logger | None = None,
):
    library = PyKCS11Lib()
    if pksc11_lib is not None:
        library.load(pksc11_lib)
    else:
        library.load()
    slots = library.getSlotList(tokenPresent=True)
    for sl in slots:
        tp = TokenProperties.read_from_slot(library, sl)
        if tp.is_initialized():
            yield PKCS11AdminSession(
                tp.get_label(),
                pin,
                norm_user,
                pksc11_lib=pksc11_lib,
                logger=logger,
            )


# Support function to list token labels
def list_token_labels(pksc11_lib: str | None = None):
    library = PyKCS11Lib()
    if pksc11_lib is not None:
        library.load(pksc11_lib)
    else:
        library.load()
    slots = library.getSlotList(tokenPresent=True)
    for sl in slots:
        tp = TokenProperties.read_from_slot(library, sl)
        if tp.is_initialized():
            yield tp.get_label()


# Support function to list token labels
def list_slots(pksc11_lib: str | None = None):
    library = PyKCS11Lib()
    if pksc11_lib is not None:
        library.load(pksc11_lib)
    else:
        library.load()
    slots = library.getSlotList(tokenPresent=True)
    for sl in slots:
        si = library.getSlotInfo(sl)
        ti = library.getTokenInfo(sl)
        ret = {}
        ret.update(si.to_dict())
        ret["flags"] = si.flags2text()
        ret["token"] = {}
        ret["token"].update(ti.to_dict())
        ret["token"]["flags"] = ti.flags2text()
        yield ret
