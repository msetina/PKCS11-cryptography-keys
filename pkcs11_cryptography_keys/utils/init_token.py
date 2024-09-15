from PyKCS11 import CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_SO, PyKCS11Lib

from pkcs11_cryptography_keys.utils.exceptions import (
    PinException,
    TokenException,
)
from pkcs11_cryptography_keys.utils.token_properties import (
    PinState,
    TokenProperties,
)


def __create_token(lib, slot, soPin: str, label: str, userPin: str):
    login_required = False
    if lib is not None:
        tp = TokenProperties.read_from_slot(lib, slot)
        # TODO:check user pin and so pin for length
        if not tp.check_pin_length(soPin):
            raise PinException("SO pin too short or too long for this token.")
        if not tp.check_pin_length(userPin):
            raise PinException("User pin too short or too long for this token.")
        if not tp.is_initialized():
            lib.initToken(slot, soPin, label)
            session = lib.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)

            if tp.is_login_required():
                login_required = True
                session.login(soPin, CKU_SO)
            try:
                session.initPin(userPin)
            finally:
                if login_required:
                    session.logout()
                session.closeSession()
        else:
            raise TokenException("Token already initialized.")


def create_token(
    new_slot, soPin: str, label: str, userPin: str, pkcs11lib: str | None = None
):
    lib = PyKCS11Lib()
    if pkcs11lib is not None:
        lib.load(pkcs11lib)
    else:
        lib.load()
    try:
        slots = lib.getSlotList(tokenPresent=False)
        for slot in slots:
            if slot == new_slot:
                __create_token(lib, slot, soPin, label, userPin)
    finally:
        del lib


def create_token_on_all_slots(
    soPin: str, label: str, userPin: str, pkcs11lib: str | None = None
):
    lib = PyKCS11Lib()
    if pkcs11lib is not None:
        lib.load(pkcs11lib)
    else:
        lib.load()
    try:
        slots = lib.getSlotList(tokenPresent=False)
        for slot in slots:
            __create_token(lib, slot, soPin, label, userPin)
    finally:
        del lib
