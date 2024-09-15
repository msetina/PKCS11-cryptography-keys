from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKF_SERIAL_SESSION,
    CKK_EC,
    CKK_RSA,
    CKO_CERTIFICATE,
    CKO_DATA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    PyKCS11Lib,
)

from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
    KeyTypes,
    read_key_usage_from_key,
)

from .library_properties import LibraryProperties
from .mechanism_properties import MechanismProperties
from .slot_properties import SlotProperties
from .token_properties import TokenProperties

PKCS11_type_translation: dict[str, int] = {
    "certificate": CKO_CERTIFICATE,
    "data": CKO_DATA,
    "private": CKO_PRIVATE_KEY,
    "public": CKO_PUBLIC_KEY,
    "secret-key": CKO_SECRET_KEY,
}

PKCS11_key_type_translation: dict[int, KeyTypes] = {
    CKK_EC: KeyTypes.EC,
    CKK_RSA: KeyTypes.RSA,
}


class PKCS11Scanner(object):
    def __init__(self, library: str | None = None) -> None:
        self._library = library

    def __read_keys(
        self,
        library: PyKCS11Lib,
        slot: int,
        tp: str,
        login_required: bool,
        pin: str | None,
    ):
        ret = []
        template = []
        if tp in PKCS11_type_translation:
            tp_v = PKCS11_type_translation[tp]
            template.append((CKA_CLASS, tp_v))
            session = library.openSession(slot, CKF_SERIAL_SESSION)
            try:
                if login_required and pin is not None:
                    session.login(pin)
                keys = session.findObjects(template)
                for key in keys:
                    key_data = {}
                    attrs = session.getAttributeValue(
                        key, [CKA_LABEL, CKA_ID, CKA_KEY_TYPE]
                    )
                    label = attrs[0]
                    key_id = bytes(attrs[1])
                    kt = attrs[2]
                    key_data["label"] = label
                    key_data["id"] = key_id
                    key_data["type"] = tp
                    kt_i = PKCS11_key_type_translation.get(kt, None)
                    if kt_i is not None:
                        key_data["key_type"] = kt_i
                    key_usage = read_key_usage_from_key(session, key)
                    if key_usage is not None:
                        key_data["key_usage"] = key_usage
                    ret.append(key_data)
            finally:
                if login_required:
                    session.logout()
                session.closeSession()
        return ret

    def scan_from_library(
        self,
        pin: str | None = None,
    ) -> dict:
        ret: dict = {}
        login_required = False
        if self._library is not None:
            ret["used_library"] = self._library
        else:
            ret["used_library"] = "default"
        library = PyKCS11Lib()
        if self._library is not None:
            library.load(self._library)
        else:
            library.load()
        lp = LibraryProperties.read_from_slot(library)
        for tag, val in lp.gen_tags():
            ret[tag] = val
        slots = library.getSlotList(tokenPresent=True)
        ret["slots"] = []
        for sl in slots:
            slot = {}
            tp = TokenProperties.read_from_slot(library, sl)
            if tp.is_login_required():
                login_required = True
            sp = SlotProperties.read_from_slot(library, sl)
            for tag, val in sp.gen_tags():
                slot[tag] = val
            slot["token"] = {}
            # slot["token"]["max_pin_length"] = tp.get_max_pin_length()
            # slot["token"]["min_pin_length"] = tp.get_min_pin_length()
            for tag, val in tp.gen_tags():
                slot["token"][tag] = val
            slot["token"]["private keys"] = self.__read_keys(
                library, sl, "private", login_required, pin
            )
            slot["token"]["public keys"] = self.__read_keys(
                library, sl, "public", login_required, pin
            )
            slot["token"]["certificates"] = self.__read_keys(
                library,
                sl,
                "certificate",
                login_required,
                pin,
            )
            slot["token"]["mechanisms"] = {}
            for mp in MechanismProperties.gen_mechanism_properties(library, sl):
                slot["token"]["mechanisms"][mp.get_mechanism_type()] = {}
                for tag, val in mp.gen_tags():
                    slot["token"]["mechanisms"][mp.get_mechanism_type()] = val
            ret["slots"].append(slot)
        del library

        return ret
