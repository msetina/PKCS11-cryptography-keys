from enum import Flag
from urllib.parse import quote, quote_from_bytes

from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_LABEL,
    CKF_LOGIN_REQUIRED,
    CKF_SERIAL_SESSION,
    PyKCS11Lib,
)

from .definitions import (
    CK_INFO_translation,
    CK_SLOT_INFO_translation,
    CK_TOKEN_INFO_translation,
    PKCS11_type_translation,
)


class URILocationLevel(Flag):
    NO = 0
    LIBRARY = 1
    SLOT = 2
    TOKEN = 4
    PRIVATE_KEY = 8
    PUBLIC_KEY = 16
    CERTIFICATE = 32
    TOKEN_SLOT = SLOT | TOKEN
    ALL_TO_TOKEN = LIBRARY | TOKEN_SLOT
    TOKEN_PRIVATE_KEY = TOKEN | PRIVATE_KEY
    TOKEN_PUBLIC_KEY = TOKEN | PUBLIC_KEY
    TOKEN_CERTIFICATE = TOKEN | CERTIFICATE
    TOKEN_ALL_KEYS = TOKEN_PRIVATE_KEY | PUBLIC_KEY | CERTIFICATE


def __read_keys(
    library: PyKCS11Lib,
    slot: int,
    location: list,
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
            # ses_info = session.getSessionInfo()
            # slot_id = ses_info.__dict__["slotID"]
            keys = session.findObjects(template)
            for key in keys:
                # "slot-id"
                key_location = []
                key_location.extend(location)
                #   key_location.append("slot-id={0}".format(slot_id))
                attrs = session.getAttributeValue(key, [CKA_LABEL, CKA_ID])
                label = attrs[0]
                key_id = bytes(attrs[1])
                key_location.append("object={0}".format(quote(label)))
                key_location.append("id={0}".format(quote_from_bytes(key_id)))
                key_location.append("type={0}".format(tp))
                ret.append("pkcs11:{0}".format(";".join(key_location)))
        finally:
            if login_required:
                session.logout()
            session.closeSession()
    return ret


def get_URIs_from_module(
    module: str | None,
    location_level: URILocationLevel,
    pin: str | None = None,
) -> list[str]:
    uris = []
    lib_location = []
    query = []
    login_required = False
    if module is not None:
        query.append("module-path={0}".format(module))
    if pin is not None:
        query.append("pin-value={0}".format(pin))
    library = PyKCS11Lib()
    if module is not None:
        library.load(module)
    else:
        library.load()
    info = library.getInfo()
    if location_level & URILocationLevel.LIBRARY is not URILocationLevel.NO:
        for tag in CK_INFO_translation:
            ck_tag = CK_INFO_translation[tag]
            if tag not in ["library-version"]:
                val = quote(info.__dict__[ck_tag].strip())
                lib_location.append("{0}={1}".format(tag, val))
    slots = library.getSlotList(tokenPresent=True)
    for sl in slots:
        location = []
        location.extend(lib_location)
        ti = library.getTokenInfo(sl)
        if ti.flags & CKF_LOGIN_REQUIRED != 0:
            login_required = True
        if location_level & URILocationLevel.SLOT is not URILocationLevel.NO:
            si = library.getSlotInfo(sl)
            for tag in CK_SLOT_INFO_translation:
                ck_tag = CK_SLOT_INFO_translation[tag]
                val = quote(si.__dict__[ck_tag].strip())
                location.append("{0}={1}".format(tag, val))
        if location_level & URILocationLevel.TOKEN is not URILocationLevel.NO:
            for tag in CK_TOKEN_INFO_translation:
                ck_tag = CK_TOKEN_INFO_translation[tag]
                val = quote(ti.__dict__[ck_tag].strip())
                location.append("{0}={1}".format(tag, val))
        if (
            location_level & URILocationLevel.PRIVATE_KEY
            is not URILocationLevel.NO
        ):
            uris.extend(
                __read_keys(
                    library, sl, location, "private", login_required, pin
                )
            )
        elif (
            location_level & URILocationLevel.PUBLIC_KEY
            is not URILocationLevel.NO
        ):
            uris.extend(
                __read_keys(
                    library, sl, location, "public", login_required, pin
                )
            )
        elif (
            location_level & URILocationLevel.CERTIFICATE
            is not URILocationLevel.NO
        ):
            uris.extend(
                __read_keys(
                    library, sl, location, "certificate", login_required, pin
                )
            )
        else:
            uris.append("pkcs11:{0}".format(";".join(location)))
    del library
    if len(query) > 0:
        for i in range(len(uris)):
            uris[i] = "{0}?{1}".format(uris[i], ";".join(query))
    return uris


def get_pkcs11_uri(
    token_label: str,
    module: str | None = None,
    key_id: bytes | None = None,
    key_label: str | None = None,
    pin: str | None = None,
) -> str:
    query = []
    if module is not None:
        query.append("module-path={0}".format(module))
    if pin is not None:
        query.append("pin-value={0}".format(pin))
    location = []
    location.append("token={0}".format(quote(token_label)))
    if key_label is not None:
        location.append("object={0}".format(quote(key_label)))
    if key_id is not None:
        location.append("id={0}".format(quote_from_bytes(key_id)))
    uri = "pkcs11:{0}".format(";".join(location))
    if len(query) > 0:
        uri = "{0}?{1}".format(uri, ";".join(query))
    return uri
