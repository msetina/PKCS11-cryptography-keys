from __future__ import annotations

from logging import Logger, getLogger
from re import compile
from typing import Any
from urllib.parse import unquote

from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKF_LOGIN_REQUIRED,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_TOKEN_INITIALIZED,
    CKU_SO,
    PyKCS11Lib,
    Session,
)

from pkcs11_cryptography_keys.utils.pin_4_token import Pin4Token, PinTypes

from .definitions import (
    CK_INFO_translation,
    CK_SESSION_INFO_translation,
    CK_SLOT_INFO_translation,
    CK_TOKEN_INFO_translation,
    PKCS11_type_translation,
)


class PKCS11URI(object):
    def __init__(
        self,
        location: dict[str, str],
        query: dict[str, str],
        logger: Logger | None = None,
    ) -> None:
        self._PKCS11_key_translation = {
            "object": (CKA_LABEL, self.__get_object_value),
            "id": (CKA_ID, self.__get_id_value),
            "type": (CKA_CLASS, self.__get_type_value),
        }
        self._location: dict[str, str] = location
        self._query: dict[str, str] = query
        self._operations: list[tuple[int, str]] = []
        self._logger = logger if logger is not None else getLogger("PKCS11 uri")

    def __get_object_value(self, value: str):
        return value

    def __get_id_value(self, value: str):
        return bytes(value, "UTF-8")

    def __get_type_value(self, value: str):
        return PKCS11_type_translation.get(value, None)

    # If a URI contains both "pin-source" and "pin-value" query attributes, the URI SHOULD be refused as invalid.

    # platform independent module name
    #  "module-name"
    # absolute path to module
    #  "module-path"

    # object is CKA_LABEL
    #  "object"
    #  "type" "=" ( "public" / "private" / "cert" / "secret-key" / "data" )
    # id is CKA_ID
    #  "id"

    # can be URI to pin-value
    #  "pin-source"
    #  "pin-value"

    # "library-description",
    # "manufacturer",
    # "library-manufacturer",
    # "model",
    # "object",
    # "serial",
    # "slot-description",
    # "slot-manufacturer",
    # "token",
    # "type",
    # "module-name"

    @classmethod
    def parse(
        cls,
        uri: str,
        logger: Logger | None,
    ) -> PKCS11URI:
        local_logger = logger if logger is not None else getLogger("URI parser")
        grob = compile("(.+?)(\?.+?)?(#.+)?$")
        m = grob.match(uri)
        if m is not None:
            g = m.groups()
            if len(g) == 3:
                location: dict[str, str] = {}
                query: dict[str, str] = {}
                if g[0] is not None:
                    schema, sep, rest = g[0].partition(":")
                    if schema == "pkcs11" and len(rest.strip()) > 0:
                        while True:
                            a = rest.find(";")
                            b = rest.find("=")
                            if a > 0 and a < b:
                                raise Exception(
                                    "Bad location: {0}".format(rest)
                                )
                            elif a < 0:
                                location[rest[0:b]] = unquote(rest[b + 1 :])
                                break
                            else:
                                location[rest[0:b]] = unquote(rest[b + 1 : a])
                                rest = rest[a + 1 :]
                    else:
                        return cls({}, {}, local_logger)
                if g[1] is not None:
                    if g[1].startswith("?"):
                        rest = g[1][1:]
                        while True:
                            a = rest.find(";")
                            b = rest.find("=")
                            if a > 0 and a < b:
                                raise Exception("Bad query: {0}".format(rest))
                            elif a < 0:
                                query[rest[0:b]] = unquote(rest[b + 1 :])
                                break
                            else:
                                query[rest[0:b]] = unquote(rest[b + 1 : a])
                                rest = rest[a + 1 :]

                    else:
                        raise Exception("Bad query in URI")
                return cls(location, query, local_logger)
            else:
                raise Exception("URI was not parsed properly")
        else:
            raise Exception("Provided string is not an URI")

    def get_session(
        self, norm_user: bool = True, pin_getter: Pin4Token | None = None
    ) -> Session:
        session = None
        library = PyKCS11Lib()
        if "module-path" in self._query:
            library.load(self._query["module-path"])
        else:
            library.load()
        info = library.getInfo()
        for tag in self._location:
            if tag in CK_INFO_translation:
                ck_tag = CK_INFO_translation[tag]
                if self._location[tag] != info.__dict__[ck_tag].strip():
                    raise Exception(
                        "PKCS11 library does not corespond to URI parameters. {0} -> {1} != {2}".format(
                            tag, self._location[tag], info.fields[ck_tag]
                        )
                    )
        slots = library.getSlotList(tokenPresent=True)
        slot = None
        login_required = False
        for sl in slots:
            ti = library.getTokenInfo(sl)
            si = library.getSlotInfo(sl)
            if ti.flags & CKF_LOGIN_REQUIRED != 0:
                login_required = True
            if not ti.flags & CKF_TOKEN_INITIALIZED != 0:
                del ti
                del si
                continue
            found = False
            for tag in self._location:
                if tag in CK_SLOT_INFO_translation:
                    ck_tag = CK_SLOT_INFO_translation[tag]
                    found = True
                    if self._location[tag] != si.__dict__[ck_tag].strip().strip(
                        "\x00"
                    ):
                        self._logger.info(
                            "On slot '{0}' did not match '{1}'".format(
                                self._location[tag], si.__dict__[ck_tag].strip()
                            )
                        )
                        slot = None
                        break
                    else:
                        slot = sl
                if tag in CK_TOKEN_INFO_translation:
                    ck_tag = CK_TOKEN_INFO_translation[tag]
                    found = True
                    if self._location[tag] != ti.__dict__[ck_tag].strip().strip(
                        "\x00"
                    ):
                        self._logger.info(
                            "On token '{0}' did not match '{1}'".format(
                                self._location[tag], ti.__dict__[ck_tag].strip()
                            )
                        )
                        slot = None
                        break
                    else:
                        slot = sl
            del ti
            del si
            if found:
                if slot is None:
                    found = False
                    continue
                else:
                    break
        if slot is not None:
            session = library.openSession(
                slot, CKF_SERIAL_SESSION | CKF_RW_SESSION
            )
            ses_info = session.getSessionInfo()
            for tag in self._location:
                if tag in CK_SESSION_INFO_translation:
                    ck_tag = CK_SESSION_INFO_translation[tag]
                    if self._location[tag] != ses_info.__dict__[ck_tag]:
                        session.closeSession()
                        session = None
                        raise Exception(
                            "{0} is of value {1}".format(
                                tag, ses_info.__dict__[ck_tag]
                            )
                        )
            if session is not None:
                pin = None
                if "pin-value" in self._query:
                    pin = self._query["pin-value"]
                if login_required:
                    if pin is None:
                        if pin_getter is None:
                            pg = Pin4Token(
                                "Unknown", "We want to do something with a key."
                            )
                            pin = pg.get_pin(
                                PinTypes.NORM_USER
                                if norm_user
                                else PinTypes.SO_USER
                            )
                        else:
                            pin = pin_getter.get_pin(
                                PinTypes.NORM_USER
                                if norm_user
                                else PinTypes.SO_USER
                            )
                    if pin is not None:
                        if norm_user:
                            session.login(pin)
                        else:
                            session.login(pin, CKU_SO)
                    else:
                        raise Exception(
                            "Login is required, but pin was not provided"
                        )
                    mechanisms = library.getMechanismList(slot)
                    self._operations = []
                    for m in mechanisms:
                        mi = library.getMechanismInfo(slot, m)
                        for mf in mi.flags_dict:
                            if mi.flags & mf != 0:
                                op = mi.flags_dict[mf].replace("CKF_", "")
                                self._operations.append((m, op))
            else:
                self._logger.info("Session could not be opened.")
        else:
            self._logger.info("Required slot was not found.")
        return session

    def gen_operations(self):
        for m, op in self._operations:
            yield m, op

    def get_key(self, session: Session) -> tuple[bytes | None, int | None, Any]:
        template = []
        for tag in self._location:
            if tag in self._PKCS11_key_translation:
                oper = self._PKCS11_key_translation[tag]
                key = oper[0]
                operation = oper[1]
                val = operation(self._location[tag])
                if val is not None:
                    template.append((key, val))

        if session is not None and len(template) > 0:
            objs = session.findObjects(template)
            if objs is not None and len(objs) > 0:
                if len(objs) > 1:
                    self._logger.info(
                        "There multiple keys with provided URI description."
                    )
                key = objs[0]
                attrs = session.getAttributeValue(key, [CKA_KEY_TYPE, CKA_ID])
                key_type = attrs[0]
                keyid = bytes(attrs[1])
                return keyid, key_type, key
        return None, None, None

    def get_private_key(
        self, session: Session
    ) -> tuple[bytes | None, str | None, int | None, Any]:
        template = []
        found = False
        keyid = None
        label = None
        for tag in self._location:
            if tag in self._PKCS11_key_translation:
                oper = self._PKCS11_key_translation[tag]
                key = oper[0]
                operation = oper[1]
                if tag == "type":
                    found = True
                    val = operation("private")
                else:
                    val = operation(self._location[tag])
                    if tag == "object":
                        label = val
                    elif tag == "id":
                        keyid = val
                if val is not None:
                    template.append((key, val))
        if not found:
            oper = self._PKCS11_key_translation["type"]
            key = oper[0]
            operation = oper[1]
            val = operation("private")
            if val is not None:
                template.append((key, val))
        if session is not None and len(template) > 0:
            objs = session.findObjects(template)
            if objs is not None and len(objs) > 0:
                if len(objs) > 1:
                    self._logger.info(
                        "There multiple keys with provided URI description."
                    )
                key = objs[0]
                attrs = session.getAttributeValue(
                    key, [CKA_KEY_TYPE, CKA_ID, CKA_LABEL]
                )
                key_type = attrs[0]
                keyid = bytes(attrs[1])
                label = attrs[2]
                return keyid, label, key_type, key
        return keyid, label, None, None
