from logging import Logger
from typing import Dict

from PyKCS11 import CKF_RW_SESSION, CKF_SERIAL_SESSION, PyKCS11Lib

from ..card_token.PKCS11_object import add_to_operations
from ..keys.symetric_crypto import SymetricKeyPKCS11
from ..utils.token_properties import TokenProperties
from .PKCS11_session import PKCS11Session


# contextmanager to facilitate connecting to source
class PKCS11OperationSession(PKCS11Session):
    def __init__(
        self,
        token_label: str,
        pin: str,
        pksc11_lib: str | None = None,
        logger: Logger | None = None,
    ):
        super().__init__(logger)
        self._pksc11_lib = pksc11_lib
        self._token_label = token_label
        self._pin = pin
        self._library = None
        self._slot = None
        # operations supported by the card
        # they are separated in method groups (DIGEST,VERIFY,SIGN,ENCRYPT,DECRYPT)
        self._operations: Dict[str, Dict] = {}
        # symetric keys supported by the card
        self._symetric_key_support: Dict[str, Dict] = {}
        # key wrappers
        self._key_wrappers: Dict[str, set] = {}

    # API to init card allowed operations
    def _get_mechanism_translation(self, method, PKCS11_mechanism, properties):
        return None

    # API to init card allowed symetric keys
    def _get_symetric_key_translation(
        self, method, PKCS11_mechanism, properties
    ):
        return None

    # API to init card allowed key wrappers
    def _get_key_wrappers_translation(
        self, method, PKCS11_mechanism, properties
    ):
        return None

    # At the init time the call to fill_operations will translate method
    # and mechanism to parameters form cryptography API calls
    def _fill_operations(
        self, PKCS11_mechanism, method: str, properties: dict
    ) -> None:
        sk = None
        wp = None
        mm = None
        try:
            if method in [
                "DIGEST",
                "SIGN",
                "VERIFY",
                "ENCRYPT",
                "DECRYPT",
                "DERIVE",
                "UNWRAP",
                "WRAP",
            ]:
                mm = self._get_mechanism_translation(
                    method, PKCS11_mechanism, properties
                )
                sk = self._get_symetric_key_translation(
                    method, PKCS11_mechanism, properties
                )
                wp = self._get_key_wrappers_translation(
                    method, PKCS11_mechanism, properties
                )
        except Exception:
            pass
        if mm:
            add_to_operations(self._operations, method, PKCS11_mechanism, mm)
        if sk:
            if method not in self._symetric_key_support:
                self._symetric_key_support[method] = sk
            else:
                for nm, key_def in sk.items():
                    if nm in self._symetric_key_support[method]:
                        if "hw_padd" in key_def:
                            self._symetric_key_support[method][nm] = key_def

                    else:
                        self._symetric_key_support[method][nm] = key_def

        if wp:
            if method not in self._key_wrappers:
                self._key_wrappers[method] = set(wp)
            else:
                if not self._key_wrappers[method].issubset(wp):
                    self._key_wrappers[method] |= set(wp)

    # Uses pin if needed, reads permited operations(mechanisms)
    def open(
        self,
    ):
        self._library = PyKCS11Lib()
        slots: list = []
        if self._library is not None:
            if self._pksc11_lib is not None:
                self._library.load(self._pksc11_lib)
            else:
                self._library.load()
            slots = self._library.getSlotList(tokenPresent=True)
        self._slot = None
        self._login_required = False
        tp = None
        for sl in slots:
            tp = TokenProperties.read_from_slot(self._library, sl)
            if self._token_label is None:
                self._slot = sl
                break
            lbl = tp.get_label()
            if lbl == self._token_label:
                self._slot = sl
                break
        if self._slot is not None and tp is not None:
            for m, op, properties in self._gen_mechanisms():
                self._fill_operations(m, op, properties)
            if tp.is_login_required():
                self._login_required = True
            self._session = self._library.openSession(
                self._slot, CKF_SERIAL_SESSION | CKF_RW_SESSION
            )
            if self._session is not None:
                if self._login_required:
                    self._session.login(self._pin)
            else:
                self._logger.info("PKCS11 session could not be opened")
        else:
            self._logger.info("Slot could not be found")
        return self

    def _gen_mechanisms(self):
        if self._library is not None and self._slot is not None:
            mechanisms = self._library.getMechanismList(self._slot)
            for m in mechanisms:
                mi = self._library.getMechanismInfo(self._slot, m)
                properties = {}
                for property, value in mi.to_dict().items():
                    if isinstance(value, str):
                        properties[property] = value.strip()
                    else:
                        properties[property] = value
                for mf in mi.flags_dict:
                    if mi.flags & mf != 0:
                        op = mi.flags_dict[mf].replace("CKF_", "")
                        yield m, op, properties

    def _generate_symetric_key(self, sym_algo_props):
        if self._session:
            return SymetricKeyPKCS11.generate_key(self._session, sym_algo_props)
        else:
            self._logger.info("PKCS11 session is not opened.")
            return None

    # Closing work on an open session
    def close(self):
        if self._session is not None:
            if self._login_required:
                self._session.logout()
            self._session.closeSession()
            self._session = None
            self._library = None
            self._slot = None

    # context manager API
    def __enter__(
        self,
    ):
        ret = self.open()
        return ret

    async def __aenter__(
        self,
    ):
        ret = self.open()
        return ret
