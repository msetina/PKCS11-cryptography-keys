from typing import Dict

import PyKCS11
from cryptography.exceptions import UnsupportedAlgorithm

from .PKCS11_key_definition import read_key_usage_from_key


def add_to_operations(operations, method, PKCS11_mechanism, properties):
    ll = len(properties)
    if method not in operations:
        operations[method] = {}
    p = operations[method]
    for idx, k in enumerate(properties, start=1):
        if idx == ll:
            p[k] = PyKCS11.CKM[PKCS11_mechanism]
        else:
            if k in p:
                p = p[k]
            else:
                p[k] = {}
                p = p[k]


# Token representation
class PKCS11Object:
    def __init__(self, session, pk_ref):
        # session for interacton with the card
        self._session = session
        # private key reference
        self._private_key = pk_ref
        # operations supported by the card
        # they are separated in method groups (DIGEST,VERIFY,SIGN,ENCRYPT,DECRYPT)
        self._operations: Dict[str, Dict] = {}
        # symetric keys supported by the card
        self._symetric_key_support: Dict[str, Dict] = {}
        # key wrappers
        self._key_wrappers: Dict[str, set] = {}

    # API to init card allowed operations
    def _get_mechanism_translation(self, method, PKCS11_mechanism, properties):
        raise NotImplementedError("Just a stub!")

    # API to init card allowed symetric keys
    def _get_symetric_key_translation(
        self, method, PKCS11_mechanism, properties
    ):
        raise NotImplementedError("Just a stub!")

    # API to init card allowed key wrappers
    def _get_key_wrappers_translation(
        self, method, PKCS11_mechanism, properties
    ):
        raise NotImplementedError("Just a stub!")

    def read_key_usage(self):
        return read_key_usage_from_key(self._session, self._private_key)

    # At the init time the call to fill_operations will translate method
    # and mechanism to parameters form cryptography API calls
    def fill_operations(
        self, PKCS11_mechanism, method: str, properties: dict
    ) -> None:
        mm = None
        sk = None
        wp = None
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

    # sign data on the card using provided PK_me which is cards mechanism transalted from cryptography call
    def _sign(self, data: bytes, PK_me):
        if self._session is not None and self._private_key is not None:
            if PK_me is None:
                raise UnsupportedAlgorithm("Signing algorithm not supported.")
            else:
                sig = self._session.sign(self._private_key, data, PK_me)
            return sig
        else:
            return None
