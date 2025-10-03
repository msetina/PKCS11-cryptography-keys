import PyKCS11
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import (
    aes_key_unwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap,
    aes_key_wrap_with_padding,
)

from ..utils.exceptions import KeyException, SessionException
from .symetric_crypto import SymetricAlgorithmProperties

pkcs11_wrap_map = {
    PyKCS11.CKM_AES_KEY_WRAP: {
        "WRAP": {
            "aes128_wrap": {"length": 16, "unit": "bytes"},
            "aes192_wrap": {"length": 24, "unit": "bytes"},
            "aes256_wrap": {"length": 32, "unit": "bytes"},
        },
        "UNWRAP": {
            "aes128_wrap": {"length": 16, "unit": "bytes"},
            "aes192_wrap": {"length": 24, "unit": "bytes"},
            "aes256_wrap": {"length": 32, "unit": "bytes"},
        },
    },
    PyKCS11.CKM_AES_KEY_WRAP_KWP: {
        "WRAP": {
            "aes128_wrap_pad": {"length": 16, "unit": "bytes"},
            "aes192_wrap_pad": {"length": 24, "unit": "bytes"},
            "aes256_wrap_pad": {"length": 32, "unit": "bytes"},
        },
        "UNWRAP": {
            "aes128_wrap_pad": {"length": 16, "unit": "bytes"},
            "aes192_wrap_pad": {"length": 24, "unit": "bytes"},
            "aes256_wrap_pad": {"length": 32, "unit": "bytes"},
        },
    },
}

wrap_name_map = {
    "aes128_wrap": {
        "key_length_bytes": 16,
        "padded": False,
    },
    "aes192_wrap": {
        "key_length_bytes": 24,
        "padded": False,
    },
    "aes256_wrap": {
        "key_length_bytes": 32,
        "padded": False,
    },
    "aes128_wrap_pad": {
        "key_length_bytes": 16,
        "padded": True,
    },
    "aes192_wrap_pad": {
        "key_length_bytes": 24,
        "padded": True,
    },
    "aes256_wrap_pad": {
        "key_length_bytes": 32,
        "padded": True,
    },
}


def get_key_wrappers_translation(method, PKCS11_mechanism, properties):
    mm = PyKCS11.CKM[PKCS11_mechanism]
    if mm in pkcs11_wrap_map and method in pkcs11_wrap_map[mm]:
        definition = pkcs11_wrap_map[mm][method]
        key_types = []
        min_k_l: int | None = None
        max_k_l: int | None = None
        if "ulMinKeySize" in properties:
            min_k_l = properties["ulMinKeySize"]
        if "ulMaxKeySize" in properties:
            max_k_l = properties["ulMaxKeySize"]
        for nm, key_def in definition.items():
            if isinstance(key_def["length"], int):
                key_length = key_def["length"]
                if (
                    max_k_l is not None
                    and min_k_l is not None
                    and key_length <= max_k_l
                    and key_length >= min_k_l
                ):
                    key_types.append(nm)
        return key_types


def _get_PKSC11_mechanism_U(padded: bool):
    PK_me = None
    template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_FALSE),
    ]
    if padded:
        PK_me = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_WRAP_KWP)
    else:
        PK_me = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_WRAP)
    return PK_me, template


def _get_PKSC11_mechanism_W(do_padd: bool):
    PK_me = None
    if do_padd:
        PK_me = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_WRAP_KWP)
    else:
        PK_me = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_WRAP)
    return PK_me


def _get_import_template(key_bytes: bytes):
    return [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
        (PyKCS11.CKA_VALUE, key_bytes),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
    ]


class AESWrapAlgorithmProperties(SymetricAlgorithmProperties):
    def __init__(self, key_length_bytes: int, do_hw_padd: bool = False):
        super().__init__(key_length_bytes)
        self._do_padd = do_hw_padd

    @classmethod
    def from_name(cls, name: str):
        if name in wrap_name_map:
            props = wrap_name_map[name]
            klb = props["key_length_bytes"]
            do_padd = props["padded"]
            if isinstance(klb, int) and isinstance(do_padd, bool):
                return cls(klb, do_padd)
        else:
            return None

    def get_generate_template(self):
        return [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_VALUE_LEN, self._key_length_bytes),
            (
                PyKCS11.CKA_TOKEN,
                PyKCS11.CK_FALSE,
            ),  # TODO: what if someone wants nonsession. Is this OK??
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            # (
            #     PyKCS11.CKA_EXTRACTABLE,
            #     PyKCS11.CK_FALSE,
            # ),  # if just to encrypt, then it also needs to be token key
            (
                PyKCS11.CKA_EXTRACTABLE,
                PyKCS11.CK_TRUE,
            ),  # if just to wrap
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
        ]

    def get_import_template(self, key_bytes: bytes):
        return [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_VALUE, key_bytes),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
        ]

    def wrap_sw(self, wrapping_key: bytes, key_to_wrap: bytes) -> bytes:
        ret = None
        if self._do_padd:
            ret = aes_key_wrap_with_padding(
                wrapping_key, key_to_wrap, default_backend()
            )
        else:
            ret = aes_key_wrap(wrapping_key, key_to_wrap, default_backend())
        return ret

    def unwrap_sw(self, wrapping_key: bytes, wrapped_key: bytes) -> bytes:
        ret = None
        if self._do_padd:
            ret = aes_key_unwrap_with_padding(
                wrapping_key, wrapped_key, default_backend()
            )
        else:
            ret = aes_key_unwrap(wrapping_key, wrapped_key, default_backend())
        return ret

    def get_PKCS11_key(self, session, h_derived_key):
        return PKCS11AESWrap(session, h_derived_key, self._do_padd)

    def create_PKCS11_key_from_bytes(self, session, key_bytes: bytes):
        return PKCS11AESWrap.create_from_bytes(
            session, key_bytes, self._do_padd
        )


class PKCS11AESWrap(object):
    def __init__(self, session, h_key, do_padd):
        self._session = session
        self._key = h_key
        self._do_padd = do_padd

    @classmethod
    def create_from_bytes(cls, session, key_bytes: bytes, do_padd: bool):
        imported_key_template = _get_import_template(key_bytes)
        h_key = session.createObject(imported_key_template)
        return cls(session, h_key, do_padd)

    def unwrap(
        self,
        wrapped_key: bytes,
        unwrapped_key_props: SymetricAlgorithmProperties,
    ):
        if self._session is not None:
            PK_me, template = _get_PKSC11_mechanism_U(self._do_padd)
            if PK_me is not None:
                h_key_ref = self._session.unwrapKey(
                    self._key, wrapped_key, template, mecha=PK_me
                )
                if hasattr(unwrapped_key_props, "get_PKCS11_key"):
                    return unwrapped_key_props.get_PKCS11_key(
                        self._session, h_key_ref
                    )
                else:
                    self._session.destroyObect(h_key_ref)
                    raise KeyException(
                        "Derived key can not be used. Key object type not found."
                    )
            else:
                raise UnsupportedAlgorithm("Mechanism for unwrap not found")
        else:
            raise SessionException("Session to card missing")

    def wrap(
        self,
        h_key_to_wrap: int,
    ) -> bytes:
        if self._session is not None:
            PK_me = _get_PKSC11_mechanism_W(self._do_padd)
            if PK_me is not None:
                wrapped_key = self._session.wrapKey(
                    self._key, h_key_to_wrap, mecha=PK_me
                )
                return bytes(wrapped_key)
            else:
                raise UnsupportedAlgorithm("Mechanism for wrap not found")
        else:
            raise SessionException("Session to card missing")

    def destroy_key(self):
        self._session.destroyObject(self._key)


def get_wrap_algorithm_properties(encryption_algorithm: str):
    if encryption_algorithm in wrap_name_map:
        return AESWrapAlgorithmProperties.from_name(encryption_algorithm)
    else:
        return None
