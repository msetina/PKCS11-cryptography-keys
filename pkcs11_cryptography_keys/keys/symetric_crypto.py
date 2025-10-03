from secrets import token_bytes
from typing import Dict

import PyKCS11
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from ..card_token.PKCS11_key_definition import read_key_usage_from_key
from ..utils.exceptions import SessionException

_symetric_key_mechanism_map = {
    PyKCS11.CKM_AES_CBC_PAD: {
        "ENCRYPT": {
            "aes128_cbc": {"length": 16, "unit": "bytes", "hw_padd": True},
            "aes192_cbc": {"length": 24, "unit": "bytes", "hw_padd": True},
            "aes256_cbc": {"length": 32, "unit": "bytes", "hw_padd": True},
        },
        "DECRYPT": {
            "aes128_cbc": {"length": 16, "unit": "bytes", "hw_padd": True},
            "aes192_cbc": {"length": 24, "unit": "bytes", "hw_padd": True},
            "aes256_cbc": {"length": 32, "unit": "bytes", "hw_padd": True},
        },
    },
    PyKCS11.CKM_AES_CBC: {
        "ENCRYPT": {
            "aes128_cbc": {"length": 16, "unit": "bytes"},
            "aes192_cbc": {"length": 24, "unit": "bytes"},
            "aes256_cbc": {"length": 32, "unit": "bytes"},
        },
        "DECRYPT": {
            "aes128_cbc": {"length": 16, "unit": "bytes"},
            "aes192_cbc": {"length": 24, "unit": "bytes"},
            "aes256_cbc": {"length": 32, "unit": "bytes"},
        },
    },
    PyKCS11.CKM_AES_GCM: {
        "ENCRYPT": {
            "aes128_gcm": {"length": 16, "unit": "bytes"},
            "aes192_gcm": {"length": 24, "unit": "bytes"},
            "aes256_gcm": {"length": 32, "unit": "bytes"},
        },
        "DECRYPT": {
            "aes128_gcm": {"length": 16, "unit": "bytes"},
            "aes192_gcm": {"length": 24, "unit": "bytes"},
            "aes256_gcm": {"length": 32, "unit": "bytes"},
        },
    },
}


def get_symetric_key_translation(method, PKCS11_mechanism, properties):
    mm = PyKCS11.CKM[PKCS11_mechanism]
    if (
        mm in _symetric_key_mechanism_map
        and method in _symetric_key_mechanism_map[mm]
    ):
        definition = _symetric_key_mechanism_map[mm][method]
        key_types = {}
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
                    key_types[nm] = key_def
        return key_types


class SymetricAlgorithmProperties(object):
    def __init__(self, key_length_bytes: int):
        self._key_length_bytes = key_length_bytes

    def get_key_length(self):
        return self._key_length_bytes

    def get_mechanism(self, **kwargs):
        raise NotImplementedError("Abstract class can not produce a mechanism")

    def get_import_template(self, key_bytes: bytes):
        raise NotImplementedError("Abstract class can not produce a template")

    def get_generate_template(self):
        return NotImplementedError("Abstract class can not produce a template")

    def generate_key(self):
        return token_bytes(self._key_length_bytes)

    def get_nonce(self):
        return None


class SymetricCipherProperties(SymetricAlgorithmProperties):
    def __init__(self, key_length_bytes):
        super().__init__(key_length_bytes)

    def get_sw_decryptor(self, key: bytes, **kwargs):
        raise NotImplementedError("Software decryptor not implemented")

    def get_sw_encryptor(self, key: bytes, **kwargs):
        raise NotImplementedError("Software decryptor not implemented")

    def get_encrypted_data(self, ciphertext: bytes, **kwargs):
        return ciphertext

    def post_hsm_encryption(self, hsm_encrypted_data: bytes):
        return hsm_encrypted_data, None

    def post_decryption(self, content: bytes):
        return content

    def pre_encryption(self, content: bytes):
        return content

    def get_PKCS11_key(self, session, h_derived_key):
        return SymetricKeyPKCS11(session, h_derived_key, self)


# Translation from mechanism read from the card to parameters needed for cryptography API
# At init time this is used to for operations list for later use in function calls as card limitations
_digest_algorithm_implementations: Dict[str, Dict] = {
    PyKCS11.CKM_SHA_1: {"DIGEST": {"hash": hashes.SHA1}},
    PyKCS11.CKM_SHA224: {"DIGEST": {"hash": hashes.SHA224}},
    PyKCS11.CKM_SHA384: {"DIGEST": {"hash": hashes.SHA384}},
    PyKCS11.CKM_SHA256: {"DIGEST": {"hash": hashes.SHA256}},
    PyKCS11.CKM_SHA512: {"DIGEST": {"hash": hashes.SHA512}},
    PyKCS11.CKM_AES_CBC: {
        "UNWRAP": {"mode": modes.CBC, "algo": algorithms.AES},
        "WRAP": {"mode": modes.CBC, "algo": algorithms.AES},
        "ENCRYPT": {"mode": modes.CBC, "algo": algorithms.AES},
        "DECRYPT": {"mode": modes.CBC, "algo": algorithms.AES},
    },
    PyKCS11.CKM_AES_GCM: {
        "ENCRYPT": {"mode": modes.GCM, "algo": algorithms.AES},
        "DECRYPT": {"mode": modes.GCM, "algo": algorithms.AES},
        "UNWRAP": {"mode": modes.GCM, "algo": algorithms.AES},
        "WRAP": {"mode": modes.GCM, "algo": algorithms.AES},
    },
    PyKCS11.CKM_AES_ECB: {
        "UNWRAP": {"mode": modes.ECB, "algo": algorithms.AES},
        "WRAP": {"mode": modes.ECB, "algo": algorithms.AES},
    },
}


def _get_PKSC11_mechanism_ED(props: SymetricCipherProperties, **kwargs):
    PK_me = props.get_mechanism(**kwargs)
    return PK_me


def _get_PKSC11_mechanism_U(operation_dict, mode):
    PK_me = None
    pcls = mode.__class__
    template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_FALSE),
    ]
    if pcls in operation_dict:
        if pcls == modes.ECB:
            PK_me = PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB)
    return PK_me, template


def _get_PKSC11_mechanism_W(operation_dict, mode):
    PK_me = None
    pcls = mode.__class__
    if pcls in operation_dict:
        if pcls == modes.ECB:
            PK_me = PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB)
    return PK_me


class SymetricKeyPKCS11:
    def __init__(
        self,
        session,
        key_ref,
        key_props: SymetricCipherProperties,
    ):
        # session for interacton with the card
        self._session = session
        # private key reference
        self._key = key_ref
        # key algorithm
        self._key_props = key_props
        # operations supported by the card
        # they are separated in method groups (DIGEST,ENCRYPT,DECRYPT)
        self._operations: Dict[str, Dict] = {}

    @classmethod
    def create_from_bytes(
        cls,
        session,
        key_bytes: bytes,
        key_props: SymetricCipherProperties,
    ):
        imported_key_template = key_props.get_import_template(key_bytes)
        h_key = session.createObject(imported_key_template)
        return cls(session, h_key, key_props)

    @classmethod
    def generate_key(cls, session, key_props: SymetricCipherProperties):
        gen_key_template = key_props.get_generate_template()
        h_key = session.generateKey(gen_key_template)
        return cls(session, h_key, key_props)

    def read_key_usage(self):
        return read_key_usage_from_key(self._session, self._key)

    # At the init time the call to fill_operations will translate method
    # and mechanism to parameters form cryptography API calls
    def fill_operations(
        self, PKCS11_mechanism, method: str, properties: dict
    ) -> None:
        mm = None
        try:
            if method in [
                "DIGEST",
                "UNWRAP",
                "WRAP",
                "ENCRYPT",
                "DECRYPT",
            ]:
                mm = self._get_mechanism_translation(
                    method, PKCS11_mechanism, properties
                )
        except Exception:
            pass
        if mm:
            lgth = len(mm)
            if method not in self._operations:
                self._operations[method] = {}
            p = self._operations[method]
            for idx, k in enumerate(mm, start=1):
                if idx == lgth:
                    p[k] = PyKCS11.CKM[PKCS11_mechanism]
                else:
                    if k in p:
                        p = p[k]
                    else:
                        p[k] = {}
                        p = p[k]

    # Register mechanism to operation as card capability
    def _get_mechanism_translation(self, method, PKCS11_mechanism, properties):
        mm = PyKCS11.CKM[PKCS11_mechanism]
        if (
            mm in _digest_algorithm_implementations
            and method in _digest_algorithm_implementations[mm]
        ):
            definition = _digest_algorithm_implementations[mm][method]
            if method in [
                "ENCRYPT",
                "DECRYPT",
                "UNWRAP",
                "WRAP",
            ]:
                return [definition["algo"], definition["mode"]]
            else:
                return []
        else:
            raise SessionException("Session to card missing")

    def _sw_decrypt(self, data, key, **kwargs):
        decryptor = self._key_props.get_sw_decryptor(key, **kwargs)
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        return decrypted_data

    def _sw_encrypt(self, data, key, **kwargs):
        encryptor = self._key_props.get_sw_encryptor(key, **kwargs)
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        if hasattr(encryptor, "tag"):
            tag = encryptor.tag
            return encrypted_data, tag
        else:
            return encrypted_data, None

    def extract_key(self):
        try:
            attributes = self._session.getAttributeValue(
                self._key, [PyKCS11.CKA_VALUE]
            )
            return bytes(attributes[0])
        except Exception:
            return None

    def encrypt(self, data: bytes, **kwargs) -> tuple[bytes, bytes]:
        if self._session is not None:
            # if "ENCRYPT" in self._operations:
            PK_me = _get_PKSC11_mechanism_ED(self._key_props, **kwargs)
            data_to_encrypt = self._key_props.pre_encryption(data)
            if PK_me is not None:
                hsm_encrypted_data = self._session.encrypt(
                    self._key, data_to_encrypt, PK_me
                )
                e_d = bytes(hsm_encrypted_data)
                encrypted_data, tag = self._key_props.post_hsm_encryption(e_d)
                return encrypted_data, tag
            else:
                attributes = self._session.getAttributeValue(
                    self._key, [PyKCS11.CKA_VALUE]
                )
                key_bytes = bytes(attributes[0])
                encrypted_data, tag = self._sw_encrypt(
                    data_to_encrypt, key_bytes, **kwargs
                )
                return encrypted_data, tag
        # else:
        #    raise UnsupportedAlgorithm("Encrypt not supported by card.")
        else:
            raise SessionException("Session to card missing")

    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        if self._session is not None:
            # if "DECRYPT" in self._operations:
            PK_me = _get_PKSC11_mechanism_ED(self._key_props, **kwargs)
            if PK_me is not None:
                encrypted_data = self._key_props.get_encrypted_data(
                    ciphertext, **kwargs
                )
                decrypted_data = self._session.decrypt(
                    self._key, encrypted_data, PK_me
                )
                return self._key_props.post_decryption(bytes(decrypted_data))
            else:
                attributes = self._session.getAttributeValue(
                    self._key, [PyKCS11.CKA_VALUE]
                )
                key_bytes = bytes(attributes[0])
                decrypted_data = self._sw_decrypt(ciphertext, key_bytes)
                return self._key_props.post_decryption(decrypted_data)
            # else:
            #    raise UnsupportedAlgorithm("Decrypt not supported by card.")
        else:
            raise SessionException("Session to card missing")

    def unwrap(
        self,
        wrapped_key: bytes,
        unwrapped_key_props: SymetricCipherProperties,
    ):
        if self._session is not None:
            if "UNWRAP" in self._operations:
                PK_me, template = _get_PKSC11_mechanism_U(
                    self._operations["UNWRAP"],
                    modes.ECB,
                )
                if PK_me is not None:
                    h_key_ref = self._session.unwrapKey(
                        self._key, wrapped_key, template, mecha=PK_me
                    )
                    return SymetricKeyPKCS11(
                        self._session, h_key_ref, unwrapped_key_props
                    )
                else:
                    raise UnsupportedAlgorithm("Mechanism for unwrap not found")
            else:
                raise UnsupportedAlgorithm("Unwrap not supported by card.")
        else:
            raise SessionException("Session to card missing")

    def wrap(self, h_key_to_wrap: int) -> bytes:
        if self._session is not None:
            if "UNWRAP" in self._operations:
                PK_me = _get_PKSC11_mechanism_W(
                    self._operations["WRAP"], modes.ECB
                )
                if PK_me is not None:
                    wrapped_key = self._session.wrapKey(
                        self._key, h_key_to_wrap, mecha=PK_me
                    )
                    return bytes(wrapped_key)
                else:
                    raise UnsupportedAlgorithm("Mechanism for wrap not found")
            else:
                raise UnsupportedAlgorithm("Wrap not supported by card.")
        else:
            raise SessionException("Session to card missing")

    def destroy_key(self):
        self._session.destroyObject(self._key)

    def get_key_handle(self):
        return self._key
