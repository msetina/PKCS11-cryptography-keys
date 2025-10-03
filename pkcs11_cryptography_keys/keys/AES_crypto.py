from secrets import token_bytes

import PyKCS11
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from .symetric_crypto import SymetricCipherProperties


class AESAlgorithmProperties(SymetricCipherProperties):
    def __init__(self, key_length_bytes: int):
        super().__init__(key_length_bytes)

    @classmethod
    def from_name(cls, name: str):
        if name in AES_key_props:
            props = AES_key_props[name]
            klb = props["key_length_bytes"]
            if isinstance(klb, int):
                return cls(klb)
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
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
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
            (PyKCS11.CKA_WRAP, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_FALSE),
        ]


class AESAlgorithmPropertiesECB(AESAlgorithmProperties):
    def __init__(self, key_length_bytes: int):
        super().__init__(key_length_bytes)

    def get_mechanism(self, **kwargs):
        PK_me = PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB)
        return PK_me


class AESAlgorithmPropertiesCBC(AESAlgorithmProperties):
    def __init__(self, iv: bytes, key_length_bytes: int, hw_padd: bool = False):
        super().__init__(key_length_bytes)
        self._iv = iv
        self._hw_padd = hw_padd

    @classmethod
    def create(cls, key_length_bytes: int, **kwargs):
        if "iv" in kwargs:
            iv = kwargs["iv"]
        else:
            iv = token_bytes(16)
        if "hw_padd" in kwargs:
            return cls(iv, key_length_bytes, kwargs["hw_padd"])
        else:
            return cls(iv, key_length_bytes)

    def get_nonce(self):
        return self._iv

    def get_mechanism(self, **kwargs):
        if self._hw_padd:
            PK_me = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC_PAD, self._iv)
        else:
            PK_me = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC, self._iv)

        return PK_me

    def get_sw_decryptor(self, key: bytes, **kwargs):
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(self._iv),
            default_backend(),
        )
        return cipher.decryptor()

    def get_sw_encryptor(self, key: bytes, **kwargs):
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(self._iv),
            default_backend(),
        )
        return cipher.encryptor()

    def post_decryption(self, content: bytes):
        if not self._hw_padd:
            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            return unpadder.update(content) + unpadder.finalize()
        else:
            return content

    def pre_encryption(self, content: bytes):
        if not self._hw_padd:
            padder = PKCS7(algorithms.AES.block_size).padder()
            return padder.update(content) + padder.finalize()
        else:
            return content


class AESAlgorithmPropertiesGCM(AESAlgorithmProperties):
    def __init__(
        self,
        nonce: bytes,
        key_length_bytes: int,
        tag_bits: int = 128,
    ):
        super().__init__(key_length_bytes)
        self._nonce = nonce
        self._tag_bits = tag_bits

    @classmethod
    def create(cls, key_length_bytes: int, **kwargs):
        if "tag_bits" in kwargs:
            tag_bits: int = kwargs["tag_bits"]
        else:
            tag_bits = 128
        if "iv" in kwargs:
            iv = kwargs["iv"]
        else:
            iv = token_bytes(12)
        return cls(iv, key_length_bytes, tag_bits)

    def get_nonce(self):
        return self._nonce

    def get_mechanism(self, **kwargs):
        if "aad" in kwargs:
            aad = kwargs["aad"]
        else:
            aad = None
        PK_me = PyKCS11.AES_GCM_Mechanism(self._nonce, aad, self._tag_bits)
        return PK_me

    def get_encrypted_data(self, ciphertext: bytes, **kwargs):
        if "received_tag" in kwargs:
            received_tag = kwargs["received_tag"]
            return ciphertext + received_tag
        else:
            return ciphertext

    def post_hsm_encryption(self, hsm_encrypted_data: bytes):
        tag_length_in_bytes = self._tag_bits // 8
        ciphertext = hsm_encrypted_data[:-tag_length_in_bytes]
        tag = hsm_encrypted_data[-tag_length_in_bytes:]
        return ciphertext, tag

    def get_sw_decryptor(self, key: bytes, **kwargs):
        received_tag = None
        if "received_tag" in kwargs:
            received_tag = kwargs["received_tag"]
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(self._nonce, received_tag),
            default_backend(),
        )
        decryptor = cipher.decryptor()
        if "aad" in kwargs:
            decryptor.authenticate_additional_data(kwargs["aad"])
        return decryptor

    def get_sw_encryptor(self, key: bytes, **kwargs):
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(self._nonce),
            default_backend(),
        )
        encryptor = cipher.encryptor()
        if "aad" in kwargs:
            encryptor.authenticate_additional_data(kwargs["aad"])
        return encryptor


AES_key_props = {
    "aes128_cbc": {
        "mode": modes.CBC,
        "algo": algorithms.AES,
        "key_length_bytes": 16,
        "prop_class": AESAlgorithmPropertiesCBC,
    },
    "aes192_cbc": {
        "mode": modes.CBC,
        "algo": algorithms.AES,
        "key_length_bytes": 24,
        "prop_class": AESAlgorithmPropertiesCBC,
    },
    "aes256_cbc": {
        "mode": modes.CBC,
        "algo": algorithms.AES,
        "key_length_bytes": 32,
        "prop_class": AESAlgorithmPropertiesCBC,
    },
    "aes128_gcm": {
        "mode": modes.GCM,
        "algo": algorithms.AES,
        "key_length_bytes": 16,
        "prop_class": AESAlgorithmPropertiesGCM,
    },
    "aes192_gcm": {
        "mode": modes.GCM,
        "algo": algorithms.AES,
        "key_length_bytes": 24,
        "prop_class": AESAlgorithmPropertiesGCM,
    },
    "aes256_gcm": {
        "mode": modes.GCM,
        "algo": algorithms.AES,
        "key_length_bytes": 32,
        "prop_class": AESAlgorithmPropertiesGCM,
    },
}


def get_AES_key_props_from_algorithm_name(encryption_algorithm: str):
    if encryption_algorithm in AES_key_props:
        return AES_key_props[encryption_algorithm]
    else:
        return None


def get_AES_algorithm_properties(encryption_algorithm: str, **kwargs):
    e_props = get_AES_key_props_from_algorithm_name(encryption_algorithm)
    if e_props:
        key_length_bytes = e_props["key_length_bytes"]
        if isinstance(key_length_bytes, int):
            if e_props["prop_class"] == AESAlgorithmPropertiesGCM:
                return AESAlgorithmPropertiesGCM.create(
                    key_length_bytes, **kwargs
                )
            elif e_props["prop_class"] == AESAlgorithmPropertiesCBC:
                return AESAlgorithmPropertiesCBC.create(
                    key_length_bytes, **kwargs
                )
        else:
            return None
    else:
        return None
