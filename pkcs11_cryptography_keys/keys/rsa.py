# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii
from typing import Dict

import PyKCS11
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import _serialization, hashes
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.padding import (
    OAEP,
    PSS,
    PKCS1v15,
    calculate_max_pss_salt_length,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPrivateNumbers,
    RSAPublicKey,
    RSAPublicNumbers,
)

from pkcs11_cryptography_keys.card_token.PKCS11_token import PKCS11Token

# Translation from mechanism read from the card to parameters needed for cryptography API
# At init time this is used to for operations list for later use in function calls as card limitations
_digest_algorithm_implementations: Dict[str, Dict] = {
    PyKCS11.CKM_SHA_1: {"DIGEST": {"hash": hashes.SHA1}},
    PyKCS11.CKM_SHA224: {"DIGEST": {"hash": hashes.SHA224}},
    PyKCS11.CKM_SHA384: {"DIGEST": {"hash": hashes.SHA384}},
    PyKCS11.CKM_SHA256: {"DIGEST": {"hash": hashes.SHA256}},
    PyKCS11.CKM_SHA512: {"DIGEST": {"hash": hashes.SHA512}},
    PyKCS11.CKM_RSA_PKCS: {
        "SIGN": {"hash": asym_utils.Prehashed, "pad": PKCS1v15},
        "VERIFY": {"hash": asym_utils.Prehashed, "pad": PKCS1v15},
        "ENCRYPT": {"hash": asym_utils.Prehashed, "pad": PKCS1v15},
        "DECRYPT": {"hash": asym_utils.Prehashed, "pad": PKCS1v15},
    },
    PyKCS11.CKM_SHA224_RSA_PKCS: {
        "SIGN": {"hash": hashes.SHA224, "pad": PKCS1v15},
        "VERIFY": {"hash": hashes.SHA224, "pad": PKCS1v15},
        "ENCRYPT": {"hash": hashes.SHA224, "pad": PKCS1v15},
        "DECRYPT": {"hash": hashes.SHA224, "pad": PKCS1v15},
    },
    PyKCS11.CKM_SHA256_RSA_PKCS: {
        "SIGN": {"hash": hashes.SHA256, "pad": PKCS1v15},
        "VERIFY": {"hash": hashes.SHA256, "pad": PKCS1v15},
        "ENCRYPT": {"hash": hashes.SHA256, "pad": PKCS1v15},
        "DECRYPT": {"hash": hashes.SHA256, "pad": PKCS1v15},
    },
    PyKCS11.CKM_SHA384_RSA_PKCS: {
        "SIGN": {"hash": hashes.SHA384, "pad": PKCS1v15},
        "VERIFY": {"hash": hashes.SHA384, "pad": PKCS1v15},
        "ENCRYPT": {"hash": hashes.SHA384, "pad": PKCS1v15},
        "DECRYPT": {"hash": hashes.SHA384, "pad": PKCS1v15},
    },
    PyKCS11.CKM_SHA512_RSA_PKCS: {
        "SIGN": {"hash": hashes.SHA512, "pad": PKCS1v15},
        "VERIFY": {"hash": hashes.SHA512, "pad": PKCS1v15},
        "ENCRYPT": {"hash": hashes.SHA512, "pad": PKCS1v15},
        "DECRYPT": {"hash": hashes.SHA512, "pad": PKCS1v15},
    },
    PyKCS11.CKM_SHA1_RSA_PKCS: {
        "SIGN": {"hash": hashes.SHA1, "pad": PKCS1v15},
        "VERIFY": {"hash": hashes.SHA1, "pad": PKCS1v15},
        "ENCRYPT": {"hash": hashes.SHA1, "pad": PKCS1v15},
        "DECRYPT": {"hash": hashes.SHA1, "pad": PKCS1v15},
    },
    PyKCS11.CKM_RSA_PKCS_PSS: {
        "SIGN": {"hash": asym_utils.Prehashed, "pad": PSS},
        "VERIFY": {"hash": asym_utils.Prehashed, "pad": PSS},
        "ENCRYPT": {"hash": asym_utils.Prehashed, "pad": PSS},
        "DECRYPT": {"hash": asym_utils.Prehashed, "pad": PSS},
    },
    PyKCS11.CKM_SHA224_RSA_PKCS_PSS: {
        "SIGN": {"hash": hashes.SHA224, "pad": PSS},
        "VERIFY": {"hash": hashes.SHA224, "pad": PSS},
        "ENCRYPT": {"hash": hashes.SHA224, "pad": PSS},
        "DECRYPT": {"hash": hashes.SHA224, "pad": PSS},
    },
    PyKCS11.CKM_SHA256_RSA_PKCS_PSS: {
        "SIGN": {"hash": hashes.SHA256, "pad": PSS},
        "VERIFY": {"hash": hashes.SHA256, "pad": PSS},
        "ENCRYPT": {"hash": hashes.SHA256, "pad": PSS},
        "DECRYPT": {"hash": hashes.SHA256, "pad": PSS},
    },
    PyKCS11.CKM_SHA384_RSA_PKCS_PSS: {
        "SIGN": {"hash": hashes.SHA384, "pad": PSS},
        "VERIFY": {"hash": hashes.SHA384, "pad": PSS},
        "ENCRYPT": {"hash": hashes.SHA384, "pad": PSS},
        "DECRYPT": {"hash": hashes.SHA384, "pad": PSS},
    },
    PyKCS11.CKM_SHA512_RSA_PKCS_PSS: {
        "SIGN": {"hash": hashes.SHA512, "pad": PSS},
        "VERIFY": {"hash": hashes.SHA512, "pad": PSS},
        "ENCRYPT": {"hash": hashes.SHA512, "pad": PSS},
        "DECRYPT": {"hash": hashes.SHA512, "pad": PSS},
    },
    PyKCS11.CKM_SHA1_RSA_PKCS_PSS: {
        "SIGN": {"hash": hashes.SHA1, "pad": PSS},
        "VERIFY": {"hash": hashes.SHA1, "pad": PSS},
        "ENCRYPT": {"hash": hashes.SHA1, "pad": PSS},
        "DECRYPT": {"hash": hashes.SHA1, "pad": PSS},
    },
    PyKCS11.CKM_RSA_PKCS_OAEP: {
        "SIGN": {"hash": asym_utils.Prehashed, "pad": OAEP},
        "VERIFY": {"hash": asym_utils.Prehashed, "pad": OAEP},
        "ENCRYPT": {"hash": asym_utils.Prehashed, "pad": OAEP},
        "DECRYPT": {"hash": asym_utils.Prehashed, "pad": OAEP},
    },
}

mgf_methods = {
    hashes.SHA1: PyKCS11.CKG_MGF1_SHA1,
    hashes.SHA224: PyKCS11.CKG_MGF1_SHA224,
    hashes.SHA256: PyKCS11.CKG_MGF1_SHA256,
    hashes.SHA384: PyKCS11.CKG_MGF1_SHA384,
    hashes.SHA512: PyKCS11.CKG_MGF1_SHA512,
    # hashes.SHA3_224: PyKCS11.CKG_MGF1_SHA3_224,
    # hashes.SHA3_256: PyKCS11.CKG_MGF1_SHA3_256,
    # hashes.SHA3_384: PyKCS11.CKG_MGF1_SHA3_384,
    # hashes.SHA3_512: PyKCS11.CKG_MGF1_SHA3_512,
}


def _get_salt_length_int(key, hash, padding):
    ret = 0
    if isinstance(padding._salt_length, int):
        ret = padding._salt_length
    elif padding._salt_length is padding.DIGEST_LENGTH:
        ret = hash.digest_size
    elif padding._salt_length is padding.AUTO:
        raise UnsupportedAlgorithm("AUTO is not supported")
    elif padding._salt_length is padding.MAX_LENGTH:
        ret = calculate_max_pss_salt_length(key, hash)
    return ret


# Get PKCS11 mechanism from hashing algorithm and padding information for sign/verify
def _get_PKSC11_mechanism_SV(
    operation_dict, algorithm, padding, digest_dict, key
):
    PK_me = None
    cls = algorithm.__class__
    pcls = padding.__class__
    if cls in operation_dict and pcls in operation_dict[cls]:
        mech = operation_dict[cls][pcls]
        if pcls == PKCS1v15:
            PK_me = PyKCS11.Mechanism(mech)
        if pcls == PSS:
            mc = padding.mgf._algorithm.__class__
            mgf = mgf_methods[mc]
            hash = digest_dict[mc]
            salt = _get_salt_length_int(key, mc, padding)
            PK_me = PyKCS11.RSA_PSS_Mechanism(
                mech,
                hash,
                mgf,
                salt,
            )
        if pcls == OAEP:
            raise Exception("OAEP is not supported for signing")
    return PK_me


# Get PKCS11 mechanism from padding information for encryption/decryption


def _get_PKSC11_mechanism_ED(operation_dict, padding, digest_dict, key):
    PK_me = None
    pcls = padding.__class__
    if pcls in operation_dict:
        if pcls == PKCS1v15:
            PK_me = PyKCS11.MechanismRSAPKCS1
        if pcls == PSS:
            mc = padding.mgf._algorithm.__class__
            padding.mgf
            mgf = mgf_methods[mc]
            hash = digest_dict[mc]
            mech = operation_dict[pcls]
            salt = _get_salt_length_int(key, mc, padding)
            PK_me = PyKCS11.RSA_PSS_Mechanism(mech, hash, mgf, salt)
        if pcls == OAEP:
            mc = padding.mgf._algorithm.__class__
            hc = padding.algorithm.__class__
            hash = digest_dict[hc]
            mgf = mgf_methods[mc]
            PK_me = PyKCS11.RSAOAEPMechanism(hash, mgf)
    return PK_me


class RSAPublicKeyPKCS11:
    def __init__(self, session, public_key, operations: dict):
        self._session = session
        self._public_key = public_key
        self._operations = operations

    # cryptography API
    def encrypt(self, plaintext: bytes, padding: AsymmetricPadding) -> bytes:
        if self._session is not None:
            if "ENCRYPT" in self._operations and "DIGEST" in self._operations:
                PK_me = _get_PKSC11_mechanism_ED(
                    self._operations["ENCRYPT"],
                    padding,
                    self._operations["DIGEST"],
                    self,
                )
                if PK_me is not None:
                    encrypted_text = self._session.encrypt(
                        self._public_key, plaintext, PK_me
                    )
                else:
                    raise UnsupportedAlgorithm(
                        "Algorithm not supported: {0}".format(padding.__class__)
                    )
                return bytes(encrypted_text)
            else:
                raise UnsupportedAlgorithm(
                    "Encryption is not supported by card"
                )
        else:
            raise PyKCS11.PyKCS11Error("Session to card missing")

    @property
    def key_size(self) -> int:
        if self._session is not None:
            attrs = self._session.getAttributeValue(
                self._public_key,
                [PyKCS11.CKA_MODULUS_BITS],
            )
            if len(attrs) > 0 and attrs[0] is not None:
                return int(attrs[0])
            else:
                raise PyKCS11.PyKCS11Error("CKA_MODULUS_BITS not set")
        else:
            raise PyKCS11.PyKCS11Error("Session to card missing")

    def public_numbers(self) -> RSAPublicNumbers:
        if self._session is not None:
            attrs = self._session.getAttributeValue(
                self._public_key,
                [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT],
            )
            m = int(binascii.hexlify(bytearray(attrs[0])), 16)
            e = int(binascii.hexlify(bytearray(attrs[1])), 16)
            return RSAPublicNumbers(e, m)
        else:
            raise PyKCS11.PyKCS11Error("Session to card missing")

    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        if self._session is not None:
            pn = self.public_numbers()
            key = pn.public_key()
            return key.public_bytes(encoding, format)
        else:
            raise PyKCS11.PyKCS11Error("Session to card missing")

    def verify(
        self,
        signature: bytes,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: asym_utils.Prehashed | hashes.HashAlgorithm,
    ) -> None:
        if self._session != None:
            if "VERIFY" in self._operations and "DIGEST" in self._operations:
                PK_me = _get_PKSC11_mechanism_SV(
                    self._operations["VERIFY"],
                    algorithm,
                    padding,
                    self._operations["DIGEST"],
                    self,
                )
                rez = False
                if PK_me is None:
                    raise UnsupportedAlgorithm(
                        "Algorithm not supported: {0} + {1}".format(
                            padding.__class__, algorithm.__class__
                        )
                    )
                else:
                    rez = self._session.verify(
                        self._public_key, data, signature, PK_me
                    )
                if not rez:
                    raise InvalidSignature("Signature verification failed.")
            else:
                raise UnsupportedAlgorithm("Verify not supported by card")
        else:
            raise PyKCS11.PyKCS11Error("Session to card missing")

    def recover_data_from_signature(
        self,
        signature: bytes,
        padding: AsymmetricPadding,
        algorithm: hashes.HashAlgorithm | None,
    ) -> bytes:
        raise NotImplementedError(
            "Recover data from signature not implemented yet"
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RSAPublicKeyPKCS11):
            return self._public_key == other._public_key
        else:
            return False


RSAPublicKeyWithSerialization = RSAPublicKeyPKCS11
RSAPublicKey.register(RSAPublicKeyPKCS11)


class RSAPrivateKeyPKCS11(PKCS11Token):
    def __init__(self, session, keyid, pk_ref):
        super().__init__(session, keyid, pk_ref)

    # Register mechanism to operation as card capability
    def _get_mechanism_translation(self, method, PKCS11_mechanism):
        mm = PyKCS11.CKM[PKCS11_mechanism]
        if (
            mm in _digest_algorithm_implementations
            and method in _digest_algorithm_implementations[mm]
        ):
            definition = _digest_algorithm_implementations[mm][method]
            if method in [
                "SIGN",
                "VERIFY",
            ]:
                return [definition["hash"], definition["pad"]]
            elif method in [
                "ENCRYPT",
                "DECRYPT",
            ]:
                return [definition["pad"]]
            elif method in ["DIGEST"]:
                return [definition["hash"]]
            else:
                return []
        else:
            raise PyKCS11.PyKCS11Error("Session to card missing")

    # cryptography API
    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        if self._session is not None:
            if "DECRYPT" in self._operations and "DIGEST" in self._operations:
                PK_me = _get_PKSC11_mechanism_ED(
                    self._operations["DECRYPT"],
                    padding,
                    self._operations["DIGEST"],
                    self,
                )
                if PK_me is not None:
                    decrypted_text = self._session.decrypt(
                        self._private_key, ciphertext, PK_me
                    )
                else:
                    raise UnsupportedAlgorithm(
                        "Algorithm not supported: {0}".format(padding.__class__)
                    )
                return bytes(decrypted_text)
            else:
                raise UnsupportedAlgorithm("Decrypt not supported by card.")
        else:
            raise PyKCS11.PyKCS11Error("Session to card missing")

    @property
    def key_size(self) -> int:
        if self._session is not None:
            attrs = self._session.getAttributeValue(
                self._private_key,
                [PyKCS11.CKA_MODULUS_BITS],
            )
            if len(attrs) > 0 and attrs[0] is not None:
                return int(attrs[0])
            else:
                public = self.public_key()
                if public is not None:
                    return public.key_size
        else:
            raise PyKCS11.PyKCS11Error("Session to card missing")

    def public_key(self) -> RSAPublicKeyPKCS11:
        if self._session is not None:
            pubkey_o = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            if len(pubkey_o) > 0:
                pubkey = pubkey_o[0]
                return RSAPublicKeyPKCS11(
                    self._session, pubkey, self._operations
                )
            else:
                raise Exception(
                    "Public key with id {0!r} not found".format(self._keyid)
                )

        else:
            raise PyKCS11.PyKCS11Error("Session to card missing")

    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: asym_utils.Prehashed | hashes.HashAlgorithm,
    ) -> bytes:
        if "SIGN" in self._operations and "DIGEST" in self._operations:
            PK_me = _get_PKSC11_mechanism_SV(
                self._operations["SIGN"],
                algorithm,
                padding,
                self._operations["DIGEST"],
                self,
            )
            if PK_me is not None:
                sig = self._sign(data, PK_me)
                return bytes(sig)
            else:
                raise UnsupportedAlgorithm(
                    "Not supported. algorithm: {0}, hash:{1}".format(
                        algorithm.__class__, padding.__class__
                    )
                )
        else:
            raise UnsupportedAlgorithm("Sign not supported by card")

    def private_numbers(self) -> RSAPrivateNumbers:
        raise NotImplementedError("Cards should not export private key")

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError("Cards should not export private key")


RSAPrivateKeyWithSerialization = RSAPrivateKeyPKCS11
RSAPrivateKey.register(RSAPrivateKeyPKCS11)


def get_key(session, keyid, pk_ref) -> RSAPrivateKeyPKCS11:
    return RSAPrivateKeyPKCS11(session, keyid, pk_ref)
