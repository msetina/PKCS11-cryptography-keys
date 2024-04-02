# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii
from typing import Dict

import PyKCS11
from asn1crypto.core import ObjectIdentifier, OctetString
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat._oid import ObjectIdentifier as cryptoObjectIdentifier
from cryptography.hazmat.primitives import _serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    _OID_TO_CURVE,
    ECDH,
    EllipticCurve,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
    EllipticCurveSignatureAlgorithm,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
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
    PyKCS11.CKM_ECDSA: {
        "SIGN": {"hash": Prehashed},
        "VERIFY": {"hash": Prehashed},
    },
    PyKCS11.CKM_ECDSA_SHA1: {
        "SIGN": {"hash": hashes.SHA1},
        "VERIFY": {"hash": hashes.SHA1},
    },
    PyKCS11.CKM_ECDSA_SHA224: {
        "SIGN": {"hash": hashes.SHA224},
        "VERIFY": {"hash": hashes.SHA1},
    },
    PyKCS11.CKM_ECDSA_SHA256: {
        "SIGN": {"hash": hashes.SHA256},
        "VERIFY": {"hash": hashes.SHA1},
    },
    PyKCS11.CKM_ECDSA_SHA384: {
        "SIGN": {"hash": hashes.SHA384},
        "VERIFY": {"hash": hashes.SHA1},
    },
    PyKCS11.CKM_ECDSA_SHA512: {
        "SIGN": {"hash": hashes.SHA512},
        "VERIFY": {"hash": hashes.SHA1},
    },
    # PyKCS11.CKM_ECDH1_COFACTOR_DERIVE: ECDH(),
    PyKCS11.CKM_ECDH1_DERIVE: {"DERIVE": {"hash": ECDH}},
}


# Get curve class from EC_PARAMS
def _get_curve_class(data: bytes):
    oid = ObjectIdentifier.load(data)
    coi = cryptoObjectIdentifier(oid.dotted)
    return _OID_TO_CURVE.get(coi, None)


# Get PKCS11 mechanism from hashing algorithm for sign/verify
def _get_PKSC11_mechanism(operation_dict, algorithm):
    PK_me = None
    cls = algorithm.algorithm.__class__
    if "hash" in operation_dict and cls in operation_dict["hash"]:
        mech = operation_dict["hash"][cls]
        PK_me = PyKCS11.Mechanism(mech)
    return PK_me


# ECDSA signtures come from the card RS encoded, for transformation we need separate r and s
def _decode_RS_signature(data):
    l = len(data) / 2
    r = bytearray()
    s = bytearray()
    for i in range(len(data)):
        if i < l:
            r.append(data[i])
        else:
            s.append(data[i])
    return r, s


class EllipticCurvePublicKeyPKCS11:
    def __init__(self, session, public_key, operations: dict):
        self._session = session
        self._public_key = public_key
        self._operations = operations
        self._public_key_buffer = None

    def _read_public_key_data(self) -> EllipticCurvePublicKey:
        if self._session is not None and self._public_key_buffer is None:
            ec_attrs = self._session.getAttributeValue(
                self._public_key,
                [
                    PyKCS11.CKA_EC_POINT,
                    PyKCS11.CKA_EC_PARAMS,
                ],
            )
            ansiXY = OctetString.load(bytes(ec_attrs[0]))
            ansiXY_bytes = bytes(ansiXY)
            curve_class = _get_curve_class(bytes(ec_attrs[1]))
            if curve_class != None and ansiXY_bytes[0] == 4:
                curve = curve_class()
                self._public_key_buffer = (
                    EllipticCurvePublicKey.from_encoded_point(
                        curve, ansiXY_bytes
                    )
                )
        return self._public_key_buffer

    # cryptography API
    @property
    def curve(self) -> EllipticCurve:
        key = self._read_public_key_data()
        if key != None:
            return key.curve

    @property
    def key_size(self) -> int:
        key = self._read_public_key_data()
        if key != None:
            return key.key_size

    def public_numbers(self) -> EllipticCurvePublicNumbers:
        key = self._read_public_key_data()
        if key != None:
            return key.public_numbers()

    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        key = self._read_public_key_data()
        if key != None:
            return key.public_bytes(encoding, format)

    def verify(
        self,
        signature: bytes,
        data: bytes,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> None:
        if self._session != None:
            PK_me = _get_PKSC11_mechanism(
                self._operations["VERIFY"], signature_algorithm
            )
            rez = False
            if PK_me is None:
                rez = self._session.verify(self._public_key, data, signature)
            else:
                rez = self._session.verify(
                    self._public_key, data, signature, PK_me
                )
            if not rez:
                raise InvalidSignature("Signature verification failed.")

    def __eq__(self, other: object) -> bool:
        return self._public_key == other._public_key


EllipticCurvePublicKeyWithSerialization = EllipticCurvePublicKeyPKCS11
EllipticCurvePublicKey.register(EllipticCurvePublicKeyPKCS11)


class EllipticCurvePrivateKeyPKCS11(PKCS11Token):
    def __init__(self, session, keyid, key_type, pk_ref):
        super().__init__(session, keyid, key_type, pk_ref)

    # Register mechanism to operation as card capability
    def _get_mechanism_translation(self, method, PKCS11_mechanism):
        mm = PyKCS11.CKM[PKCS11_mechanism]
        if (
            mm in _digest_algorithm_implementations
            and method
            in _digest_algorithm_implementations[PyKCS11.CKM[PKCS11_mechanism]]
        ):
            return _digest_algorithm_implementations[
                PyKCS11.CKM[PKCS11_mechanism]
            ][method]

    def exchange(
        self, algorithm: ECDH, peer_public_key: EllipticCurvePublicKey
    ) -> bytes:
        publicData = peer_public_key.public_bytes(
            _serialization.Encoding.X962,
            _serialization.PublicFormat.UncompressedPoint,
        )
        # :param publicData: Other party public key which is EC Point [PC || coord-x || coord-y]. 04 || x || y
        # :param kdf: Key derivation function. OPTIONAL. Defaults to CKD_NULL
        # :param sharedData: additional shared data. OPTIONAL
        mech = PyKCS11.ECDH1_DERIVE_Mechanism(
            publicData, kdf=1, sharedData=None
        )
        template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
        ]

        ret = self._session.deriveKey(self._private_key, template, mech)
        # :param baseKey: the base key handle
        # :type baseKey: integer
        # :param template: template for the unwrapped key
        # :param mecha: the decrypt mechanism to be used
        # :type mecha: :class:`Mechanism`
        # :return: the unwrapped key object
        # :rtype: integer

        raise NotImplemented()

    def public_key(self) -> EllipticCurvePublicKeyPKCS11:
        if self._session is not None:
            pubkey = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )[0]
            return EllipticCurvePublicKeyPKCS11(
                self._session, pubkey, self._operations
            )

    @property
    def curve(self) -> EllipticCurve:
        if self._session is not None:
            ec_attrs = self._session.getAttributeValue(
                self._private_key,
                [
                    PyKCS11.CKA_EC_PARAMS,
                ],
            )
            curve_class = _get_curve_class(bytes(ec_attrs[0]))
            if curve_class != None:
                return curve_class()

    @property
    def key_size(self) -> int:
        if self._session is not None:
            ec_attrs = self._session.getAttributeValue(
                self._private_key,
                [
                    PyKCS11.CKA_EC_PARAMS,
                ],
            )
            curve_class = _get_curve_class(bytes(ec_attrs[0]))
            if curve_class != None:
                curve = curve_class()
                return curve.key_size

    def sign(
        self,
        data: bytes,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        PK_me = _get_PKSC11_mechanism(
            self._operations["SIGN"], signature_algorithm
        )
        sig = self._sign(data, PK_me)
        r, s = _decode_RS_signature(sig)
        return encode_dss_signature(
            int(binascii.hexlify(r), 16), int(binascii.hexlify(s), 16)
        )

    def private_numbers(self) -> EllipticCurvePrivateNumbers:
        raise NotImplemented()

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplemented()


EllipticCurvePrivateKeyWithSerialization = EllipticCurvePrivateKeyPKCS11
EllipticCurvePrivateKey.register(EllipticCurvePrivateKeyPKCS11)


def get_key(session, keyid, key_type, pk_ref):
    return EllipticCurvePrivateKeyPKCS11(session, keyid, key_type, pk_ref)
