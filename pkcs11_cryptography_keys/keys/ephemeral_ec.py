# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

import PyKCS11
from asn1crypto.core import BitString, OctetString
from asn1crypto.keys import ECDomainParameters, NamedCurve
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurve,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
    EllipticCurveSignatureAlgorithm,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    KeySerializationEncryption,
    PrivateFormat,
    PublicFormat,
)

from ..card_token.PKCS11_key_definition import PKCS11KeyUsage
from ..card_token.PKCS11_object import PKCS11Object
from ..utils.exceptions import KeyException, SessionException
from .AES_wrap import PKCS11AESWrap, get_key_wrappers_translation
from .ec import (
    _decode_RS_signature,
    _digest_algorithm_implementations,
    _encode_RS_signature,
    _get_curve_class,
    _get_PKSC11_mechanism,
    _get_PKSC11_mechanism_D,
)
from .eliptic_curve_derive_algorithm import (
    ECDH_noKDF,
    EllipticCurveKDFAlgorithm,
)
from .symetric_crypto import (
    SymetricAlgorithmProperties,
    SymetricKeyPKCS11,
    get_symetric_key_translation,
)


def get_mechanism_definition(mechanism_name: str):
    mech = PyKCS11.CKM[mechanism_name]
    if mech in _digest_algorithm_implementations:
        return _digest_algorithm_implementations[mech]


class EphemeralEllipticCurvePublicKeyPKCS11:
    def __init__(self, session, public_key, operations: dict):
        self._session = session
        self._public_key = public_key
        self._operations = operations

    def _read_public_key_data(self) -> EllipticCurvePublicKey:
        if self._session is not None:
            ec_attrs = self._session.getAttributeValue(
                self._public_key,
                [
                    PyKCS11.CKA_EC_POINT,
                    PyKCS11.CKA_EC_PARAMS,
                ],
            )
            if ec_attrs[0] is not None:
                tag = ec_attrs[0][0]
                if tag == 4:
                    ansiXY = OctetString.load(bytes(ec_attrs[0]))
                elif tag == 3:
                    ansiXY = BitString.load(bytes(ec_attrs[0]))
                    # this will be in next versions. Question how to get proper 04|X|Y from it.
                else:
                    raise KeyException(
                        "EC point envelope is not recognized: {0}".format(
                            ec_attrs[0]
                        )
                    )
                ansiXY_bytes = bytes(ansiXY)
                curve_class = _get_curve_class(bytes(ec_attrs[1]))
                if curve_class is not None:
                    curve = curve_class()
                    if ansiXY_bytes[0] == 4:
                        public_key_buffer = (
                            EllipticCurvePublicKey.from_encoded_point(
                                curve, ansiXY_bytes
                            )
                        )
                        return public_key_buffer
                    else:
                        raise KeyException(
                            "EC point not properly formated (04|X|Y)"
                        )

                else:
                    raise KeyException("Could not get curve class")
            else:
                raise KeyException("EC point was not returned")
        else:
            raise SessionException("Session to card missing")

    # cryptography API
    @property
    def curve(self) -> EllipticCurve:
        key = self._read_public_key_data()
        if key is not None:
            return key.curve
        else:
            raise KeyException("Key not found")

    @property
    def key_size(self) -> int:
        key = self._read_public_key_data()
        if key is not None:
            return key.key_size
        else:
            raise KeyException("Key not found")

    def public_numbers(self) -> EllipticCurvePublicNumbers:
        key = self._read_public_key_data()
        if key is not None:
            return key.public_numbers()
        else:
            raise KeyException("Key not found")

    def public_bytes(
        self,
        encoding: Encoding,
        format: PublicFormat,
    ) -> bytes:
        key = self._read_public_key_data()
        if key is not None:
            return key.public_bytes(encoding, format)
        else:
            raise KeyException("Key not found")

    def verify(
        self,
        signature: bytes,
        data: bytes,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> None:
        if self._session is not None:
            if "VERIFY" in self._operations:
                PK_me = _get_PKSC11_mechanism(
                    self._operations["VERIFY"], signature_algorithm
                )
                sig_ec = decode_dss_signature(signature)
                sig_val = _encode_RS_signature(sig_ec, self.key_size)
                if sig_val is None:
                    raise InvalidSignature("Signature could not be verified.")
                rez = False
                if PK_me is None:
                    rez = self._session.verify(self._public_key, data, sig_val)
                else:
                    rez = self._session.verify(
                        self._public_key, data, sig_val, PK_me
                    )
                if not rez:
                    raise InvalidSignature("Signature verification failed.")
            else:
                raise UnsupportedAlgorithm("Verify not supported by the card")
        else:
            raise SessionException("Session to card missing")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EphemeralEllipticCurvePublicKeyPKCS11):
            return self._public_key == other._public_key
        else:
            return False


class EphemeralEllipticCurvePrivateKeyPKCS11(PKCS11Object):
    def __init__(self, session, pk_ref, pub_key_ref):
        super().__init__(session, pk_ref)
        self._public_key = pub_key_ref

    @classmethod
    def generate_ephemeral_keypair(
        cls,
        session,
        intended_usage: PKCS11KeyUsage,
        curve,
        mechanism_generator,
        logger,
    ):
        domain_params = ECDomainParameters(
            name="named", value=NamedCurve(curve.name)
        )
        ec_params = domain_params.dump()
        public_key_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),  # Ephemeral Public Key
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_EC_PARAMS, ec_params),
        ]

        private_key_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),  # Ephemeral Private Key
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DERIVE, PyKCS11.CK_TRUE),  # Needed for ECDH
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
        ]

        logger.info("Generating ephemeral EC key pair...")

        # Generate the key pair
        public_key_handle, private_key_handle = session.generateKeyPair(
            public_key_template,
            private_key_template,
            mecha=PyKCS11.MechanismECGENERATEKEYPAIR,
        )
        em_pk = cls(session, private_key_handle, public_key_handle)
        for PKCS11_mechanism, method, properties in mechanism_generator():
            em_pk.fill_operations(PKCS11_mechanism, method, properties)
        return em_pk

    # Register mechanism to operation as card capability
    def _get_mechanism_translation(self, method, PKCS11_mechanism, properties):
        mm = PyKCS11.CKM[PKCS11_mechanism]
        if (
            mm in _digest_algorithm_implementations
            and method in _digest_algorithm_implementations[mm]
        ):
            definition = _digest_algorithm_implementations[mm][method]
            return [definition["hash"]]

    # Register symetric key support
    def _get_symetric_key_translation(
        self, method, PKCS11_mechanism, properties
    ):
        return get_symetric_key_translation(
            method, PKCS11_mechanism, properties
        )

    # Register key wrap support
    def _get_key_wrappers_translation(
        self, method, PKCS11_mechanism, properties
    ):
        return get_key_wrappers_translation(
            method, PKCS11_mechanism, properties
        )

    def __derive_key_on_card(
        self,
        algorithm: EllipticCurveKDFAlgorithm,
        peer_public_key: EllipticCurvePublicKey,
    ) -> int:
        if self._session is not None:
            publicData = peer_public_key.public_bytes(
                Encoding.X962,
                PublicFormat.UncompressedPoint,
            )
            if "DERIVE" in self._operations:

                PK_me, template = _get_PKSC11_mechanism_D(
                    self._operations["DERIVE"], algorithm, publicData
                )
                if PK_me is None:
                    raise UnsupportedAlgorithm(
                        "Derive algorithm {0} not supported.".format(algorithm)
                    )
                else:
                    if (
                        peer_public_key.curve.key_size != self.curve.key_size
                        and peer_public_key.curve.name != self.curve.name
                    ):
                        raise KeyException(
                            "Both keys need to be of same curve and length"
                        )

                    try:
                        h_derived_key = None
                        h_derived_key = self._session.deriveKey(
                            self._private_key, template, PK_me
                        )
                        # :param baseKey: the base key handle
                        # :type baseKey: integer
                        # :param template: template for the unwrapped key
                        # :param mecha: the decrypt mechanism to be used
                        # :type mecha: :class:`Mechanism`
                        # :return: the unwrapped key object
                        # :rtype: integer

                    except:
                        raise
                    return h_derived_key
            else:
                raise UnsupportedAlgorithm("Derive not supported by the card")
        else:
            raise SessionException("Session to card missing")

    def __derive_key(
        self,
        algorithm: EllipticCurveKDFAlgorithm,
        peer_public_key: EllipticCurvePublicKey,
    ) -> bytes:
        if self._session is not None:
            derkey = None
            try:
                h_derived_key = None
                h_derived_key = self.__derive_key_on_card(
                    algorithm, peer_public_key
                )
                attributes = self._session.getAttributeValue(
                    h_derived_key, [PyKCS11.CKA_VALUE]
                )
                derkey = bytes(attributes[0])
            except:
                raise
            finally:
                if h_derived_key is not None:
                    self._session.destroyObject(h_derived_key)
            return derkey
        else:
            raise SessionException("Session to card missing")

    def exchange(
        self, algorithm: ECDH, peer_public_key: EllipticCurvePublicKey
    ) -> bytes:
        return self.__derive_key(ECDH_noKDF(), peer_public_key)

    def derive_key_bytes(
        self,
        algorithm: EllipticCurveKDFAlgorithm,
        peer_public_key: EllipticCurvePublicKey,
    ) -> bytes:
        return self.__derive_key(algorithm, peer_public_key)

    def derive(
        self,
        algorithm: EllipticCurveKDFAlgorithm,
        peer_public_key: EllipticCurvePublicKey,
        derived_key_props: SymetricAlgorithmProperties,
    ) -> SymetricKeyPKCS11 | PKCS11AESWrap:
        h_derived_key = self.__derive_key_on_card(algorithm, peer_public_key)
        if hasattr(derived_key_props, "get_PKCS11_key"):
            return derived_key_props.get_PKCS11_key(
                self._session, h_derived_key
            )
        else:
            self._session.destroyObect(h_derived_key)
            raise KeyException(
                "Derived key can not be used. Key object type not found."
            )

    def public_key(self) -> EphemeralEllipticCurvePublicKeyPKCS11:
        if self._session is not None:
            return EphemeralEllipticCurvePublicKeyPKCS11(
                self._session, self._public_key, self._operations
            )
        else:
            raise SessionException("Session to card missing")

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
            return curve_class()
        else:
            raise SessionException("Session to card missing")

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
            curve = curve_class()
            return curve.key_size
        else:
            raise SessionException("Session to card missing")

    def sign(
        self,
        data: bytes,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        if "SIGN" in self._operations:
            PK_me = _get_PKSC11_mechanism(
                self._operations["SIGN"], signature_algorithm
            )
            if PK_me is None:
                raise UnsupportedAlgorithm(
                    "Signing algorithm {0} not supported.".format(
                        signature_algorithm
                    )
                )
            else:
                sig = self._sign(data, PK_me)
                r, s = _decode_RS_signature(sig)
                return encode_dss_signature(
                    int(binascii.hexlify(r), 16), int(binascii.hexlify(s), 16)
                )
        else:
            raise UnsupportedAlgorithm("Sign not supported by the card.")

    def private_numbers(self) -> EllipticCurvePrivateNumbers:
        raise NotImplementedError("Cards should not export private key")

    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError("Cards should not export private key")


def get_key(session, keyid, pk_ref) -> EphemeralEllipticCurvePrivateKeyPKCS11:
    return EphemeralEllipticCurvePrivateKeyPKCS11(session, keyid, pk_ref)
