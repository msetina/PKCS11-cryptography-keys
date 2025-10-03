from logging import Logger

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

from ..card_token.PKCS11_key_definition import (
    PKCS11KeyUsageDerive,
    PKCS11KeyUsageEncryption,
)
from ..keys.AES_crypto import get_AES_algorithm_properties
from ..keys.AES_wrap import (
    get_key_wrappers_translation,
    get_wrap_algorithm_properties,
)
from ..keys.eliptic_curve_derive_algorithm import ECDH_KDF, ECDH_noKDF
from ..keys.ephemeral_ec import EphemeralEllipticCurvePrivateKeyPKCS11
from ..keys.rsa import RSAPublicKeyPKCS11
from ..keys.symetric_crypto import (
    SymetricKeyPKCS11,
    get_symetric_key_translation,
)
from .PKCS11_operation_session import PKCS11OperationSession


# contextmanager to facilitate connecting to source
class PKCS11EncryptNWrapSession(PKCS11OperationSession):
    def __init__(
        self,
        token_label: str,
        pin: str,
        pksc11_lib: str | None = None,
        logger: Logger | None = None,
    ):
        super().__init__(token_label, pin, pksc11_lib, logger)
        self._symetric_key: bytes | SymetricKeyPKCS11 | None = None

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

    def _generate_ephemeral_EC_keys_ECDH(self, curve):
        intended_usage = PKCS11KeyUsageDerive()
        return (
            EphemeralEllipticCurvePrivateKeyPKCS11.generate_ephemeral_keypair(
                self._session,
                intended_usage,
                curve,
                self._gen_mechanisms,
                self._logger,
            )
        )

    def _import_session_RSA_public_key(self, receiver_pub_key: RSAPublicKey):
        intended_usage = PKCS11KeyUsageEncryption()
        return RSAPublicKeyPKCS11.import_session_RSA_public_key(
            self._session,
            receiver_pub_key,
            intended_usage,
            self._gen_mechanisms,
        )

    def encrypt(
        self,
        data: bytes,
        encryption_algorithm: str,
        **kwargs,
    ):
        if self._symetric_key is None:
            card_encryption = (
                "ENCRYPT" in self._symetric_key_support
                and encryption_algorithm
                in self._symetric_key_support["ENCRYPT"]
            )

            sym_algo_props = get_AES_algorithm_properties(encryption_algorithm)
            if card_encryption:
                self._logger.info("Encrypting on card")
                self._symetric_key = self._generate_symetric_key(sym_algo_props)
                nonce = sym_algo_props.get_nonce()
                if self._symetric_key is not None and isinstance(
                    self._symetric_key, SymetricKeyPKCS11
                ):
                    if "aad_for_gcm" in kwargs:
                        aad = kwargs["aad_for_gcm"]
                        encrypted_content, tag = self._symetric_key.encrypt(
                            data, aad=aad
                        )
                    else:
                        encrypted_content, tag = self._symetric_key.encrypt(
                            data
                        )

            else:
                # sw encryption
                self._logger.info("Encrypting in software")
                padded_payload = sym_algo_props.pre_encryption(data)
                self._symetric_key = sym_algo_props.generate_key()
                nonce = sym_algo_props.get_nonce()
                if "aad_for_gcm" in kwargs:
                    aad = kwargs["aad_for_gcm"]
                    encryptor = sym_algo_props.get_sw_encryptor(
                        self._symetric_key, aad=aad
                    )
                else:
                    encryptor = sym_algo_props.get_sw_encryptor(
                        self._symetric_key
                    )
                ciphertext = (
                    encryptor.update(padded_payload) + encryptor.finalize()
                )
                if hasattr(encryptor, "tag"):
                    tag = encryptor.tag
                else:
                    tag = None

                encrypted_content = ciphertext

            return encrypted_content, tag, nonce
        else:
            raise Exception("Symetric key already set for session")

    def wrap_key(self, public_key_info: bytes, **kwargs):
        if self._symetric_key is None:
            raise Exception("No symetric key set for session")
        receiver_public_key = load_der_public_key(public_key_info)
        if isinstance(receiver_public_key, EllipticCurvePublicKey):
            if "kdf_hash" in kwargs and "wrap_algorithm" in kwargs:
                return self._wrap_key_ECDH_ES(
                    receiver_public_key,
                    **kwargs,
                )
            else:
                raise Exception("Invalid parameters for wrap method")
        elif isinstance(receiver_public_key, RSAPublicKey):
            if "padding" in kwargs:
                return self._wrap_key_RSA(receiver_public_key, **kwargs)
            else:
                raise Exception("Invalid parameters for wrap method")

    def _wrap_key_ECDH_ES(
        self,
        receiver_public_key: EllipticCurvePublicKey,
        **kwargs,
    ):
        if self._symetric_key is not None:
            wrap_algorithm = kwargs["wrap_algorithm"]
            card_wrap = (
                "WRAP" in self._key_wrappers
                and wrap_algorithm in self._key_wrappers["WRAP"]
            )
            sym_wrap_algo_props = get_wrap_algorithm_properties(wrap_algorithm)
            if isinstance(receiver_public_key, EllipticCurvePublicKey):
                ec_key = self._generate_ephemeral_EC_keys_ECDH(
                    receiver_public_key.curve
                )
                pub_K = ec_key.public_key()
                peer_pub_key_info = pub_K.public_bytes(
                    Encoding.DER,
                    PublicFormat.SubjectPublicKeyInfo,
                )
                if "kdf_hash" in kwargs:
                    kdf_hash = kwargs["kdf_hash"]
                else:
                    raise Exception("No kdf_hash provided for key wrap")
                if "other_info_bytes" in kwargs:
                    other_info_bytes = kwargs["other_info_bytes"]
                else:
                    other_info_bytes = None
                if "kdf_on_card" in kwargs:
                    kdf_on_card = kwargs["kdf_on_card"]
                else:
                    kdf_on_card = True

                if kdf_on_card and card_wrap:
                    self._logger.info("Derive with KDF on HSM")
                    wrap_key = ec_key.derive(
                        ECDH_KDF(
                            kdf_hash,
                            sym_wrap_algo_props.get_key_length() * 8,
                            other_info_bytes,
                        ),
                        receiver_public_key,
                        sym_wrap_algo_props,
                    )
                else:
                    self._logger.info("Derive with KDF in software")
                    wrap_secret = ec_key.exchange(
                        ECDH_noKDF(), receiver_public_key
                    )
                    # Perform key derivation.
                    kdf = ConcatKDFHash(
                        algorithm=kdf_hash,
                        length=sym_wrap_algo_props.get_key_length(),
                        otherinfo=other_info_bytes,  # This is the `SharedInfo` or `OtherInfo`
                        backend=default_backend(),
                    )
                    wrap_key_bytes = kdf.derive(wrap_secret)
                    if card_wrap:
                        wrap_key = (
                            sym_wrap_algo_props.create_PKCS11_key_from_bytes(
                                self._session, wrap_key_bytes
                            )
                        )
                if card_wrap and isinstance(
                    self._symetric_key, SymetricKeyPKCS11
                ):
                    self._logger.info("Wrap on card")
                    wrapped_key = wrap_key.wrap(
                        self._symetric_key.get_key_handle()
                    )
                else:
                    if isinstance(self._symetric_key, SymetricKeyPKCS11):
                        key_to_wrap = self._symetric_key.extract_key()
                    if key_to_wrap is None:
                        raise Exception(
                            "Failed to export symetric key from card"
                        )
                    self._logger.info("Wrap in software")
                    wrapped_key = sym_wrap_algo_props.wrap_sw(
                        wrap_key_bytes, key_to_wrap
                    )
                return wrapped_key, peer_pub_key_info
            else:
                raise Exception("Peer key is not EllipticCurvePublicKey")
        else:
            raise Exception("No symetric key set for session")

    def _wrap_key_RSA(
        self,
        receiver_public_key: RSAPublicKey,
        **kwargs,
    ):
        if self._symetric_key is None:
            raise Exception("No symetric key set for session")
        if isinstance(receiver_public_key, RSAPublicKey):
            if "padding" in kwargs:
                padding = kwargs["padding"]
            else:
                raise Exception("No padding provided for RSA wrap")
            if isinstance(self._symetric_key, SymetricKeyPKCS11):
                self._logger.info("Wrapping key on card")
                rsa_key = self._import_session_RSA_public_key(
                    receiver_public_key
                )
                if rsa_key is not None and isinstance(
                    rsa_key, RSAPublicKeyPKCS11
                ):
                    self._logger.info("Importing RSA key to card successful")
                    if rsa_key.can_wrap(padding):
                        self._logger.info("Card can wrap with selected padding")
                        wrapped_content_encryption_key = rsa_key.wrap(
                            self._symetric_key.get_key_handle(), padding
                        )
                    elif rsa_key.can_encrypt(padding):
                        self._logger.info(
                            "Card can encrypt with selected padding"
                        )
                        wrapped_content_encryption_key = rsa_key.encrypt(
                            self._symetric_key.get_key_handle(), padding
                        )
                    else:
                        sym_key_bytes = self._symetric_key.extract_key()
                        if sym_key_bytes is not None:
                            wrapped_content_encryption_key = (
                                receiver_public_key.encrypt(
                                    sym_key_bytes, padding
                                )
                            )
                        else:
                            raise Exception(
                                "Failed to export symetric key from card"
                            )
            else:
                if isinstance(self._symetric_key, bytes):
                    self._logger.info("Wrapping key in software")
                    wrapped_content_encryption_key = (
                        receiver_public_key.encrypt(self._symetric_key, padding)
                    )
                elif isinstance(self._symetric_key, SymetricKeyPKCS11):
                    self._logger.info(
                        "Exporting key from card and wrapping in software"
                    )
                    sym_key_bytes = self._symetric_key.extract_key()
                    if sym_key_bytes is not None:
                        wrapped_content_encryption_key = (
                            receiver_public_key.encrypt(sym_key_bytes, padding)
                        )
                    else:
                        raise Exception(
                            "Failed to export symetric key from card"
                        )
                else:
                    raise Exception("Symetric key set for session is not valid")
            return wrapped_content_encryption_key
        else:
            raise Exception("Peer key is not RSAPublicKey")
