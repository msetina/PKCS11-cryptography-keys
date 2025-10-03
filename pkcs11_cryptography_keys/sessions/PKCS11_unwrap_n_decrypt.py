from importlib import import_module

import PyKCS11
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.x509 import (
    ExtensionNotFound,
    SubjectKeyIdentifier,
    load_pem_x509_certificate,
)
from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKK_ECDSA,
    CKK_RSA,
    CKO_PRIVATE_KEY,
)

from ..keys.AES_crypto import (
    AESAlgorithmPropertiesCBC,
    AESAlgorithmPropertiesGCM,
    get_AES_algorithm_properties,
)
from ..keys.AES_wrap import (
    get_key_wrappers_translation,
    get_wrap_algorithm_properties,
)
from ..keys.ec import (
    EllipticCurvePrivateKeyPKCS11,
    _digest_algorithm_implementations,
)
from ..keys.eliptic_curve_derive_algorithm import ECDH_KDF
from ..keys.rsa import RSAPrivateKeyPKCS11
from ..keys.symetric_crypto import (
    SymetricKeyPKCS11,
    get_symetric_key_translation,
)
from .PKCS11_operation_session import PKCS11OperationSession

_key_modules = {
    CKK_ECDSA: "pkcs11_cryptography_keys.keys.ec",
    CKK_RSA: "pkcs11_cryptography_keys.keys.rsa",
}


class PKCS11UnwrapNDecryptSession(PKCS11OperationSession):

    def __init__(
        self,
        token_label,
        pin,
        key_label=None,
        key_id=None,
        pksc11_lib=None,
        logger=None,
    ):
        super().__init__(token_label, pin, pksc11_lib, logger)
        self._private_key: (
            EllipticCurvePrivateKeyPKCS11 | RSAPrivateKeyPKCS11 | None
        ) = None
        self._key_label = key_label
        self._key_id = key_id

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

    def _get_private_key(
        self, key_label: str | None = None, key_id: str | None = None
    ) -> tuple:
        if self._session is not None:
            private_key = None
            if key_label is None and key_id is None:
                private_keys = self._session.findObjects(
                    [
                        (CKA_CLASS, CKO_PRIVATE_KEY),
                    ]
                )
                if len(private_keys) > 0:
                    private_key = private_keys[0]
            elif key_id is not None:
                private_keys = self._session.findObjects(
                    [
                        (CKA_CLASS, CKO_PRIVATE_KEY),
                        (CKA_ID, key_id),
                    ]
                )
                if len(private_keys) > 0:
                    private_key = private_keys[0]
            else:
                private_keys = self._session.findObjects(
                    [
                        (CKA_CLASS, CKO_PRIVATE_KEY),
                        (CKA_LABEL, key_label),
                    ]
                )
                if len(private_keys) > 0:
                    private_key = private_keys[0]
            if private_key is not None:
                attrs = self._session.getAttributeValue(
                    private_key, [CKA_KEY_TYPE, CKA_ID]
                )
                key_type = attrs[0]
                keyid = bytes(attrs[1])
                return keyid, key_type, private_key
        else:
            self._logger.info("PKCS11 session is not present")
        return None, None, None

    def open(self):
        super().open()
        keyid, key_type, pk_ref = self._get_private_key(
            self._key_label, self._key_id
        )
        module = None
        module_name = _key_modules.get(key_type, None)
        if module_name is not None:
            module = import_module(module_name)
        else:
            self._logger.info(
                "Module for key type {0} is not acceptable".format(key_type)
            )
        if module is not None:
            private_key = module.get_key(
                self._session,
                keyid,
                pk_ref,
            )
            for m, op, properties in self._gen_mechanisms():
                private_key.fill_operations(m, op, properties)
            if isinstance(private_key, EllipticCurvePrivateKeyPKCS11):
                self._private_key = private_key
            elif isinstance(private_key, RSAPrivateKeyPKCS11):
                self._private_key = private_key
            else:
                self._logger.info(
                    "Private key is not EC or RSA, it is {0}".format(
                        type(private_key)
                    )
                )
        return self

    def get_SubjectKeyIdentifier(self):
        if self._private_key is None:
            return None
        cert_bytes = self._private_key.certificate()
        if cert_bytes is None:
            return None
        cert = load_pem_x509_certificate(cert_bytes)
        encryption_public_key = cert.public_key()
        public_key_info_der = encryption_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        recipient_identifier_value = None
        try:
            ski_extension = cert.extensions.get_extension_for_class(
                SubjectKeyIdentifier
            )
            recipient_identifier_value = ski_extension.value.digest
        except ExtensionNotFound:
            # If SKI extension is not present in the cert, compute it from SubjectPublicKeyInfo
            hasher = hashes.Hash(hashes.SHA1())
            hasher.update(public_key_info_der)
            recipient_identifier_value = hasher.finalize()
        return recipient_identifier_value

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

    def unwrap_and_decrypt(
        self,
        data: bytes,
        encrypted_key: bytes,
        encryption_algorithm: str,
        nonce: bytes,
        **kwargs,
    ):
        if self._private_key is None:
            return None
        if (
            isinstance(self._private_key, RSAPrivateKeyPKCS11)
            and "padding" in kwargs
        ):
            unwrapped_key, unwrapped_key_props, card_decryption = (
                self._unwrap_RSA(
                    encrypted_key,
                    encryption_algorithm,
                    nonce,
                    **kwargs,
                )
            )
        elif (
            isinstance(self._private_key, EllipticCurvePrivateKeyPKCS11)
            and "kdf_hash" in kwargs
            and "public_key_info" in kwargs
            and "wrap_algorithm" in kwargs
        ):
            unwrapped_key, unwrapped_key_props, card_decryption = (
                self._unwrap_ECDH(
                    encrypted_key,
                    encryption_algorithm,
                    nonce,
                    **kwargs,
                )
            )
        else:
            self._logger.info("Unwrapping method not supported.")
            return None
        if unwrapped_key is not None and unwrapped_key_props is not None:
            decrypted_data = self._decrypt(
                data,
                unwrapped_key,
                unwrapped_key_props,
                card_decryption,
                **kwargs,
            )
            return decrypted_data
        else:
            self._logger.info("Unwrapping failed.")
            return None

    def _unwrap_ECDH(
        self,
        encrypted_key: bytes,
        encryption_algorithm: str,
        nonce: bytes,
        **kwargs,
    ):
        if self._private_key is None:
            return None
        if "kdf_hash" in kwargs:
            wrap_algorithm = kwargs["wrap_algorithm"]
        else:
            self._logger.info("KDF hash not provided for ECDH unwrapping.")
            return None
        sym_wrap_algo_props = get_wrap_algorithm_properties(wrap_algorithm)
        card_decryption = (
            "DECRYPT" in self._symetric_key_support
            and encryption_algorithm in self._symetric_key_support["DECRYPT"]
        )
        card_unwrap = (
            "UNWRAP" in self._key_wrappers
            and wrap_algorithm in self._key_wrappers["UNWRAP"]
        )
        if "kdf_hash" in kwargs:
            kdf_hash = kwargs["kdf_hash"]
        else:
            self._logger.info("KDF hash not provided for ECDH unwrapping.")
            return None
        if not isinstance(kdf_hash, hashes.HashAlgorithm):
            self._logger.info("KDF hash is not a valid hash algorithm.")
            return None
        if "public_key_info" in kwargs:
            public_key_info = kwargs["public_key_info"]
        else:
            self._logger.info(
                "Peer public key not provided for ECDH unwrapping."
            )
            return None

        if sym_wrap_algo_props is None:
            card_unwrap = False

        sender_public_key = load_der_public_key(public_key_info)
        if "other_info_bytes" in kwargs:
            other_info_bytes = kwargs["other_info_bytes"]
        else:
            other_info_bytes = None
        if "kdf_on_card" in kwargs:
            kdf_on_card = kwargs["kdf_on_card"]
        else:
            kdf_on_card = True
        kek_obj = None
        if not isinstance(sender_public_key, EllipticCurvePublicKey):
            self._logger.info("Peer key is not EC")
            return None
        elif not isinstance(self._private_key, EllipticCurvePrivateKeyPKCS11):
            self._logger.info("Private key is not EC")
            return None
        else:
            if "DIGEST" in self._operations and kdf_on_card:
                h_kek = self._private_key.derive(
                    ECDH_KDF(
                        kdf_hash,
                        sym_wrap_algo_props.get_key_length(),
                        other_info_bytes,
                    ),
                    sender_public_key,
                    sym_wrap_algo_props,
                )
                kek_obj = sym_wrap_algo_props.get_PKCS11_key(
                    self._session, h_kek
                )
                self._logger.info("KDF performed on card.")
            else:
                raw_shared_secret_bytes = self._private_key.exchange(
                    ECDH(), sender_public_key
                )

                # Initialize ConcatKDFHash
                kdf = ConcatKDFHash(
                    algorithm=kdf_hash,
                    length=sym_wrap_algo_props.get_key_length(),  # Desired output length
                    otherinfo=other_info_bytes,
                )

                # Derive the key
                kek: bytes | None = kdf.derive(raw_shared_secret_bytes)

                self._logger.info("KDF performed in software.")
        if "received_tag" in kwargs:
            received_tag = kwargs["received_tag"]
            tag_bits = len(received_tag) * 8
            unwrapped_key_props = get_AES_algorithm_properties(
                encryption_algorithm, iv=nonce, tag_bits=tag_bits
            )
        else:
            received_tag = None
            if card_decryption:
                hw_padd = False
                if (
                    "hw_padd"
                    in self._symetric_key_support["DECRYPT"][
                        encryption_algorithm
                    ]
                ):
                    hw_padd = self._symetric_key_support["DECRYPT"][
                        encryption_algorithm
                    ]["hw_padd"]
                unwrapped_key_props = get_AES_algorithm_properties(
                    encryption_algorithm, iv=nonce, hw_padd=hw_padd
                )
            else:
                unwrapped_key_props = get_AES_algorithm_properties(
                    encryption_algorithm, iv=nonce
                )

        if unwrapped_key_props is not None:
            unwrapped_key: bytes | None = None
            if card_unwrap:
                # if token writable
                if kek_obj is None and kek is not None:
                    self._logger.info("KEK imported to HSM.")
                    kek_obj = sym_wrap_algo_props.create_PKCS11_key_from_bytes(
                        self._session,
                        kek,
                    )
                    kek = None
                if kek_obj is not None:
                    self._logger.info("Unwrapping CEK on HSM.")
                    try:
                        unwrapped_key_obj = kek_obj.unwrap(
                            encrypted_key, unwrapped_key_props
                        )
                    finally:
                        kek_obj.destroy_key()

            else:
                self._logger.info(
                    "Card cannot unwrap KEK. Falling back to full software decryption from KDF onwards."
                )
                # In this case, derived_kek is available in software
                if kek is not None:
                    unwrapped_key = sym_wrap_algo_props.unwrap_sw(
                        kek, encrypted_key
                    )
                # if token writable
                if card_decryption:
                    if unwrapped_key is not None:
                        unwrapped_key_obj = SymetricKeyPKCS11.create_from_bytes(
                            self._session, unwrapped_key, unwrapped_key_props
                        )
                        unwrapped_key = None
            return unwrapped_key_obj, unwrapped_key_props, card_decryption
        else:
            raise UnsupportedAlgorithm(
                f"Encryption algorithm {encryption_algorithm} not known."
            )

    def _unwrap_RSA(
        self,
        encrypted_key: bytes,
        encryption_algorithm: str,
        nonce: bytes,
        **kwargs,
    ):
        if self._private_key is None:
            return None
        card_decryption = (
            "DECRYPT" in self._symetric_key_support
            and encryption_algorithm in self._symetric_key_support["DECRYPT"]
        )
        if "padding" in kwargs:
            padding = kwargs["padding"]
        else:
            self._logger.info("Padding not provided for RSA unwrapping.")
            return None
        if "received_tag" in kwargs:
            received_tag = kwargs["received_tag"]
            tag_bits = len(received_tag) * 8
            unwrapped_key_props = get_AES_algorithm_properties(
                encryption_algorithm, iv=nonce, tag_bits=tag_bits
            )
        else:
            received_tag = None
            # check if card supports padding with AES CBC
            if card_decryption:
                hw_padd = False
                if (
                    "hw_padd"
                    in self._symetric_key_support["DECRYPT"][
                        encryption_algorithm
                    ]
                ):
                    hw_padd = self._symetric_key_support["DECRYPT"][
                        encryption_algorithm
                    ]["hw_padd"]
                unwrapped_key_props = get_AES_algorithm_properties(
                    encryption_algorithm, iv=nonce, hw_padd=hw_padd
                )
            else:
                unwrapped_key_props = get_AES_algorithm_properties(
                    encryption_algorithm, iv=nonce
                )
        if not isinstance(self._private_key, RSAPrivateKeyPKCS11):
            self._logger.info("Private key is not RSA")
            return None
        elif unwrapped_key_props:
            if card_decryption:
                self._logger.info("Unwrapping on card")
                h_unwrapped_key = self._private_key.unwrap(
                    encrypted_key, padding, unwrapped_key_props
                )
                unwrapped_key_obj = SymetricKeyPKCS11(
                    self._session, h_unwrapped_key, unwrapped_key_props
                )
            else:
                self._logger.info("Unrapping in software")
                unwrapped_key = self._private_key.decrypt(
                    encrypted_key,
                    padding,
                )
                unwrapped_key_obj = SymetricKeyPKCS11.create_from_bytes(
                    self._session, unwrapped_key, unwrapped_key_props
                )
            return unwrapped_key_obj, unwrapped_key_props, card_decryption
        else:
            raise UnsupportedAlgorithm(
                f"Encryption algorithm {encryption_algorithm} not known."
            )

    # def decrypt(
    #     self,
    #     data: bytes,
    #     unwrapped_key: SymetricKeyPKCS11 | bytes,
    #     unwrapped_key_props: (
    #         AESAlgorithmPropertiesGCM | AESAlgorithmPropertiesCBC
    #     ),
    #     card_decryption: bool = False,
    #     **kwargs,
    # ):
    #     if unwrapped_key_props is None or unwrapped_key is None:
    #         return None
    #     return_value = None
    #     if isinstance(unwrapped_key_props, AESAlgorithmPropertiesGCM):
    #         if "aad_for_gcm" in kwargs:
    #             aad_for_gcm = kwargs["aad_for_gcm"]
    #         else:
    #             aad_for_gcm = None
    #         if "received_tag" in kwargs:
    #             received_tag = kwargs["received_tag"]
    #         else:
    #             received_tag = None
    #         if card_decryption:
    #             if isinstance(unwrapped_key, bytes):
    #                 # if token writable
    #                 unwrapped_key_obj = SymetricKeyPKCS11.create_from_bytes(
    #                     self._session, unwrapped_key, unwrapped_key_props
    #                 )
    #             elif isinstance(unwrapped_key, SymetricKeyPKCS11):
    #                 unwrapped_key_obj = unwrapped_key
    #             self._logger.info("Decrypting on HSM.")
    #             if unwrapped_key_obj is not None:
    #                 try:
    #                     if aad_for_gcm is not None:
    #                         return_value = unwrapped_key_obj.decrypt(
    #                             data, received_tag=received_tag, aad=aad_for_gcm
    #                         )
    #                     else:
    #                         return_value = unwrapped_key_obj.decrypt(
    #                             data, received_tag=received_tag
    #                         )
    #                 finally:
    #                     unwrapped_key_obj.destroy_key()

    #         else:
    #             unwrapped_key_bytes: bytes | None = None
    #             if isinstance(unwrapped_key, SymetricKeyPKCS11):
    #                 try:
    #                     unwrapped_key_bytes = unwrapped_key.extract_key()
    #                 finally:
    #                     unwrapped_key.destroy_key()
    #             elif isinstance(unwrapped_key, bytes):
    #                 unwrapped_key_bytes = unwrapped_key
    #             if unwrapped_key_bytes is not None:
    #                 self._logger.info("Decrypting in software.")
    #                 decryptor = unwrapped_key_props.get_sw_decryptor(
    #                     unwrapped_key_bytes,
    #                     received_tag=received_tag,
    #                     aad=aad_for_gcm,
    #                 )
    #                 decrypted_data = (
    #                     decryptor.update(data) + decryptor.finalize()
    #                 )
    #                 return_value = unwrapped_key_props.post_decryption(
    #                     decrypted_data
    #                 )
    #             else:
    #                 return_value = None
    #     elif isinstance(unwrapped_key_props, AESAlgorithmPropertiesCBC):
    #         if card_decryption:
    #             unwrapped_key_obj = None
    #             if isinstance(unwrapped_key, bytes):
    #                 # if token writable
    #                 unwrapped_key_obj = SymetricKeyPKCS11.create_from_bytes(
    #                     self._session, unwrapped_key, unwrapped_key_props
    #                 )
    #             elif isinstance(unwrapped_key, SymetricKeyPKCS11):
    #                 unwrapped_key_obj = unwrapped_key
    #             if unwrapped_key_obj is not None:
    #                 self._logger.info("Decrypting on HSM.")
    #                 try:
    #                     return_value = unwrapped_key_obj.decrypt(data)
    #                 finally:
    #                     unwrapped_key_obj.destroy_key()
    #         else:
    #             unwrapped_key_bytes: bytes | None = None
    #             if isinstance(unwrapped_key, SymetricKeyPKCS11):
    #                 self._logger.info("Extracting key for decryption.")
    #                 try:
    #                     unwrapped_key_bytes = unwrapped_key.extract_key()
    #                 finally:
    #                     unwrapped_key.destroy_key()
    #             if unwrapped_key_bytes is not None:
    #                 self._logger.info("Decrypting in software.")
    #                 decryptor = unwrapped_key_props.get_sw_decryptor(
    #                     unwrapped_key_bytes
    #                 )
    #                 decrypted_data = (
    #                     decryptor.update(data) + decryptor.finalize()
    #                 )
    #                 return_value = unwrapped_key_props.post_decryption(
    #                     decrypted_data
    #                 )
    #             else:
    #                 return_value = None
    #     return return_value

    def _decrypt(
        self,
        data: bytes,
        unwrapped_key: SymetricKeyPKCS11 | bytes,
        unwrapped_key_props: (
            AESAlgorithmPropertiesGCM | AESAlgorithmPropertiesCBC
        ),
        card_decryption: bool = False,
        **kwargs,
    ):
        if unwrapped_key_props is None or unwrapped_key is None:
            return None
        return_value = None
        if isinstance(unwrapped_key_props, AESAlgorithmPropertiesGCM):
            return_value = self._decryptGCM(
                data,
                unwrapped_key,
                unwrapped_key_props,
                card_decryption,
                kwargs,
            )
        elif isinstance(unwrapped_key_props, AESAlgorithmPropertiesCBC):
            return_value = self._decrypt_CBC(
                data, unwrapped_key, unwrapped_key_props, card_decryption
            )

        return return_value

    def _decrypt_CBC(
        self, data, unwrapped_key, unwrapped_key_props, card_decryption
    ):
        if card_decryption:
            if isinstance(unwrapped_key, bytes):
                self._logger.info("Writing key to session for decryption.")
                unwrapped_key_obj = SymetricKeyPKCS11.create_from_bytes(
                    self._session, unwrapped_key, unwrapped_key_props
                )
            elif isinstance(unwrapped_key, SymetricKeyPKCS11):
                unwrapped_key_obj = unwrapped_key
            self._logger.info("Decrypting on HSM")
            try:
                return_value = unwrapped_key_obj.decrypt(data)
            finally:
                unwrapped_key_obj.destroy_key()
        else:
            unwrapped_key_bytes: bytes | None = None
            if isinstance(unwrapped_key, SymetricKeyPKCS11):
                self._logger.info("Extracting key for decryption.")
                try:
                    unwrapped_key_bytes = unwrapped_key.extract_key()
                finally:
                    unwrapped_key.destroy_key()
            if unwrapped_key_bytes is not None:
                self._logger.info("Decrypting in software")
                decryptor = unwrapped_key_props.get_sw_decryptor(
                    unwrapped_key_bytes,
                )
                decrypted_data = decryptor.update(data) + decryptor.finalize()
                return_value = unwrapped_key_props.post_decryption(
                    decrypted_data
                )
            else:
                return_value = None
        return return_value

    def _decryptGCM(
        self, data, unwrapped_key, unwrapped_key_props, card_decryption, kwargs
    ):
        if "aad_for_gcm" in kwargs:
            aad_for_gcm = kwargs["aad_for_gcm"]
        else:
            aad_for_gcm = None
        if "received_tag" in kwargs:
            received_tag = kwargs["received_tag"]
        else:
            received_tag = None
        if card_decryption:
            unwrapped_key_obj = None
            if isinstance(unwrapped_key, bytes):
                self._logger.info("Writing key to session for decryption.")
                unwrapped_key_obj = SymetricKeyPKCS11.create_from_bytes(
                    self._session, unwrapped_key, unwrapped_key_props
                )
            elif isinstance(unwrapped_key, SymetricKeyPKCS11):
                unwrapped_key_obj = unwrapped_key
            if unwrapped_key_obj is not None:
                self._logger.info("Decrypting on card")
                try:
                    if aad_for_gcm is not None:
                        return_value = unwrapped_key_obj.decrypt(
                            data,
                            received_tag=received_tag,
                            aad=aad_for_gcm,
                        )
                    else:
                        return_value = unwrapped_key_obj.decrypt(
                            data, received_tag=received_tag
                        )
                finally:
                    unwrapped_key_obj.destroy_key()
        else:
            unwrapped_key_bytes: bytes | None = None
            if isinstance(unwrapped_key, SymetricKeyPKCS11):
                try:
                    self._logger.info("Extracting key for decryption.")
                    unwrapped_key_bytes = unwrapped_key.extract_key()
                finally:
                    unwrapped_key.destroy_key()
            elif isinstance(unwrapped_key, bytes):
                unwrapped_key_bytes = unwrapped_key
            if unwrapped_key_bytes is not None:
                self._logger.info("Decrypting in software")
                decryptor = unwrapped_key_props.get_sw_decryptor(
                    unwrapped_key_bytes,
                    received_tag=received_tag,
                    aad=aad_for_gcm,
                )
                decrypted_data = decryptor.update(data) + decryptor.finalize()
                return_value = unwrapped_key_props.post_decryption(
                    decrypted_data
                )
            else:
                return_value = None

        return return_value
