_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestKeyAgreementECDH:

    def test_ECDH_cbc_decrypt(self):
        from cryptography.hazmat.primitives import (
            hashes,
            keywrap,
            serialization,
        )
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP384R1,
        )
        from cryptography.hazmat.backends import default_backend

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11UnwrapNDecryptSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            get_AES_algorithm_properties,
            ECDH_ephemeral,
        )

        data = b"This is a test if it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."
        other_info_for_kdf = b"this is shared info"

        encryption_algorithm = "aes256_cbc"
        key_wrap_algorithm = "aes256_wrap"
        kdf_hash = hashes.SHA256()

        sym_algo_props = get_AES_algorithm_properties(encryption_algorithm)
        if sym_algo_props is None:
            assert False, "algorithm not Known"
        else:
            padded_payload = sym_algo_props.pre_encryption(data)
            content_encryption_key = sym_algo_props.generate_key()
            iv = sym_algo_props.get_nonce()
            encryptor = sym_algo_props.get_sw_encryptor(content_encryption_key)
            ciphertext = encryptor.update(padded_payload) + encryptor.finalize()
            encrypted_content = ciphertext

            kek_gen = ECDH_ephemeral.create_for_wrap(
                key_wrap_algorithm, kdf_hash
            )

            # Generate a private key for use in the exchange.
            for label in list_token_labels(_pkcs11lib):
                pub_key_obj_1 = None
                create_session_1 = PKCS11AdminSession(
                    label, "1234", True, "ec_token_1", b"254", _pkcs11lib
                )
                with create_session_1 as current_admin:
                    keydef = PKCS11KeyUsageAll()
                    ec_private_key_1 = current_admin.create_key_pair(
                        keydef, key_type=KeyTypes.EC, EC_curve=SECP384R1()
                    )
                    assert ec_private_key_1 is not None
                    pub_key_1 = ec_private_key_1.public_key()
                    pub_key_obj_1 = pub_key_1.public_numbers().public_key()

                derived_key, peer_pub_key = kek_gen.derive_key_concat_kdf(
                    pub_key_obj_1, other_info_for_kdf
                )
                wrapped_content_encryption_key = keywrap.aes_key_wrap(
                    derived_key, content_encryption_key, default_backend()
                )
                peer_pub_key_info = peer_pub_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )

                if (
                    peer_pub_key_info is not None
                    and wrapped_content_encryption_key is not None
                ):
                    private_1_ses = PKCS11UnwrapNDecryptSession(
                        label, "1234", "ec_token_1", pksc11_lib=_pkcs11lib
                    )
                    with private_1_ses as curr_key:
                        decrypted_message = curr_key.unwrap_and_decrypt(
                            encrypted_content,
                            wrapped_content_encryption_key,
                            encryption_algorithm,
                            iv,
                            public_key_info=peer_pub_key_info,
                            kdf_hash=kdf_hash,
                            wrap_algorithm=key_wrap_algorithm,
                            other_info_bytes=other_info_for_kdf,
                            kdf_on_card=False,
                        )
                        assert decrypted_message == data
                else:
                    assert (
                        False
                    ), "Encryption did not provide enough information"

                with create_session_1 as current_admin:
                    r = current_admin.delete_key_pair()
                    assert r

    def test_ECDH_gcm_decrypt(self):
        from cryptography.hazmat.primitives import (
            hashes,
            keywrap,
            serialization,
        )
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP384R1,
        )
        from cryptography.hazmat.backends import default_backend

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11UnwrapNDecryptSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            get_AES_algorithm_properties,
            ECDH_ephemeral,
        )

        _pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"
        data = b"This is not OK if it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."
        other_info_for_kdf = b"this is shared info"
        aad = b"additional data"

        encryption_algorithm = "aes256_gcm"
        key_wrap_algorithm = "aes256_wrap"
        kdf_hash = hashes.SHA256()

        sym_algo_props = get_AES_algorithm_properties(encryption_algorithm)
        if sym_algo_props is None:
            assert False, "algorithm not Known"
        else:
            padded_payload = sym_algo_props.pre_encryption(data)
            content_encryption_key = sym_algo_props.generate_key()
            iv = sym_algo_props.get_nonce()
            encryptor = sym_algo_props.get_sw_encryptor(
                content_encryption_key, aad=aad
            )
            ciphertext = encryptor.update(padded_payload) + encryptor.finalize()
            encrypted_content = ciphertext
            received_tag = encryptor.tag

            kek_gen = ECDH_ephemeral.create_for_wrap(
                key_wrap_algorithm, kdf_hash
            )

            # Generate a private key for use in the exchange.
            for label in list_token_labels(_pkcs11lib):
                pub_key_obj_1 = None
                create_session_1 = PKCS11AdminSession(
                    label, "1234", True, "ec_token_1", b"254", _pkcs11lib
                )
                with create_session_1 as current_admin:
                    keydef = PKCS11KeyUsageAll()
                    ec_private_key_1 = current_admin.create_key_pair(
                        keydef, key_type=KeyTypes.EC, EC_curve=SECP384R1()
                    )
                    assert ec_private_key_1 is not None
                    pub_key_1 = ec_private_key_1.public_key()
                    pub_key_obj_1 = pub_key_1.public_numbers().public_key()

                derived_key, peer_pub_key = kek_gen.derive_key_concat_kdf(
                    pub_key_obj_1, other_info_for_kdf
                )
                wrapped_content_encryption_key = keywrap.aes_key_wrap(
                    derived_key, content_encryption_key, default_backend()
                )
                peer_pub_key_info = peer_pub_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )

                if (
                    peer_pub_key_info is not None
                    and wrapped_content_encryption_key is not None
                ):
                    private_1_ses = PKCS11UnwrapNDecryptSession(
                        label, "1234", "ec_token_1", pksc11_lib=_pkcs11lib
                    )
                    with private_1_ses as curr_key:
                        decrypted_message = curr_key.unwrap_and_decrypt(
                            encrypted_content,
                            wrapped_content_encryption_key,
                            encryption_algorithm,
                            iv,
                            public_key_info=peer_pub_key_info,
                            kdf_hash=kdf_hash,
                            wrap_algorithm=key_wrap_algorithm,
                            other_info_bytes=other_info_for_kdf,
                            received_tag=received_tag,
                            aad_for_gcm=aad,
                            kdf_on_card=False,
                        )
                        assert decrypted_message == data
                else:
                    assert False, "encrypt did not provide enough information"

                with create_session_1 as current_admin:
                    r = current_admin.delete_key_pair()
                    assert r

    def test_ECDH_cbc_encrypt_decrypt(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            PKCS11EncryptNWrapSession,
            PKCS11UnwrapNDecryptSession,
        )

        data = b"This is a test if it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."
        other_info_for_kdf = b"this is shared info"

        encryption_algorithm = "aes256_cbc"
        key_wrap_algorithm = "aes256_wrap"
        kdf_hash = hashes.SHA256()

        # Generate a private key for use in the exchange.
        for label in list_token_labels(_pkcs11lib):
            create_session_1 = PKCS11AdminSession(
                label, "1234", True, "ec_token_1", b"254", _pkcs11lib
            )
            with create_session_1 as current_admin:
                keydef = PKCS11KeyUsageAll()
                ec_private_key_1 = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.EC, EC_curve=SECP384R1()
                )
                assert ec_private_key_1 is not None
                pub_key_1 = ec_private_key_1.public_key()
                public_key_info_der = pub_key_1.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )

            ecdh_es_session = PKCS11EncryptNWrapSession(
                "A token", "1234", _pkcs11lib
            )
            with ecdh_es_session as ecdh_es:
                encrypted_content, received_tag, iv = ecdh_es.encrypt(
                    data, encryption_algorithm
                )
                wrapped_content_encryption_key, peer_pub_key_info = (
                    ecdh_es.wrap_key(
                        public_key_info_der,
                        kdf_hash=kdf_hash,
                        wrap_algorithm=key_wrap_algorithm,
                        other_info_bytes=other_info_for_kdf,
                        kdf_on_card=False,
                    )
                )

            if wrapped_content_encryption_key is not None:
                private_1_ses = PKCS11UnwrapNDecryptSession(
                    label, "1234", "ec_token_1", pksc11_lib=_pkcs11lib
                )
                with private_1_ses as ecdh_static:
                    decrypted_message = ecdh_static.unwrap_and_decrypt(
                        encrypted_content,
                        wrapped_content_encryption_key,
                        encryption_algorithm,
                        iv,
                        public_key_info=peer_pub_key_info,
                        kdf_hash=kdf_hash,
                        wrap_algorithm=key_wrap_algorithm,
                        other_info_bytes=other_info_for_kdf,
                        kdf_on_card=False,
                    )
                    assert decrypted_message == data
            else:
                assert False, "wrapped_content_encryption_key is None"

            with create_session_1 as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    def test_ECDH_gcm_encrypt_decrypt(self):
        from cryptography.hazmat.primitives import (
            hashes,
            serialization,
        )
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            PKCS11UnwrapNDecryptSession,
            PKCS11EncryptNWrapSession,
        )

        data = b"This is a test if it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."
        aad = b"additional data"
        other_info_for_kdf = b"this is shared info"

        encryption_algorithm = "aes256_gcm"
        key_wrap_algorithm = "aes256_wrap"
        kdf_hash = hashes.SHA256()

        # Generate a private key for use in the exchange.
        for label in list_token_labels(_pkcs11lib):
            create_session_1 = PKCS11AdminSession(
                label, "1234", True, "ec_token_1", b"254", _pkcs11lib
            )
            with create_session_1 as current_admin:
                keydef = PKCS11KeyUsageAll()
                ec_private_key_1 = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.EC, EC_curve=SECP384R1()
                )
                assert ec_private_key_1 is not None
                pub_key_1 = ec_private_key_1.public_key()
                public_key_info_der = pub_key_1.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )

            ecdh_es_session = PKCS11EncryptNWrapSession(
                "A token", "1234", _pkcs11lib
            )
            with ecdh_es_session as ecdh_es:
                encrypted_content, received_tag, iv = ecdh_es.encrypt(
                    data, encryption_algorithm, aad_for_gcm=aad
                )
                wrapped_content_encryption_key, peer_pub_key_info = (
                    ecdh_es.wrap_key(
                        public_key_info_der,
                        kdf_hash=kdf_hash,
                        wrap_algorithm=key_wrap_algorithm,
                        other_info_bytes=other_info_for_kdf,
                        kdf_on_card=False,
                    )
                )

            if wrapped_content_encryption_key is not None:
                private_1_ses = PKCS11UnwrapNDecryptSession(
                    label,
                    "1234",
                    "ec_token_1",
                    pksc11_lib=_pkcs11lib,
                )
                with private_1_ses as ecdh_static:
                    decrypted_message = ecdh_static.unwrap_and_decrypt(
                        encrypted_content,
                        wrapped_content_encryption_key,
                        encryption_algorithm,
                        iv,
                        public_key_info=peer_pub_key_info,
                        kdf_hash=kdf_hash,
                        wrap_algorithm=key_wrap_algorithm,
                        other_info_bytes=other_info_for_kdf,
                        received_tag=received_tag,
                        aad_for_gcm=aad,
                        kdf_on_card=False,
                    )
                    assert decrypted_message == data
            else:
                assert False, "wrapped_content_encryption_key is None"

            with create_session_1 as current_admin:
                r = current_admin.delete_key_pair()
                assert r
