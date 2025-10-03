_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestKeyTransportRSA:

    def test_rsa_pkcs15_cbc_decrypt(self):
        from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeyUsageAll,
            PKCS11UnwrapNDecryptSession,
            get_AES_algorithm_properties,
            list_token_labels,
        )

        data = b"This is a test if it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."

        encryption_algorithm = "aes256_cbc"

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

            # Generate a private key for use in the exchange.
            for label in list_token_labels(_pkcs11lib):
                pub_key_obj_1 = None
                create_session_1 = PKCS11AdminSession(
                    label, "1234", True, "rsa_token_1", b"254", _pkcs11lib
                )
                with create_session_1 as current_admin:
                    keydef = PKCS11KeyUsageAll()
                    rsa_private_key_1 = current_admin.create_key_pair(
                        keydef, key_type=KeyTypes.RSA, RSA_length=2048
                    )
                    assert rsa_private_key_1 is not None
                    pub_key_1 = rsa_private_key_1.public_key()
                    pub_key_obj_1 = pub_key_1.public_numbers().public_key()

                encrypted_key = pub_key_obj_1.encrypt(
                    content_encryption_key, PKCS1v15()
                )

                if encrypted_key is not None:
                    private_1_ses = PKCS11UnwrapNDecryptSession(
                        label, "1234", "rsa_token_1", pksc11_lib=_pkcs11lib
                    )
                    with private_1_ses as curr_key:
                        decrypted_message = curr_key.unwrap_and_decrypt(
                            encrypted_content,
                            encrypted_key,
                            encryption_algorithm,
                            iv,
                            padding=PKCS1v15(),
                        )
                        assert decrypted_message == data
                else:
                    assert False, "encrypted_key is None"

                with create_session_1 as current_admin:
                    r = current_admin.delete_key_pair()
                    assert r

    def test_rsa_pkcs15_gcm_decrypt(self):
        from cryptography.hazmat.primitives.asymmetric.padding import (
            PKCS1v15,
        )

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11UnwrapNDecryptSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            get_AES_algorithm_properties,
        )

        data = b"This is not OK if it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."
        aad = b"additional data"

        encryption_algorithm = "aes256_gcm"

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

            # Generate a private key for use in the exchange.
            for label in list_token_labels(_pkcs11lib):
                pub_key_obj_1 = None
                create_session_1 = PKCS11AdminSession(
                    label, "1234", True, "rsa_token_1", b"254", _pkcs11lib
                )
                with create_session_1 as current_admin:
                    keydef = PKCS11KeyUsageAll()
                    rsa_private_key_1 = current_admin.create_key_pair(
                        keydef, key_type=KeyTypes.RSA, RSA_length=2048
                    )
                    assert rsa_private_key_1 is not None
                    pub_key_1 = rsa_private_key_1.public_key()
                    pub_key_obj_1 = pub_key_1.public_numbers().public_key()

                encrypted_key = pub_key_obj_1.encrypt(
                    content_encryption_key, PKCS1v15()
                )

                if encrypted_key is not None:
                    private_1_ses = PKCS11UnwrapNDecryptSession(
                        label, "1234", "rsa_token_1", pksc11_lib=_pkcs11lib
                    )
                    with private_1_ses as curr_key:
                        decrypted_message = curr_key.unwrap_and_decrypt(
                            encrypted_content,
                            encrypted_key,
                            encryption_algorithm,
                            iv,
                            padding=PKCS1v15(),
                            received_tag=received_tag,
                            aad_for_gcm=aad,
                        )
                        assert decrypted_message == data
                else:
                    assert False, "encrypted_key is None"

                with create_session_1 as current_admin:
                    r = current_admin.delete_key_pair()
                    assert r

    def test_rsa_oaep_cbc_decrypt(self):
        from cryptography.hazmat.primitives.asymmetric.padding import (
            MGF1,
            OAEP,
        )
        from cryptography.hazmat.primitives import hashes

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11UnwrapNDecryptSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            get_AES_algorithm_properties,
        )

        data = b"This is a test.If it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."

        encryption_algorithm = "aes256_cbc"
        # SoftHSM2 supports only SHA1
        mask_hash = hashes.SHA1()
        hash = hashes.SHA1()

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

            # Generate a private key for use in the exchange.
            for label in list_token_labels(_pkcs11lib):
                pub_key_obj_1 = None
                create_session_1 = PKCS11AdminSession(
                    label, "1234", True, "rsa_token_1", b"254", _pkcs11lib
                )
                with create_session_1 as current_admin:
                    keydef = PKCS11KeyUsageAll()
                    rsa_private_key_1 = current_admin.create_key_pair(
                        keydef, key_type=KeyTypes.RSA, RSA_length=2048
                    )
                    assert rsa_private_key_1 is not None
                    pub_key_1 = rsa_private_key_1.public_key()
                    pub_key_obj_1 = pub_key_1.public_numbers().public_key()

                oaep_padd = OAEP(
                    mgf=MGF1(algorithm=mask_hash),
                    algorithm=hash,
                    label=None,
                )

                encrypted_key = pub_key_obj_1.encrypt(
                    content_encryption_key, oaep_padd
                )

                if encrypted_key is not None:
                    private_1_ses = PKCS11UnwrapNDecryptSession(
                        label, "1234", "rsa_token_1", pksc11_lib=_pkcs11lib
                    )
                    with private_1_ses as curr_key:
                        decrypted_message = curr_key.unwrap_and_decrypt(
                            encrypted_content,
                            encrypted_key,
                            encryption_algorithm,
                            iv,
                            padding=oaep_padd,
                        )
                        assert decrypted_message == data
                else:
                    assert False, "encrypted_key is None"

                with create_session_1 as current_admin:
                    r = current_admin.delete_key_pair()
                    assert r

    def test_rsa_oaep_gcm_decrypt(self):
        from cryptography.hazmat.primitives.asymmetric.padding import (
            MGF1,
            OAEP,
        )
        from cryptography.hazmat.primitives import hashes

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11UnwrapNDecryptSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            get_AES_algorithm_properties,
        )

        data = b"This is a test if it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."
        aad = b"additional data"

        encryption_algorithm = "aes256_gcm"
        # SoftHSM2 supports only SHA1
        mask_hash = hashes.SHA1()
        hash = hashes.SHA1()

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

            # Generate a private key for use in the exchange.
            for label in list_token_labels(_pkcs11lib):
                pub_key_obj_1 = None
                create_session_1 = PKCS11AdminSession(
                    label, "1234", True, "rsa_token_1", b"254", _pkcs11lib
                )
                with create_session_1 as current_admin:
                    keydef = PKCS11KeyUsageAll()
                    rsa_private_key_1 = current_admin.create_key_pair(
                        keydef, key_type=KeyTypes.RSA, RSA_length=2048
                    )
                    assert rsa_private_key_1 is not None
                    pub_key_1 = rsa_private_key_1.public_key()
                    pub_key_obj_1 = pub_key_1.public_numbers().public_key()

                oaep_padd = OAEP(
                    mgf=MGF1(algorithm=mask_hash),
                    algorithm=hash,
                    label=None,
                )

                encrypted_key = pub_key_obj_1.encrypt(
                    content_encryption_key, oaep_padd
                )

                if encrypted_key is not None:
                    private_1_ses = PKCS11UnwrapNDecryptSession(
                        label, "1234", "rsa_token_1", pksc11_lib=_pkcs11lib
                    )
                    with private_1_ses as curr_key:
                        decrypted_message = curr_key.unwrap_and_decrypt(
                            encrypted_content,
                            encrypted_key,
                            encryption_algorithm,
                            iv,
                            padding=oaep_padd,
                            received_tag=received_tag,
                            aad_for_gcm=aad,
                        )
                        assert decrypted_message == data
                else:
                    assert False, "encrypted_key is None"

                with create_session_1 as current_admin:
                    r = current_admin.delete_key_pair()
                    assert r

    def test_rsa_pkcs15_cbc_encrypt_decrypt(self):
        from cryptography.hazmat.primitives.asymmetric.padding import (
            PKCS1v15,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11UnwrapNDecryptSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            PKCS11EncryptNWrapSession,
        )

        data = b"This is a test. If it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."

        encryption_algorithm = "aes256_cbc"

        # Generate a private key for use in the exchange.
        for label in list_token_labels(_pkcs11lib):
            create_session_1 = PKCS11AdminSession(
                label, "1234", True, "rsa_token_1", b"254", _pkcs11lib
            )
            with create_session_1 as current_admin:
                keydef = PKCS11KeyUsageAll()
                rsa_private_key_1 = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
                assert rsa_private_key_1 is not None
                pub_key_1 = rsa_private_key_1.public_key()
                pub_key_info = pub_key_1.public_bytes(
                    Encoding.DER,
                    PublicFormat.SubjectPublicKeyInfo,
                )

            operation_session = PKCS11EncryptNWrapSession(
                "A token", "1234", _pkcs11lib
            )
            asyn_padding = PKCS1v15()
            with operation_session as ops:
                encrypted_content, tag, iv = ops.encrypt(
                    data, encryption_algorithm
                )
                wrapped_content_encryption_key = ops.wrap_key(
                    pub_key_info, padding=asyn_padding
                )

            if wrapped_content_encryption_key is not None:
                private_1_ses = PKCS11UnwrapNDecryptSession(
                    label, "1234", "rsa_token_1", pksc11_lib=_pkcs11lib
                )
                with private_1_ses as rsa_unwrap:
                    decrypted_message = rsa_unwrap.unwrap_and_decrypt(
                        encrypted_content,
                        wrapped_content_encryption_key,
                        encryption_algorithm,
                        iv,
                        padding=asyn_padding,
                    )
                    assert decrypted_message == data
            else:
                assert False, "wrapped_content_encryption_key is None"

            with create_session_1 as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    def test_rsa_pkcs15_gcm_encrypt_decrypt(self):
        from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            PKCS11EncryptNWrapSession,
            PKCS11UnwrapNDecryptSession,
        )

        data = b"This is a test. If it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."
        aad = b"additional data"

        encryption_algorithm = "aes256_gcm"

        for label in list_token_labels(_pkcs11lib):
            create_session_1 = PKCS11AdminSession(
                label, "1234", True, "rsa_token_1", b"254", _pkcs11lib
            )
            with create_session_1 as current_admin:
                keydef = PKCS11KeyUsageAll()
                rsa_private_key_1 = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
                assert rsa_private_key_1 is not None
                pub_key_1 = rsa_private_key_1.public_key()
                pub_key_info = pub_key_1.public_bytes(
                    Encoding.DER,
                    PublicFormat.SubjectPublicKeyInfo,
                )

            operation_session = PKCS11EncryptNWrapSession(
                "A token", "1234", _pkcs11lib
            )
            asyn_padding = PKCS1v15()
            with operation_session as ops:
                encrypted_content, received_tag, iv = ops.encrypt(
                    data, encryption_algorithm, aad_for_gcm=aad
                )
                wrapped_content_encryption_key = ops.wrap_key(
                    pub_key_info, padding=asyn_padding
                )
            if wrapped_content_encryption_key is not None:
                private_1_ses = PKCS11UnwrapNDecryptSession(
                    label,
                    "1234",
                    "rsa_token_1",
                    pksc11_lib=_pkcs11lib,
                )
                with private_1_ses as rsa_unwrap:
                    decrypted_message = rsa_unwrap.unwrap_and_decrypt(
                        encrypted_content,
                        wrapped_content_encryption_key,
                        encryption_algorithm,
                        iv,
                        padding=asyn_padding,
                        received_tag=received_tag,
                        aad_for_gcm=aad,
                    )
                    assert decrypted_message == data
            else:
                assert False, "wrapped_content_encryption_key is None"

            with create_session_1 as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    def test_rsa_oaep_cbc_encrypt_decrypt(self):
        from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            PKCS11EncryptNWrapSession,
            PKCS11UnwrapNDecryptSession,
        )

        data = b"This is a test. If it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."

        encryption_algorithm = "aes256_cbc"
        # SoftHSM2 supports only SHA1
        mask_hash = hashes.SHA1()
        hash = hashes.SHA1()

        # Generate a private key for use in the exchange.
        for label in list_token_labels(_pkcs11lib):
            create_session_1 = PKCS11AdminSession(
                label, "1234", True, "rsa_token_1", b"254", _pkcs11lib
            )
            with create_session_1 as current_admin:
                keydef = PKCS11KeyUsageAll()
                rsa_private_key_1 = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
                assert rsa_private_key_1 is not None
                pub_key_1 = rsa_private_key_1.public_key()
                pub_key_info = pub_key_1.public_bytes(
                    Encoding.DER,
                    PublicFormat.SubjectPublicKeyInfo,
                )

            operation_session = PKCS11EncryptNWrapSession(
                "A token", "1234", _pkcs11lib
            )
            asyn_padding = OAEP(
                mgf=MGF1(algorithm=mask_hash),
                algorithm=hash,
                label=None,
            )
            with operation_session as ops:
                encrypted_content, tag, iv = ops.encrypt(
                    data, encryption_algorithm
                )
                wrapped_content_encryption_key = ops.wrap_key(
                    pub_key_info, padding=asyn_padding
                )

            if wrapped_content_encryption_key is not None:
                private_1_ses = PKCS11UnwrapNDecryptSession(
                    label,
                    "1234",
                    "rsa_token_1",
                    pksc11_lib=_pkcs11lib,
                )
                with private_1_ses as rsa_unwrap:
                    decrypted_message = rsa_unwrap.unwrap_and_decrypt(
                        encrypted_content,
                        wrapped_content_encryption_key,
                        encryption_algorithm,
                        iv,
                        padding=asyn_padding,
                    )
                    assert decrypted_message == data
            else:
                assert False, "wrapped_content_encryption_key is None"

            with create_session_1 as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    def test_rsa_oaep_gcm_encrypt_decrypt(self):
        from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeyUsageAll,
            list_token_labels,
            PKCS11EncryptNWrapSession,
            PKCS11UnwrapNDecryptSession,
        )

        data = b"This is a test. If it commes over, but I think we do a good job, and next time we will do it like it is nothing. Let us try to build a simple test and then run with it."
        aad = b"additional data"

        encryption_algorithm = "aes256_gcm"
        # SoftHSM2 supports only SHA1
        mask_hash = hashes.SHA1()
        hash = hashes.SHA1()

        # Generate a private key for use in the exchange.
        for label in list_token_labels(_pkcs11lib):
            create_session_1 = PKCS11AdminSession(
                label, "1234", True, "rsa_token_1", b"254", _pkcs11lib
            )
            with create_session_1 as current_admin:
                keydef = PKCS11KeyUsageAll()
                rsa_private_key_1 = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
                assert rsa_private_key_1 is not None
                pub_key_1 = rsa_private_key_1.public_key()
                pub_key_info = pub_key_1.public_bytes(
                    Encoding.DER,
                    PublicFormat.SubjectPublicKeyInfo,
                )

            operation_session = PKCS11EncryptNWrapSession(
                "A token", "1234", _pkcs11lib
            )
            asyn_padding = OAEP(
                mgf=MGF1(algorithm=mask_hash),
                algorithm=hash,
                label=None,
            )
            with operation_session as ops:
                encrypted_content, received_tag, iv = ops.encrypt(
                    data, encryption_algorithm, aad_for_gcm=aad
                )
                wrapped_content_encryption_key = ops.wrap_key(
                    pub_key_info, padding=asyn_padding
                )

            if wrapped_content_encryption_key is not None:
                private_1_ses = PKCS11UnwrapNDecryptSession(
                    label, "1234", "rsa_token_1", pksc11_lib=_pkcs11lib
                )
                with private_1_ses as rsa_unwrap:
                    decrypted_message = rsa_unwrap.unwrap_and_decrypt(
                        encrypted_content,
                        wrapped_content_encryption_key,
                        encryption_algorithm,
                        iv,
                        padding=asyn_padding,
                        received_tag=received_tag,
                        aad_for_gcm=aad,
                    )
                    assert decrypted_message == data
            else:
                assert False, "wrapped_content_encryption_key is None"

            with create_session_1 as current_admin:
                r = current_admin.delete_key_pair()
                assert r
