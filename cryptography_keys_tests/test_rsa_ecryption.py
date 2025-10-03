_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


pin = "1234"


class TestRSAEncryption:

    def test_rsa_encryption_PKCS1v15(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import padding

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            list_token_labels,
        )

        data = b"How to encode this sentence"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(
                label, pin, True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(label, pin, pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                public_key = current_key.public_key()
                pn = public_key.public_numbers()
                public = pn.public_key(default_backend)
                padding1 = padding.PKCS1v15()

                encrypted = public.encrypt(data, padding1)
                rezult = current_key.decrypt(encrypted, padding1)
                assert data == rezult
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    def test_rsa_encryption_OAEP(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            list_token_labels,
        )

        # SoftHSM2 supports only SHA1
        message = b"encrypted data"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(
                label, pin, True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(label, pin, pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                public = current_key.public_key()
                pn = public.public_numbers()
                public_key = pn.public_key(default_backend)
                padding1 = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                )
                ciphertext = public_key.encrypt(
                    message,
                    padding1,
                )
                plaintext = current_key.decrypt(
                    ciphertext,
                    padding1,
                )
                assert plaintext == message
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r
