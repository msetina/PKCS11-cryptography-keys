_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestBasic:

    def test_labels(self):
        from pkcs11_cryptography_keys import list_token_labels

        cnt = 0
        for label in list_token_labels(_pkcs11lib):
            cnt = cnt + 1
        assert cnt == 1

    def test_rsa_key_creation(self):
        from pkcs11_cryptography_keys import list_token_admins

        for admin in list_token_admins(_pkcs11lib, "1234", True):
            with admin as current_admin:
                pub, priv = current_admin.create_rsa_key_pair(2048)
                r = current_admin.delete_key_pair()
                assert pub is not None and priv is not None
                assert r

    def test_ec_key_creation(self):
        from pkcs11_cryptography_keys import list_token_admins

        for admin in list_token_admins(_pkcs11lib, "1234", True):
            with admin as current_admin:
                pub, priv = current_admin.create_ec_key_pair("secp256r1")
                r = current_admin.delete_key_pair()
                assert pub is not None and priv is not None
                assert r

    def test_rsa_encryption(self):
        from pkcs11_cryptography_keys import (
            list_token_labels,
            PKCS11AdminSession,
            PKCS11KeySession,
        )
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_der_public_key,
        )

        data = b"How to encode this sentence"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(_pkcs11lib, label, "1234", True)
            with a_session as current_admin:
                pub, priv = current_admin.create_rsa_key_pair(2048)
            assert pub is not None and priv is not None
            k_session = PKCS11KeySession(_pkcs11lib, label, "1234")
            with k_session as current_key:
                public = current_key.public_key()
                padding1 = padding.PKCS1v15()

                encrypted = public.encrypt(data, padding1)
                rezult = current_key.decrypt(encrypted, padding1)
                assert data == rezult
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r
