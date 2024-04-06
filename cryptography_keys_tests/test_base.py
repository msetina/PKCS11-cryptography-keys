_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestBasic:

    def test_labels(self):
        from pkcs11_cryptography_keys import list_token_labels

        cnt = 0
        for label in list_token_labels(_pkcs11lib):
            cnt = cnt + 1
        assert cnt == 1

    def test_change_pin(self):
        from pkcs11_cryptography_keys import (
            list_token_labels,
            PKCS11SlotAdminSession,
        )

        for label in list_token_labels(_pkcs11lib):
            sa_session = PKCS11SlotAdminSession(_pkcs11lib, label, "1234", True)
            with sa_session as slot:
                slot.change_pin("1234", "5432")
            sa_session = PKCS11SlotAdminSession(_pkcs11lib, label, "5432", True)
            with sa_session as slot:
                slot.change_pin("5432", "1234")
            sa_session = PKCS11SlotAdminSession(_pkcs11lib, label, "123456")
            with sa_session as slot:
                slot.change_pin("123456", "222222")
            sa_session = PKCS11SlotAdminSession(_pkcs11lib, label, "222222")
            with sa_session as slot:
                slot.change_pin("222222", "123456")
        assert True

    def test_rsa_key_creation(self):
        from pkcs11_cryptography_keys import list_token_admins

        for admin in list_token_admins(_pkcs11lib, "1234", True):
            with admin as current_admin:
                rsa_priv_key = current_admin.create_rsa_key_pair(2048)
                r = current_admin.delete_key_pair()
                assert rsa_priv_key is not None
                assert r

    def test_ec_key_creation(self):
        from pkcs11_cryptography_keys import list_token_admins

        for admin in list_token_admins(_pkcs11lib, "1234", True):
            with admin as current_admin:
                ec_priv_key = current_admin.create_ec_key_pair("secp256r1")
                r = current_admin.delete_key_pair()
                assert ec_priv_key is not None
                assert r

    def test_rsa_encryption_PKCS1v15(self):
        from pkcs11_cryptography_keys import (
            list_token_labels,
            PKCS11AdminSession,
            PKCS11KeySession,
        )
        from cryptography.hazmat.primitives.asymmetric import padding

        data = b"How to encode this sentence"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(_pkcs11lib, label, "1234", True)
            with a_session as current_admin:
                rsa_priv_key = current_admin.create_rsa_key_pair(2048)
            assert rsa_priv_key is not None
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

    def test_rsa_sign_verify(self):
        from pkcs11_cryptography_keys import (
            list_token_labels,
            PKCS11AdminSession,
            PKCS11KeySession,
        )
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        data = b"How to encode this sentence"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(_pkcs11lib, label, "1234", True)
            with a_session as current_admin:
                rsa_priv_key = current_admin.create_rsa_key_pair(2048)
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(_pkcs11lib, label, "1234")
            with k_session as current_key:
                public = current_key.public_key()
                padding1 = padding.PKCS1v15()
                signature = current_key.sign(data, padding1, hashes.SHA256())
                rezult = public.verify(
                    signature, data, padding1, hashes.SHA256()
                )
                assert rezult is None
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    # only prehashed supported for EC in softhsm2
    def test_ec_sign_verify(self):
        from pkcs11_cryptography_keys import (
            list_token_labels,
            PKCS11AdminSession,
            PKCS11KeySession,
        )
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.asymmetric import utils

        data = b"How to encode this sentence"
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(data)
        digest = hasher.finalize()
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(_pkcs11lib, label, "1234", True)
            with a_session as current_admin:
                ec_priv_key = current_admin.create_ec_key_pair("secp256r1")
            assert ec_priv_key is not None
            k_session = PKCS11KeySession(_pkcs11lib, label, "1234")
            with k_session as current_key:
                public = current_key.public_key()
                algo = ECDSA(utils.Prehashed(chosen_hash))
                signature = current_key.sign(digest, algo)
                rezult = public.verify(signature, digest, algo)
                assert rezult is None
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r
