_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestBasic:

    def test_init_token(self):
        from pkcs11_cryptography_keys import create_token_on_all_slots

        create_token_on_all_slots("123456", "A token", "1234", _pkcs11lib)

    def test_labels(self):
        from pkcs11_cryptography_keys import list_token_labels

        cnt = 0
        for label in list_token_labels(_pkcs11lib):
            cnt = cnt + 1
        assert cnt == 1

    def test_change_pin(self):
        from pkcs11_cryptography_keys import (
            PKCS11SlotAdminSession,
            list_token_labels,
        )

        for label in list_token_labels(_pkcs11lib):
            sa_session = PKCS11SlotAdminSession(label, "1234", True, _pkcs11lib)
            with sa_session as slot:
                slot.change_pin("1234", "5432")
            sa_session = PKCS11SlotAdminSession(label, "5432", True, _pkcs11lib)
            with sa_session as slot:
                slot.change_pin("5432", "1234")
            sa_session = PKCS11SlotAdminSession(
                label, "123456", False, _pkcs11lib
            )
            with sa_session as slot:
                slot.change_pin("123456", "222222")
            sa_session = PKCS11SlotAdminSession(
                label, "222222", False, _pkcs11lib
            )
            with sa_session as slot:
                slot.change_pin("222222", "123456")
        assert True

    def test_rsa_key_creation(self):
        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11KeyUsageAllNoDerive,
            list_token_admins,
        )

        for admin in list_token_admins("1234", _pkcs11lib, True):
            with admin as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
                assert rsa_priv_key is not None
                assert rsa_priv_key.key_size == 2048
                ku = rsa_priv_key.read_key_usage()
                r = current_admin.delete_key_pair()
                assert ku == keydef
                assert r

    def test_ec_key_creation(self):
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11KeyUsageAll,
            list_token_admins,
        )

        for admin in list_token_admins("1234", _pkcs11lib, True):
            with admin as current_admin:
                keydef = PKCS11KeyUsageAll()
                ec_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.EC, EC_curve=SECP384R1()
                )
                assert ec_priv_key is not None
                assert ec_priv_key.curve.__class__ is SECP384R1
                ku = ec_priv_key.read_key_usage()
                r = current_admin.delete_key_pair()
                assert ku == keydef
                assert r

    def test_multi_key_per_token(self):
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11KeyUsageAll,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            list_token_labels,
        )

        for label in list_token_labels(_pkcs11lib):
            rsa_id_c = b"\x01"
            ec_id_c = b"\x02"
            rsa_label_c = "rsa key"
            ec_label_c = "ec key"
            a_RSA_session = PKCS11AdminSession(
                label,
                "1234",
                True,
                pksc11_lib=_pkcs11lib,
                key_id=rsa_id_c,
                key_label=rsa_label_c,
            )
            with a_RSA_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
                rsa_id, rsa_label = rsa_priv_key.get_id_and_label()
            assert rsa_priv_key is not None
            a_EC_session = PKCS11AdminSession(
                label,
                "1234",
                True,
                pksc11_lib=_pkcs11lib,
                key_id=ec_id_c,
                key_label=ec_label_c,
            )
            with a_EC_session as current_admin:
                keydef = PKCS11KeyUsageAll()
                ec_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.EC, EC_curve=SECP384R1()
                )
                ec_id, ec_label = ec_priv_key.get_id_and_label()
            assert ec_priv_key is not None

            k_RSA_session = PKCS11KeySession(
                label, "1234", key_id=rsa_id, pksc11_lib=_pkcs11lib
            )
            with k_RSA_session as current_key:
                t_rsa_id, t_rsa_label = current_key.get_id_and_label()
                assert (rsa_id, rsa_label) == (t_rsa_id, t_rsa_label)
                assert (rsa_id_c, rsa_label_c) == (t_rsa_id, t_rsa_label)

            k_RSA_session_l = PKCS11KeySession(
                label, "1234", key_label=rsa_label, pksc11_lib=_pkcs11lib
            )
            with k_RSA_session_l as current_key:
                t2_rsa_id, t2_rsa_label = current_key.get_id_and_label()
                assert (rsa_id, rsa_label) == (t2_rsa_id, t2_rsa_label)
                assert (rsa_id_c, rsa_label_c) == (t2_rsa_id, t2_rsa_label)

            k_EC_session = PKCS11KeySession(
                label, "1234", key_id=ec_id, pksc11_lib=_pkcs11lib
            )
            with k_EC_session as current_key:
                t_ec_id, t_ec_label = current_key.get_id_and_label()
                assert (ec_id, ec_label) == (t_ec_id, t_ec_label)
                assert (ec_id_c, ec_label_c) == (t_ec_id, t_ec_label)

            k_EC_session_l = PKCS11KeySession(
                label, "1234", key_label=ec_label, pksc11_lib=_pkcs11lib
            )
            with k_EC_session_l as current_key:
                t2_ec_id, t2_ec_label = current_key.get_id_and_label()
                assert (ec_id, ec_label) == (t2_ec_id, t2_ec_label)
                assert (ec_id_c, ec_label_c) == (t2_ec_id, t2_ec_label)

            with a_RSA_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

            with a_EC_session as current_admin2:
                r2 = current_admin2.delete_key_pair()
                assert r2

    def test_multi_key_per_token_key_id(self):
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11KeyUsageAll,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            list_token_labels,
        )

        for label in list_token_labels(_pkcs11lib):
            rsa_id_c = b"\x01"
            ec_id_c = b"\x02"
            a_RSA_session = PKCS11AdminSession(
                label,
                "1234",
                True,
                pksc11_lib=_pkcs11lib,
                key_id=rsa_id_c,
            )
            with a_RSA_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
                rsa_id, rsa_label = rsa_priv_key.get_id_and_label()
            assert rsa_priv_key is not None
            a_EC_session = PKCS11AdminSession(
                label,
                "1234",
                True,
                pksc11_lib=_pkcs11lib,
                key_id=ec_id_c,
            )
            with a_EC_session as current_admin:
                keydef = PKCS11KeyUsageAll()
                ec_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.EC, EC_curve=SECP384R1()
                )
                ec_id, ec_label = ec_priv_key.get_id_and_label()
            assert ec_priv_key is not None

            k_RSA_session = PKCS11KeySession(
                label, "1234", key_id=rsa_id, pksc11_lib=_pkcs11lib
            )
            with k_RSA_session as current_key:
                t_rsa_id, t_rsa_label = current_key.get_id_and_label()
                assert (rsa_id, rsa_label) == (t_rsa_id, t_rsa_label)

            k_EC_session = PKCS11KeySession(
                label, "1234", key_id=ec_id, pksc11_lib=_pkcs11lib
            )
            with k_EC_session as current_key:
                t_ec_id, t_ec_label = current_key.get_id_and_label()
                assert (ec_id, ec_label) == (t_ec_id, t_ec_label)

            with a_RSA_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

            with a_EC_session as current_admin2:
                r2 = current_admin2.delete_key_pair()
                assert r2

    def test_rsa_encryption_PKCS1v15(self):
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
                label, "1234", True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(label, "1234", pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                public = current_key.public_key()
                padding1 = padding.PKCS1v15()

                encrypted = public.encrypt(data, padding1)
                rezult = current_key.decrypt(encrypted, padding1)
                assert data == rezult
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    # softHSM does not have PSS support for encryption
    # def test_rsa_encryption_PSS(self):
    #     from pkcs11_cryptography_keys import (
    #         list_token_labels,
    #         PKCS11AdminSession,
    #         PKCS11KeySession,
    #         PKCS11KeyUsageAllNoDerive,
    #         KeyTypes,
    #     )
    #     from cryptography.hazmat.primitives import hashes
    #     from cryptography.hazmat.primitives.asymmetric import padding

    #     message = b"encrypted data"
    #     for label in list_token_labels(_pkcs11lib):
    #         a_session = PKCS11AdminSession( label, "1234", True,pksc11_lib=_pkcs11lib)
    #         with a_session as current_admin:
    #           keydef = PKCS11KeyUsageAllNoDerive()
    # rsa_priv_key = current_admin.create_key_pair(
    #     keydef, key_type=KeyTypes.RSA, RSA_length=2048
    # )
    #         assert rsa_priv_key is not None
    #         k_session = PKCS11KeySession( label, "1234",pksc11_lib=_pkcs11lib)
    #         with k_session as current_key:
    #             public_key = current_key.public_key()
    #             hash1 = hashes.SHA256()
    #             padding1 = padding.PSS(
    #                 mgf=padding.MGF1(hash1),
    #                 salt_length=padding.PSS.MAX_LENGTH,
    #             )
    #             ciphertext = public_key.encrypt(
    #                 message,
    #                 padding1,
    #             )
    #             plaintext = current_key.decrypt(
    #                 ciphertext,
    #                 padding1,
    #             )
    #             assert plaintext == message
    #         with a_session as current_admin:
    #             r = current_admin.delete_key_pair()
    #             assert r

    def test_rsa_encryption_OAEP(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            list_token_labels,
        )

        message = b"encrypted data"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(
                label, "1234", True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(label, "1234", pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                public_key = current_key.public_key()
                # SoftHSM supports just SHA1 in this case
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

    def test_rsa_sign_verify_PKCS1(self):
        from cryptography.hazmat.primitives import hashes
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
                label, "1234", True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(label, "1234", pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                public = current_key.public_key()
                hash1 = hashes.SHA256()
                padding1 = padding.PKCS1v15()
                signature = current_key.sign(data, padding1, hash1)
                rezult = public.verify(signature, data, padding1, hash1)
                assert rezult is None
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    def test_rsa_sign_verify_PSS_digest_length(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            list_token_labels,
        )

        message = b"A message I want to sign"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(
                label, "1234", True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(label, "1234", pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                hash1 = hashes.SHA256()
                padding1 = padding.PSS(
                    mgf=padding.MGF1(hash1),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                )

                signature = current_key.sign(
                    message,
                    padding1,
                    hash1,
                )
                public_key = current_key.public_key()
                rezult = public_key.verify(
                    signature,
                    message,
                    padding1,
                    hash1,
                )
                assert rezult is None
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    def test_rsa_sign_verify_PSS_max_length(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            list_token_labels,
        )

        message = b"A message I want to sign"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(
                label, "1234", True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(label, "1234", pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                hash1 = hashes.SHA256()
                padding1 = padding.PSS(
                    mgf=padding.MGF1(hash1),
                    salt_length=padding.PSS.MAX_LENGTH,
                )

                signature = current_key.sign(
                    message,
                    padding1,
                    hash1,
                )
                public_key = current_key.public_key()
                rezult = public_key.verify(
                    signature,
                    message,
                    padding1,
                    hash1,
                )
                assert rezult is None
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    def test_rsa_sign_verify_PSS_message_length(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            list_token_labels,
        )

        message = b"A message I want to sign"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(
                label, "1234", True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(label, "1234", pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                hash1 = hashes.SHA256()
                padding1 = padding.PSS(
                    mgf=padding.MGF1(hash1),
                    salt_length=len(message),
                )

                signature = current_key.sign(
                    message,
                    padding1,
                    hash1,
                )
                public_key = current_key.public_key()
                rezult = public_key.verify(
                    signature,
                    message,
                    padding1,
                    hash1,
                )
                assert rezult is None
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    def test_rsa_sign_verify_PSS_auto(self):
        import pytest
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            list_token_labels,
        )

        message = b"A message I want to sign"
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(
                label, "1234", True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
            assert rsa_priv_key is not None
            k_session = PKCS11KeySession(label, "1234", pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                hash1 = hashes.SHA256()
                padding1 = padding.PSS(
                    mgf=padding.MGF1(hash1),
                    salt_length=padding.PSS.AUTO,
                )
                with pytest.raises(UnsupportedAlgorithm) as excinfo:
                    signature = current_key.sign(
                        message,
                        padding1,
                        hash1,
                    )
                    assert excinfo.group_contains(UnsupportedAlgorithm)

            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r

    # only prehashed supported for EC in softhsm2
    def test_ec_sign_verify(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import utils
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDSA,
            SECP384R1,
        )

        from pkcs11_cryptography_keys import (
            PKCS11AdminSession,
            PKCS11KeySession,
            list_token_labels,
        )
        from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
            KeyTypes,
            PKCS11KeyUsageAll,
        )

        data = b"How to encode this sentence"
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(data)
        digest = hasher.finalize()
        for label in list_token_labels(_pkcs11lib):
            a_session = PKCS11AdminSession(
                label, "1234", True, pksc11_lib=_pkcs11lib
            )
            with a_session as current_admin:
                keydef = PKCS11KeyUsageAll()
                ec_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.EC, EC_curve=SECP384R1()
                )
            assert ec_priv_key is not None
            k_session = PKCS11KeySession(label, "1234", pksc11_lib=_pkcs11lib)
            with k_session as current_key:
                public = current_key.public_key()
                algo = ECDSA(utils.Prehashed(chosen_hash))
                signature = current_key.sign(digest, algo)
                rezult = public.verify(signature, digest, algo)
                assert rezult is None
            with a_session as current_admin:
                r = current_admin.delete_key_pair()
                assert r
