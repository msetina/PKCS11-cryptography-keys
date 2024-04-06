_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestECKeyExchange:

    def test_ec_key_exchange(self):
        from cryptography.hazmat.primitives.asymmetric.ec import ECDH
        from pkcs11_cryptography_keys import (
            PKCS11AdminSession,
            PKCS11KeySession,
        )
        from pkcs11_cryptography_keys import list_token_labels

        # pkcs11-tool --modul /usr/lib/softhsm/libsofthsm2.so --login -p "123456" --login-type user --keypairgen --id 1 --label "bob" --key-type EC:prime256v1
        # pkcs11-tool --modul /usr/lib/softhsm/libsofthsm2.so --login -p "123456" --login-type user --keypairgen --id 2 --label "alice" --key-type EC:prime256v1
        for label in list_token_labels(_pkcs11lib):
            pub_key_obj_1 = None
            pub_key_obj_2 = None
            create_session_1 = PKCS11AdminSession(
                _pkcs11lib, label, "1234", True, "ec_token_1", b"254"
            )
            with create_session_1 as current_admin:
                ec_private_key_1 = current_admin.create_ec_key_pair("secp256r1")
                assert ec_private_key_1 is not None
                pub_key_1 = ec_private_key_1.public_key()
                pub_key_obj_1 = pub_key_1.public_numbers().public_key()

            create_session_2 = PKCS11AdminSession(
                _pkcs11lib, label, "1234", True, "ec_token_2", b"255"
            )
            with create_session_2 as current_admin:
                ec_private_key_2 = current_admin.create_ec_key_pair("secp256r1")
                assert ec_private_key_2 is not None
                pub_key_2 = ec_private_key_2.public_key()
                pub_key_obj_2 = pub_key_2.public_numbers().public_key()

            if pub_key_obj_1 is not None and pub_key_obj_2 is not None:
                ex_key_1 = None
                ex_key_2 = None
                private_1_ses = PKCS11KeySession(
                    _pkcs11lib, label, "1234", "ec_token_1"
                )
                private_2_ses = PKCS11KeySession(
                    _pkcs11lib, label, "1234", "ec_token_2"
                )
                # pkcs11-tool --modul /usr/lib/softhsm/libsofthsm2.so --login -p "123456" --login-type user --id 1 --derive -i alice-public.der -m ECDH1-DERIVE -o bob_shared_secret.raw
                with private_1_ses as curr_key:
                    ex_key_1 = curr_key.exchange(ECDH(), pub_key_obj_2)
                    assert ex_key_1 is not None

                # pkcs11-tool --modul /usr/lib/softhsm/libsofthsm2.so --login -p "123456" --login-type user --id 2 --derive -i bob-public.der -m ECDH1-DERIVE -o alice_shared_secret.raw
                with private_2_ses as curr_key:
                    ex_key_2 = curr_key.exchange(ECDH(), pub_key_obj_1)
                    assert ex_key_2 is not None
                assert ex_key_1 == ex_key_2

            with create_session_1 as current_admin:
                r = current_admin.delete_key_pair()
                assert r

            with create_session_2 as current_admin:
                r = current_admin.delete_key_pair()
                assert r
