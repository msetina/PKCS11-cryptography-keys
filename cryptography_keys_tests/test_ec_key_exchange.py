_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestECKeyExchange:

    def test_ec_key_exchange(self):
        from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP384R1

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAll,
            list_token_labels,
        )

        # pkcs11-tool --modul /usr/lib/softhsm/libsofthsm2.so --login -p "123456" --login-type user --keypairgen --id 1 --label "bob" --key-type EC:prime256v1
        # pkcs11-tool --modul /usr/lib/softhsm/libsofthsm2.so --login -p "123456" --login-type user --keypairgen --id 2 --label "alice" --key-type EC:prime256v1
        for label in list_token_labels(_pkcs11lib):
            pub_key_obj_1 = None
            pub_key_obj_2 = None
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

            create_session_2 = PKCS11AdminSession(
                label, "1234", True, "ec_token_2", b"255", _pkcs11lib
            )
            with create_session_2 as current_admin:
                keydef = PKCS11KeyUsageAll()
                ec_private_key_2 = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.EC, EC_curve=SECP384R1()
                )
                assert ec_private_key_2 is not None
                pub_key_2 = ec_private_key_2.public_key()
                pub_key_obj_2 = pub_key_2.public_numbers().public_key()

            if pub_key_obj_1 is not None and pub_key_obj_2 is not None:
                ex_key_1 = None
                ex_key_2 = None
                private_1_ses = PKCS11KeySession(
                    label, "1234", "ec_token_1", _pkcs11lib
                )
                private_2_ses = PKCS11KeySession(
                    label, "1234", "ec_token_2", _pkcs11lib
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

    def test_simple_exchange(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDH,
            SECP384R1,
            generate_private_key,
        )
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAll,
            list_token_labels,
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

            peer_private_key = generate_private_key(SECP384R1())

            if pub_key_obj_1 is not None and peer_private_key is not None:
                derived_key = None
                same_derived_key = None
                private_1_ses = PKCS11KeySession(
                    label, "1234", "ec_token_1", _pkcs11lib
                )
                with private_1_ses as curr_key:
                    ex_key_1 = curr_key.exchange(
                        ECDH(), peer_private_key.public_key()
                    )
                    assert ex_key_1 is not None

                    # Perform key derivation.
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b"handshake data",
                    ).derive(ex_key_1)
                # And now we can demonstrate that the handshake performed in the
                # opposite direction gives the same final value
                same_shared_key = peer_private_key.exchange(
                    ECDH(), pub_key_obj_1
                )
                # Perform key derivation.
                same_derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"handshake data",
                ).derive(same_shared_key)
                assert derived_key == same_derived_key

            with create_session_1 as current_admin:
                r = current_admin.delete_key_pair()
                assert r
