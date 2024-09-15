_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestKeyLoading:

    def test_rsa_key_load(self):
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            generate_private_key,
        )

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11KeyUsageAllNoDerive,
            list_token_admins,
        )

        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        for admin in list_token_admins("1234", _pkcs11lib, True):
            with admin as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef,
                    key_type=KeyTypes.RSA,
                    RSA_private_key=private_key,
                )
                assert rsa_priv_key is not None
                assert rsa_priv_key.key_size == 2048
                ku = rsa_priv_key.read_key_usage()
                r = current_admin.delete_key_pair()
                assert ku == keydef
                assert r

    def test_ec_key_load(self):
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP384R1,
            generate_private_key,
        )

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11KeyUsageAll,
            list_token_admins,
        )

        private_key = generate_private_key(curve=SECP384R1())

        for admin in list_token_admins("1234", _pkcs11lib, True):
            with admin as current_admin:
                keydef = PKCS11KeyUsageAll()
                ec_priv_key = current_admin.create_key_pair(
                    keydef,
                    key_type=KeyTypes.EC,
                    EC_private_key=private_key,
                )
                assert ec_priv_key is not None
                assert ec_priv_key.curve.__class__ == SECP384R1
                ku = ec_priv_key.read_key_usage()
                r = current_admin.delete_key_pair()
                assert ku == keydef
                assert r
